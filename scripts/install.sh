#!/usr/bin/env bash
# EasyTier 通用安装脚本：下载官方 release、安装为系统服务、加载配置。
#
# 用法：
#   curl -fsSL <本脚本地址> | sudo bash -s -- -c ./config.toml
#   curl -fsSL <本脚本地址> | sudo bash -s -- -v v2.6.4 -n easytier -u https://example.com/config.toml
#
#   -b BASE64        base64 编码的 TOML 配置（配合在线生成器使用）
#   -v VERSION        EasyTier 版本（默认 v2.6.4，可用环境变量 ET_VERSION 覆盖）
#   -n NAME           服务名（默认 easytier）
#   -c FILE           本地 TOML 配置文件
#   -u URL            从 URL 下载 TOML 配置
#   --proxy URL       GitHub 下载代理（默认自动：直连失败时走 ghfast.top）
#   --open-firewall   放行 11010 TCP/UDP（relay 需要）
# 不提供 -c/-u/-b 时只安装二进制，不注册服务。
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

VERSION="${ET_VERSION:-v2.6.4}"
SERVICE_NAME="easytier"
CONFIG_FILE=""
CONFIG_URL=""
CONFIG_BASE64=""
PROXY="${ET_PROXY:-}"
OPEN_FIREWALL=0

usage() {
  sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    -v) VERSION="$2"; shift 2 ;;
    -b) CONFIG_BASE64="$2"; shift 2 ;;
    -n) SERVICE_NAME="$2"; shift 2 ;;
    -c) CONFIG_FILE="$2"; shift 2 ;;
    -u) CONFIG_URL="$2"; shift 2 ;;
    --proxy) PROXY="$2"; shift 2 ;;
    --open-firewall) OPEN_FIREWALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数: $1" >&2; usage; exit 1 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 sudo 运行此安装器。" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  armv7l|armv7) ARCH=armv7 ;;
  *) echo "不支持的架构：$(uname -m)" >&2; exit 1 ;;
esac

if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get install -y curl unzip
  elif command -v apk >/dev/null 2>&1; then apk add --no-cache curl unzip
  elif command -v dnf >/dev/null 2>&1; then dnf install -y curl unzip
  elif command -v yum >/dev/null 2>&1; then yum install -y curl unzip
  elif command -v pacman >/dev/null 2>&1; then pacman -Sy --noconfirm curl unzip
  else echo "缺少 curl/unzip，且无法识别包管理器。" >&2; exit 1; fi
fi

download() {
  curl --fail --location --retry 3 --retry-all-errors --connect-timeout 10 --max-time 300 --speed-limit 1024 --speed-time 30 -C - --output "$2" "$1"
}

ASSET="https://github.com/EasyTier/EasyTier/releases/download/${VERSION}/easytier-linux-${ARCH}-${VERSION}.zip"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

if [ -n "$PROXY" ]; then
  download "${PROXY%/}/$ASSET" "$WORK_DIR/easytier.zip"
elif ! download "$ASSET" "$WORK_DIR/easytier.zip"; then
  echo "GitHub 直连失败，改用 ghfast.top 代理。" >&2
  download "https://ghfast.top/$ASSET" "$WORK_DIR/easytier.zip"
fi

unzip -q -o "$WORK_DIR/easytier.zip" -d "$WORK_DIR/unpacked"
SOURCE_DIR="$(dirname "$(find "$WORK_DIR/unpacked" -type f -name easytier-core -print -quit)")"
if [ -z "$SOURCE_DIR" ] || [ ! -x "$SOURCE_DIR/easytier-core" ]; then
  echo "下载包中未找到 easytier-core。" >&2
  exit 1
fi

INSTALL_DIR="/opt/easytier"
install -d -m 0755 "$INSTALL_DIR"
install -m 0755 "$SOURCE_DIR/easytier-core" "$INSTALL_DIR/easytier-core"
install -m 0755 "$SOURCE_DIR/easytier-cli" "$INSTALL_DIR/easytier-cli"
echo "已安装 EasyTier $VERSION 到 $INSTALL_DIR"

if [ -n "$CONFIG_BASE64" ]; then
  echo "$CONFIG_BASE64" | base64 -d > "$WORK_DIR/config.toml" 2>/dev/null || { echo "配置 base64 解码失败。" >&2; exit 1; }
  CONFIG_FILE="$WORK_DIR/config.toml"
fi

if [ -n "$CONFIG_URL" ]; then
  curl --fail --location --retry 2 -o "$WORK_DIR/config.toml" "$CONFIG_URL"
  CONFIG_FILE="$WORK_DIR/config.toml"
fi

if [ -z "$CONFIG_FILE" ]; then
  echo "未提供配置（-c 或 -u）；仅安装二进制，未注册服务。"
  exit 0
fi
if [ ! -f "$CONFIG_FILE" ]; then
  echo "配置文件不存在：$CONFIG_FILE" >&2
  exit 1
fi
install -d -m 0755 /etc/easytier
install -m 0600 "$CONFIG_FILE" /etc/easytier/config.toml
echo "配置已写入 /etc/easytier/config.toml"

if command -v systemctl >/dev/null 2>&1; then
  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<UNIT
[Unit]
Description=EasyTier mesh node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/easytier-core -c /etc/easytier/config.toml
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME.service"
elif command -v rc-service >/dev/null 2>&1; then
  cat > "/etc/init.d/${SERVICE_NAME}" <<INIT
#!/sbin/openrc-run
name="EasyTier mesh node"
command="${INSTALL_DIR}/easytier-core"
command_args="-c /etc/easytier/config.toml"
command_background=true
pidfile="/run/\${RC_SVCNAME}.pid"
depend() { need net; }
INIT
  chmod 0755 "/etc/init.d/${SERVICE_NAME}"
  rc-update add "$SERVICE_NAME" default
  rc-service "$SERVICE_NAME" restart
else
  echo "需要 systemd 或 OpenRC。" >&2
  exit 1
fi

if [ "$OPEN_FIREWALL" -eq 1 ]; then
  if command -v ufw >/dev/null 2>&1; then
    ufw allow 11010/tcp || true
    ufw allow 11010/udp || true
  elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port=11010/tcp || true
    firewall-cmd --permanent --add-port=11010/udp || true
    firewall-cmd --reload || true
  fi
fi

sleep 3
if command -v systemctl >/dev/null 2>&1; then
  systemctl is-active --quiet "$SERVICE_NAME.service" || echo "警告：服务未保持运行，请检查 journalctl -u $SERVICE_NAME.service" >&2
else
  rc-service "$SERVICE_NAME" status >/dev/null 2>&1 || echo "警告：服务未保持运行，请检查 rc-service 状态" >&2
fi
echo "EasyTier 已安装为服务：$SERVICE_NAME"
