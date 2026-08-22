package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/ssh"
)

//go:embed web/* scripts/install.sh
var webFS embed.FS

type Node struct {
	ID                 string `json:"id"`
	Role               string `json:"role"`
	Name               string `json:"name"`
	OS                 string `json:"os"`
	LinuxDeviceType    string `json:"linuxDeviceType"`
	OverlayIP          string `json:"overlayIP"`
	Host               string `json:"host"`
	SSHPort            int    `json:"sshPort"`
	SSHUser            string `json:"sshUser"`
	SSHAuth            string `json:"sshAuth"`
	SSHPrivateKey      string `json:"sshPrivateKey"`
	SSHPassword        string `json:"sshPassword"`
	HostKeyFingerprint string `json:"hostKeyFingerprint"`
}

type Project struct {
	Name             string `json:"name"`
	ReleaseVersion   string `json:"releaseVersion"`
	NetworkName      string `json:"networkName"`
	NetworkSecret    string `json:"networkSecret"`
	IPv4CIDR         string `json:"ipv4CIDR"`
	MagicDNS         bool   `json:"magicDNS"`
	DHCP             bool   `json:"dhcp"`
	GitHubProxy      string `json:"githubProxy"`
	ScriptBaseURL    string `json:"scriptBaseURL"`
	ProbeToken       string `json:"probeToken"`
	WireGuardEnabled bool   `json:"wireGuardEnabled"`
	WireGuardPort    int    `json:"wireGuardPort"`
	WireGuardCIDR    string `json:"wireGuardCIDR"`
	Relay            Node   `json:"relay"`
	Nodes            []Node `json:"nodes"`
}

type installToken struct {
	NodeID    string
	ExpiresAt time.Time
	Remaining int
}

type store struct {
	mu      sync.RWMutex
	project Project
	path    string
	tokens  map[string]installToken
}

func defaultProject() Project {
	return Project{
		Name:           "我的组网",
		ReleaseVersion: "v2.6.4",
		IPv4CIDR:       "10.144.144.0/24",
		MagicDNS:       true,
		ProbeToken:     randomHex(32),
		WireGuardPort:  11013,
		WireGuardCIDR:  "10.14.14.0/24",
		Relay:          Node{ID: newID(), Role: "relay", Name: "relay-vps", OS: "linux", OverlayIP: "10.144.144.1", SSHPort: 22, SSHUser: "root", SSHAuth: "key"},
	}
}

func loadStore(path string) (*store, error) {
	s := &store{path: path, project: defaultProject(), tokens: make(map[string]installToken)}
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读取本地状态: %w", err)
	}
	if err := json.Unmarshal(content, &s.project); err != nil {
		return nil, fmt.Errorf("解析本地状态: %w", err)
	}
	if s.project.Relay.ID == "" {
		s.project.Relay = defaultProject().Relay
	}
	for index := range s.project.Nodes {
		if s.project.Nodes[index].ID == "" {
			s.project.Nodes[index].ID = newID()
		}
	}
	if s.project.IPv4CIDR == "" {
		s.project.IPv4CIDR = deriveSubnet(s.project.Relay.OverlayIP)
	}
	s.project = assignOverlayIPs(s.project)
	if err := validateProject(s.project); err != nil {
		return nil, fmt.Errorf("本地状态校验失败: %w", err)
	}
	return s, nil
}

func (s *store) snapshot() Project {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneProject(s.project)
}

func cloneProject(project Project) Project {
	copy := project
	copy.Nodes = append([]Node(nil), project.Nodes...)
	return copy
}

func (s *store) save(project Project) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked(project)
}

func (s *store) saveLocked(project Project) error {
	if project.ProbeToken == "" {
		project.ProbeToken = randomHex(32)
	}
	project = assignOverlayIPs(project)
	if err := validateProject(project); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(project, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return fmt.Errorf("创建数据目录: %w", err)
	}
	temporary := s.path + ".tmp"
	if err := os.WriteFile(temporary, encoded, 0600); err != nil {
		return fmt.Errorf("写入本地状态: %w", err)
	}
	if err := os.Rename(temporary, s.path); err != nil {
		return fmt.Errorf("保存本地状态: %w", err)
	}
	s.project = cloneProject(project)
	return nil
}

func (s *store) node(id string) (Project, Node, error) {
	project := s.snapshot()
	if project.Relay.ID == id {
		return project, project.Relay, nil
	}
	for _, node := range project.Nodes {
		if node.ID == id {
			return project, node, nil
		}
	}
	return Project{}, Node{}, fmt.Errorf("找不到节点 %q", id)
}

func (s *store) trustHost(id, fingerprint string) error {
	if fingerprint == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	project := cloneProject(s.project)
	if project.Relay.ID == id && project.Relay.HostKeyFingerprint == "" {
		project.Relay.HostKeyFingerprint = fingerprint
	} else {
		for index := range project.Nodes {
			if project.Nodes[index].ID == id && project.Nodes[index].HostKeyFingerprint == "" {
				project.Nodes[index].HostKeyFingerprint = fingerprint
			}
		}
	}
	return s.saveLocked(project)
}

func (s *store) newToken(nodeID string) (string, error) {
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	token := hex.EncodeToString(bytes)
	s.mu.Lock()
	s.tokens[token] = installToken{NodeID: nodeID, ExpiresAt: time.Now().Add(time.Hour), Remaining: 1}
	s.mu.Unlock()
	return token, nil
}

func (s *store) consumeToken(token string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, found := s.tokens[token]
	if !found || item.ExpiresAt.Before(time.Now()) || item.Remaining < 1 {
		delete(s.tokens, token)
		return "", errors.New("安装链接已失效或已使用")
	}
	item.Remaining--
	if item.Remaining == 0 {
		delete(s.tokens, token)
	} else {
		s.tokens[token] = item
	}
	return item.NodeID, nil
}

func validateProject(project Project) error {
	if strings.TrimSpace(project.Name) == "" {
		return errors.New("请填写项目名称")
	}
	if !validVersion(project.ReleaseVersion) {
		return errors.New("EasyTier 版本必须是类似 v2.6.4 的发布标签")
	}
	if invalidConfigString(project.NetworkName) || invalidConfigString(project.NetworkSecret) {
		return errors.New("网络名称和网络密钥不能为空，且不能包含换行符")
	}
	subnetIP, subnet, err := net.ParseCIDR(project.IPv4CIDR)
	if err != nil || subnetIP.To4() == nil {
		return errors.New("IPv4 网段无效，例如 10.144.144.0/24")
	}
	if project.GitHubProxy != "" {
		parsed, err := url.Parse(project.GitHubProxy)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return errors.New("GitHub 下载代理必须是完整 HTTPS 地址，例如 https://ghfast.top/")
		}
	}
	if project.ScriptBaseURL != "" {
		parsed, err := url.Parse(project.ScriptBaseURL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return errors.New("安装脚本公开地址必须是完整 HTTP(S) 地址")
		}
	}
	if project.WireGuardEnabled {
		if project.WireGuardPort < 1 || project.WireGuardPort > 65535 {
			return errors.New("WireGuard 端口无效")
		}
		if _, _, err := net.ParseCIDR(project.WireGuardCIDR); err != nil {
			return errors.New("WireGuard 客户端网段无效")
		}
	}
	allNodes := append([]Node{project.Relay}, project.Nodes...)
	ips := map[string]bool{}
	names := map[string]bool{}
	for _, node := range allNodes {
		if invalidConfigString(node.Name) {
			return errors.New("每个节点都必须有名称")
		}
		if !validNodeID(node.ID) {
			return fmt.Errorf("节点 %s 的 ID 无效", node.Name)
		}
		if names[node.Name] {
			return fmt.Errorf("节点名称重复：%s", node.Name)
		}
		names[node.Name] = true
		if !project.DHCP {
			if net.ParseIP(node.OverlayIP) == nil || !strings.Contains(node.OverlayIP, ".") {
				return fmt.Errorf("节点 %s 的虚拟 IP 无效", node.Name)
			}
			if !subnet.Contains(net.ParseIP(node.OverlayIP)) {
				return fmt.Errorf("节点 %s 的虚拟 IP 不在网段 %s 内", node.Name, project.IPv4CIDR)
			}
			if ips[node.OverlayIP] {
				return fmt.Errorf("虚拟 IP 重复：%s", node.OverlayIP)
			}
			ips[node.OverlayIP] = true
		}
		if node.OS != "linux" && node.OS != "windows" {
			return fmt.Errorf("节点 %s 的系统必须是 Linux 或 Windows", node.Name)
		}
		if node.LinuxDeviceType != "" && node.LinuxDeviceType != "auto" && node.LinuxDeviceType != "desktop" && node.LinuxDeviceType != "server" {
			return fmt.Errorf("节点 %s 的 Linux 设备类型无效", node.Name)
		}
		if node.SSHPort == 0 {
			node.SSHPort = 22
		}
		if node.SSHPort < 1 || node.SSHPort > 65535 {
			return fmt.Errorf("节点 %s 的 SSH 端口无效", node.Name)
		}
	}
	if project.Relay.OS != "linux" || project.Relay.Host == "" {
		return errors.New("Relay 必须是填写公网地址的 Linux 节点")
	}
	return nil
}

// deriveSubnet 从节点 IP 推导 /24 网段（旧状态迁移用）。
func deriveSubnet(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return "10.144.144.0/24"
	}
	parsed[15] = 0
	return parsed.String() + "/24"
}

// assignOverlayIPs 在非 DHCP 模式下从网段自动分配空缺的虚拟 IP：relay 优先 .1，成员依次递增。
func assignOverlayIPs(project Project) Project {
	if project.DHCP {
		return project
	}
	ip, network, err := net.ParseCIDR(project.IPv4CIDR)
	if err != nil || ip.To4() == nil {
		return project
	}
	base := network.IP.To4()
	if base == nil {
		return project
	}
	used := map[string]bool{}
	for _, node := range append([]Node{project.Relay}, project.Nodes...) {
		if node.OverlayIP != "" {
			used[node.OverlayIP] = true
		}
	}
	next := func() string {
		for host := 1; host < 255; host++ {
			candidate := net.IPv4(base[0], base[1], base[2], byte(host)).String()
			if !used[candidate] {
				used[candidate] = true
				return candidate
			}
		}
		return ""
	}
	if project.Relay.OverlayIP == "" {
		project.Relay.OverlayIP = next()
	}
	for index := range project.Nodes {
		if project.Nodes[index].OverlayIP == "" {
			project.Nodes[index].OverlayIP = next()
		}
	}
	return project
}

// dnsHostname 把节点名转成 MagicDNS 可用的主机名（小写，仅字母数字与连字符）。
func dnsHostname(node Node) string {
	var builder strings.Builder
	lastDash := false
	for _, char := range strings.ToLower(node.Name) {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' {
			builder.WriteRune(char)
			lastDash = char == '-'
		} else if !lastDash && builder.Len() > 0 {
			builder.WriteRune('-')
			lastDash = true
		}
	}
	hostname := strings.Trim(builder.String(), "-")
	if hostname == "" {
		hostname = "node-" + shortID(node.ID)
	}
	return hostname
}

func validVersion(version string) bool {
	if len(version) < 2 || version[0] != 'v' {
		return false
	}
	for _, char := range version[1:] {
		if !(char == '.' || char == '-' || char == '_' || char >= '0' && char <= '9' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z') {
			return false
		}
	}
	return true
}

func invalidConfigString(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || strings.ContainsAny(value, "\r\n\x00")
}

func validNodeID(id string) bool {
	for _, char := range id {
		if !(char == '-' || char >= '0' && char <= '9' || char >= 'a' && char <= 'f' || char >= 'A' && char <= 'F') {
			return false
		}
	}
	return len(id) > 0
}

// shellQuote 把任意字符串变成 POSIX sh 单引号安全字面量。
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func tomlString(value string) string {
	return `"` + strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n", "\r", "\\r").Replace(value) + `"`
}

func endpoint(host, scheme string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			host = parsedHost
		}
	}
	return scheme + "://" + net.JoinHostPort(host, "11010")
}

func nodeConfig(project Project, node Node) string {
	listeners := []string{`"tcp://0.0.0.0:11010"`, `"udp://0.0.0.0:11010"`}
	mapped := []string{}
	peers := []string{}
	if node.Role == "relay" {
		mapped = []string{tomlString(endpoint(node.Host, "tcp")), tomlString(endpoint(node.Host, "udp"))}
	} else {
		peers = []string{endpoint(project.Relay.Host, "tcp"), endpoint(project.Relay.Host, "udp")}
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "instance_name = %s\n", tomlString(node.Name))
	fmt.Fprintf(&builder, "hostname = %s\n", tomlString(dnsHostname(node)))
	if project.DHCP {
		builder.WriteString("dhcp = true\n")
	} else {
		fmt.Fprintf(&builder, "ipv4 = %s\n", tomlString(node.OverlayIP))
	}
	fmt.Fprintf(&builder, "listeners = [%s]\n", strings.Join(listeners, ", "))
	fmt.Fprintf(&builder, "mapped_listeners = [%s]\n\n", strings.Join(mapped, ", "))
	if node.Role == "relay" && project.WireGuardEnabled {
		fmt.Fprintf(&builder, "\n[vpn_portal_config]\nwireguard_listen = %s\nclient_cidr = %s\n", tomlString(fmt.Sprintf("0.0.0.0:%d", project.WireGuardPort)), tomlString(project.WireGuardCIDR))
	}
	fmt.Fprintf(&builder, "[network_identity]\nnetwork_name = %s\nnetwork_secret = %s\n", tomlString(project.NetworkName), tomlString(project.NetworkSecret))
	for _, peer := range peers {
		fmt.Fprintf(&builder, "\n[[peer]]\nuri = %s\n", tomlString(peer))
	}
	builder.WriteString("\n[flags]\nenable_encryption = true\nmtu = 1380\n")
	if project.MagicDNS {
		builder.WriteString("accept_dns = true\n")
	}
	return builder.String()
}

func linuxScript(project Project, node Node) string {
	config := nodeConfig(project, node)
	proxy := downloadProxy(project.GitHubProxy)
	asset := fmt.Sprintf("https://github.com/EasyTier/EasyTier/releases/download/%s/easytier-linux-${ARCH}-%s.zip", project.ReleaseVersion, project.ReleaseVersion)
	shortNodeID := shortID(node.ID)
	installDir := "/opt/easytier-team/" + shortNodeID
	configFile := installDir + "/config/easytier.toml"
	unit := "easytier-team-" + shortNodeID + ".service"
	deviceType := node.LinuxDeviceType
	if deviceType == "" {
		deviceType = "auto"
	}
	if node.Role == "relay" {
		deviceType = "server"
	}
	firewall := ""
	if node.Role == "relay" {
		firewall = `
if command -v ufw >/dev/null 2>&1; then
  ufw allow 11010/tcp || true
  ufw allow 11010/udp || true
elif command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port=11010/tcp || true
  firewall-cmd --permanent --add-port=11010/udp || true
  firewall-cmd --reload || true
fi
`
	}
	if node.Role == "relay" && project.WireGuardEnabled {
		firewall += fmt.Sprintf(`
if command -v ufw >/dev/null 2>&1; then
  ufw allow %d/udp || true
elif command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port=%d/udp || true
  firewall-cmd --reload || true
fi
`, project.WireGuardPort, project.WireGuardPort)
	}
	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 sudo 运行此安装器。" >&2
  exit 1
fi

INSTALL_DIR=%s
CONFIG_FILE="$INSTALL_DIR/config/easytier.toml"
UNIT_FILE=/etc/systemd/system/%s
OPENRC_SERVICE=easytier-team-%s
VERSION=%s
GITHUB_PROXY=%s
LINUX_DEVICE_TYPE=%s

case "$(uname -m)" in
  x86_64|amd64) ARCH=x86_64; GUI_ARCH=amd64; DEB_ARCH=amd64; RPM_ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64; GUI_ARCH=aarch64; DEB_ARCH=arm64; RPM_ARCH=aarch64 ;;
  armv7l|armv7) ARCH=armv7; GUI_ARCH=""; DEB_ARCH=""; RPM_ARCH="" ;;
  *) echo "不支持的 Linux 架构：$(uname -m)" >&2; exit 1 ;;
esac

INIT_SYSTEM=systemd
if ! command -v systemctl >/dev/null 2>&1; then
  if command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then INIT_SYSTEM=openrc
  else echo "需要 systemd 或 OpenRC。" >&2; exit 1; fi
fi

probe_url() {
  if command -v curl >/dev/null 2>&1; then curl --connect-timeout 3 --max-time 8 --silent --show-error --location --head "$1" >/dev/null 2>&1
  elif command -v wget >/dev/null 2>&1; then wget -q --spider --timeout=8 "$1" >/dev/null 2>&1
  else return 1; fi
}
NETWORK_REGION=global
CN_MIRROR=""
if ! probe_url https://github.com; then
  for candidate in https://mirrors.tuna.tsinghua.edu.cn https://mirrors.ustc.edu.cn; do
    if probe_url "$candidate"; then
      NETWORK_REGION=china
      CN_MIRROR="$candidate"
      echo "检测到 GitHub 直连不可达，依赖下载临时使用教育网镜像：$CN_MIRROR"
      break
    fi
  done
  if [ -z "$GITHUB_PROXY" ] && probe_url https://ghfast.top/https://github.com; then
    GITHUB_PROXY=https://ghfast.top/
    echo "EasyTier 发布包改用 GitHub 代理：$GITHUB_PROXY"
  fi
fi

WORK_DIR="$(mktemp -d)"
MIRROR_BACKUPS=()
restore_package_mirrors() {
  local source backup
  for source in "${MIRROR_BACKUPS[@]}"; do
    backup="$source.$OPENRC_SERVICE.eot-backup"
    [ -f "$backup" ] && mv -f "$backup" "$source"
  done
}
cleanup() { restore_package_mirrors; rm -rf "$WORK_DIR"; }
trap cleanup EXIT
trap 'cleanup; exit 1' INT TERM HUP

configure_china_package_mirrors() {
  [ "$NETWORK_REGION" = china ] || return 0
  local source backup mirror_host
  mirror_host="${CN_MIRROR#https://}"
  if command -v apt-get >/dev/null 2>&1; then
    for source in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
      [ -f "$source" ] || continue
      backup="$source.$OPENRC_SERVICE.eot-backup"
      [ -f "$backup" ] || cp -p "$source" "$backup"
      MIRROR_BACKUPS+=("$source")
      sed -i -E \
        -e "s@([a-z]+://)([^/]*\\.)?archive\\.ubuntu\\.com/ubuntu/?@\\1${mirror_host}/ubuntu/@g" \
        -e "s@([a-z]+://)deb\\.debian\\.org/debian/?@\\1${mirror_host}/debian/@g" \
        -e "s@([a-z]+://)packages\\.deepin\\.com/deepin/?@\\1${mirror_host}/deepin/@g" "$source"
    done
    apt-get update || echo "教育网 APT 镜像刷新失败，继续使用现有缓存。"
  elif command -v pacman >/dev/null 2>&1 && [ -f /etc/pacman.d/mirrorlist ]; then
    source=/etc/pacman.d/mirrorlist; backup="$source.$OPENRC_SERVICE.eot-backup"
    [ -f "$backup" ] || cp -p "$source" "$backup"; MIRROR_BACKUPS+=("$source")
    { echo "Server = $CN_MIRROR/archlinux/\$repo/os/\$arch"; cat "$backup"; } > "$source"
    pacman -Syy --noconfirm || echo "教育网 Arch 镜像刷新失败，继续使用已有镜像。"
  elif command -v apk >/dev/null 2>&1 && [ -f /etc/apk/repositories ]; then
    source=/etc/apk/repositories; backup="$source.$OPENRC_SERVICE.eot-backup"
    [ -f "$backup" ] || cp -p "$source" "$backup"; MIRROR_BACKUPS+=("$source")
    sed -i "s@https\\?://dl-cdn\\.alpinelinux\\.org/alpine@$CN_MIRROR/alpine@g" "$source"
    apk update || echo "教育网 Alpine 镜像刷新失败，继续使用已有镜像。"
  else
    echo "当前发行版保留已有软件源；未修改 Red Hat 或 Nix 的受管仓库配置。"
  fi
}

if [ "$NETWORK_REGION" = china ] && command -v nix >/dev/null 2>&1; then
  if [ "$CN_MIRROR" = https://mirrors.tuna.tsinghua.edu.cn ]; then
    export NIX_CONFIG="${NIX_CONFIG:-}
substituters = https://mirrors.tuna.tsinghua.edu.cn/nix-channels/store https://cache.nixos.org/"
  else
    echo "中科大镜像用于系统依赖；Nix 保留现有缓存配置。"
  fi
fi
configure_china_package_mirrors

if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1 || ! command -v iperf3 >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then apt-get install -y curl unzip iperf3
  elif command -v dnf >/dev/null 2>&1; then dnf install -y curl unzip iperf3
  elif command -v yum >/dev/null 2>&1; then yum install -y curl unzip iperf3
  elif command -v pacman >/dev/null 2>&1; then pacman -Sy --noconfirm curl unzip iperf3
  elif command -v apk >/dev/null 2>&1; then apk add --no-cache curl unzip iperf3
  elif command -v nix >/dev/null 2>&1; then nix profile install nixpkgs#curl nixpkgs#unzip nixpkgs#iperf3 && export PATH="/root/.nix-profile/bin:$PATH"
  else echo "缺少 curl、unzip 或 iperf3，且无法识别包管理器。" >&2; exit 1; fi
fi
if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1 || ! command -v iperf3 >/dev/null 2>&1; then
  echo "安装 curl、unzip 或 iperf3 后仍不可用。" >&2; exit 1
fi

download() {
  curl --fail --location --retry 3 --retry-all-errors --connect-timeout 10 --max-time 300 --speed-limit 1024 --speed-time 30 -C - --output "$2" "${GITHUB_PROXY}$1"
}

ASSET=%q

download "$ASSET" "$WORK_DIR/easytier.zip"
unzip -q -o "$WORK_DIR/easytier.zip" -d "$WORK_DIR/unpacked"
SOURCE_DIR="$(dirname "$(find "$WORK_DIR/unpacked" -type f -name easytier-core -print -quit)")"
if [ -z "$SOURCE_DIR" ] || [ ! -x "$SOURCE_DIR/easytier-core" ]; then
  echo "下载包中未找到 easytier-core。" >&2
  exit 1
fi

install -d -m 0755 "$INSTALL_DIR/config"
install -m 0755 "$SOURCE_DIR/easytier-core" "$INSTALL_DIR/easytier-core"
install -m 0755 "$SOURCE_DIR/easytier-cli" "$INSTALL_DIR/easytier-cli"
cat > "$CONFIG_FILE" <<'EASYTIER_CONFIG'
%s
EASYTIER_CONFIG
chmod 600 "$CONFIG_FILE"

if [ "$INIT_SYSTEM" = systemd ]; then
  cat > "$UNIT_FILE" <<'SYSTEMD_UNIT'
[Unit]
Description=EasyTier team node %s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s/easytier-core -c %s
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
SYSTEMD_UNIT
%s
  systemctl daemon-reload
  systemctl enable --now "$OPENRC_SERVICE.service"
else
  cat > "/etc/init.d/$OPENRC_SERVICE" <<'OPENRC_SERVICE'
#!/sbin/openrc-run
name="EasyTier team node"
command="%s/easytier-core"
command_args="-c %s"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"
depend() { need net; }
OPENRC_SERVICE
  chmod 0755 "/etc/init.d/$OPENRC_SERVICE"
  rc-update add "$OPENRC_SERVICE" default
  rc-service "$OPENRC_SERVICE" restart
fi

configure_china_package_mirrors

INSTALL_GUI=0
case "$LINUX_DEVICE_TYPE" in
  desktop) INSTALL_GUI=1 ;;
  auto)
    if [ -d /usr/share/xsessions ] || { [ "$INIT_SYSTEM" = systemd ] && { systemctl get-default 2>/dev/null | grep -qx graphical.target || systemctl is-active --quiet display-manager 2>/dev/null; }; }; then INSTALL_GUI=1; fi ;;
esac
if [ "$INSTALL_GUI" -eq 1 ]; then
  GUI_VERSION="${VERSION#v}"
  if [ -z "$GUI_ARCH" ]; then
    echo "当前架构没有 EasyTier 官方 Linux GUI 发布包，保留命令行服务。"
  else
    GUI_URL="https://github.com/EasyTier/EasyTier/releases/download/$VERSION"
    GUI_APPIMAGE="$INSTALL_DIR/easytier-gui.AppImage"
    if command -v nix >/dev/null 2>&1; then
      if download "$GUI_URL/easytier-gui_${GUI_VERSION}_${GUI_ARCH}.AppImage" "$GUI_APPIMAGE"; then
        chmod 0755 "$GUI_APPIMAGE"
        cat > "$INSTALL_DIR/easytier-gui" <<NIX_GUI
#!/bin/sh
exec nix run nixpkgs#appimage-run -- "$GUI_APPIMAGE" "\$@"
NIX_GUI
        chmod 0755 "$INSTALL_DIR/easytier-gui"
        echo "已下载 NixOS GUI；运行 $INSTALL_DIR/easytier-gui 启动。"
      else echo "GUI 下载失败；命令行服务仍已部署。"; fi
    elif command -v apt-get >/dev/null 2>&1; then
      GUI_PACKAGE="$WORK_DIR/easytier-gui.deb"
      if download "$GUI_URL/easytier-gui_${GUI_VERSION}_${DEB_ARCH}.deb" "$GUI_PACKAGE"; then
        dpkg -i "$GUI_PACKAGE" || apt-get install -f -y
        echo "已安装 EasyTier Linux GUI（DEB）。"
      else echo "GUI 下载失败；命令行服务仍已部署。"; fi
    elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
      GUI_PACKAGE="$WORK_DIR/easytier-gui.rpm"
      if download "$GUI_URL/easytier-gui-${GUI_VERSION}-1.${RPM_ARCH}.rpm" "$GUI_PACKAGE"; then
        if command -v dnf >/dev/null 2>&1; then dnf install -y "$GUI_PACKAGE"; else yum localinstall -y "$GUI_PACKAGE"; fi
        echo "已安装 EasyTier Linux GUI（RPM）。"
      else echo "GUI 下载失败；命令行服务仍已部署。"; fi
    else
      if command -v pacman >/dev/null 2>&1; then pacman -Sy --noconfirm fuse2 || true
      elif command -v apk >/dev/null 2>&1; then apk add --no-cache gcompat fuse3 libstdc++ || true; fi
      if download "$GUI_URL/easytier-gui_${GUI_VERSION}_${GUI_ARCH}.AppImage" "$GUI_APPIMAGE"; then
        chmod 0755 "$GUI_APPIMAGE"
        echo "已下载 EasyTier Linux GUI AppImage：$GUI_APPIMAGE"
      else echo "GUI 下载失败；命令行服务仍已部署。"; fi
    fi
  fi
fi

if [ "$INIT_SYSTEM" = systemd ]; then systemctl --no-pager --full status "$OPENRC_SERVICE.service" || true
else rc-service "$OPENRC_SERVICE" status || true; fi
sleep 3
if [ "$INIT_SYSTEM" = systemd ]; then
  systemctl is-active --quiet "$OPENRC_SERVICE.service" || echo "警告：服务未保持运行，请检查 journalctl -u $OPENRC_SERVICE.service" >&2
else
  rc-service "$OPENRC_SERVICE" status >/dev/null 2>&1 || echo "警告：服务未保持运行，请检查 rc-service 状态" >&2
fi
echo %s
`, shellQuote(installDir), shellQuote(unit), shellQuote(shortNodeID), shellQuote(project.ReleaseVersion), shellQuote(proxy), shellQuote(deviceType), asset, config, node.Name, installDir, configFile, firewall, installDir, configFile, shellQuote("EasyTier 节点 "+node.Name+" 已部署，虚拟 IP："+node.OverlayIP))
}

func windowsScript(project Project, node Node) string {
	config := nodeConfig(project, node)
	proxy := downloadProxy(project.GitHubProxy)
	return fmt.Sprintf(`#requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
$Version = %s
$GitHubProxy = %s
$InstallDir = "C:\\EasyTierTeam\\" + %s
$ConfigFile = Join-Path $InstallDir "easytier.toml"
$Arch = if ([Environment]::Is64BitOperatingSystem) { "x86_64" } else { "i686" }
$Asset = "https://github.com/EasyTier/EasyTier/releases/download/$Version/easytier-windows-$Arch-$Version.zip"
$DownloadUrl = "$GitHubProxy$Asset"
$TempZip = Join-Path $env:TEMP "easytier-$Version.zip"
$ExtractDir = Join-Path $env:TEMP ("easytier-" + [guid]::NewGuid())

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempZip
Expand-Archive -Path $TempZip -DestinationPath $ExtractDir -Force
$SourceCore = Get-ChildItem -Path $ExtractDir -Recurse -Filter "easytier-core.exe" | Select-Object -First 1
if ($null -eq $SourceCore) { throw "下载包中未找到 easytier-core.exe" }
$SourceDir = $SourceCore.Directory.FullName
Copy-Item "$SourceDir\\easytier-core.exe" "$InstallDir\\easytier-core.exe" -Force
Copy-Item "$SourceDir\\easytier-cli.exe" "$InstallDir\\easytier-cli.exe" -Force
@'
%s
'@ | Set-Content -Path $ConfigFile -Encoding UTF8

& "$InstallDir\\easytier-cli.exe" service uninstall 2>$null
& "$InstallDir\\easytier-cli.exe" service install --display-name %s --core-path "$InstallDir\\easytier-core.exe" --service-work-dir $InstallDir -- -c $ConfigFile
& "$InstallDir\\easytier-cli.exe" service start
Remove-Item $TempZip -Force -ErrorAction SilentlyContinue
Remove-Item $ExtractDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host %s -ForegroundColor Green
`, psString(project.ReleaseVersion), psString(proxy), psString(shortID(node.ID)), config, psString("EasyTier Team - "+node.Name), psString("EasyTier 节点 "+node.Name+" 已部署，虚拟 IP："+node.OverlayIP))
}

// psString 把任意字符串变成 PowerShell 单引号安全字面量。
func psString(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func newID() string {
	value := make([]byte, 16)
	_, _ = rand.Read(value)
	return hex.EncodeToString(value)
}

type app struct {
	store      *store
	publicBase string
	agentDir   string
}

func downloadProxy(proxy string) string {
	if proxy == "" {
		return ""
	}
	return strings.TrimRight(proxy, "/") + "/"
}

func randomHex(size int) string {
	value := make([]byte, size)
	_, _ = rand.Read(value)
	return hex.EncodeToString(value)
}
func (a *app) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		a.api(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/install/") {
		a.install(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/agents/") {
		a.serveAgent(w, r)
		return
	}
	if r.URL.Path == "/install.sh" {
		a.serveInstallScript(w)
		return
	}
	web, _ := fs.Sub(webFS, "web")
	http.FileServer(http.FS(web)).ServeHTTP(w, r)
}

func (a *app) serveInstallScript(w http.ResponseWriter) {
	content, err := fs.ReadFile(webFS, "scripts/install.sh")
	if err != nil {
		http.Error(w, "安装脚本不可用", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_, _ = w.Write(content)
}

// servePublic 只对外提供安装脚本与探针二进制，管理 API 与 UI 一律不可达。
func (a *app) servePublic(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/install/") {
		a.install(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/agents/") {
		a.serveAgent(w, r)
		return
	}
	if r.URL.Path == "/install.sh" {
		a.serveInstallScript(w)
		return
	}
	http.NotFound(w, r)
}

func (a *app) serveAgent(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(strings.TrimPrefix(r.URL.Path, "/agents/"))
	if name == "." || name == ".." || name == "" || a.agentDir == "" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, filepath.Join(a.agentDir, name))
}

func (a *app) api(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.URL.Path == "/api/project" {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, a.store.snapshot())
		case http.MethodPut:
			var project Project
			if err := decodeJSON(r, &project); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			if project.Relay.ID == "" {
				project.Relay.ID = newID()
			}
			project.Relay.Role = "relay"
			for index := range project.Nodes {
				if project.Nodes[index].ID == "" {
					project.Nodes[index].ID = newID()
				}
				project.Nodes[index].Role = "member"
			}
			if err := a.store.save(project); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			writeJSON(w, http.StatusOK, a.store.snapshot())
		default:
			methodNotAllowed(w)
		}
		return
	}
	if r.URL.Path == "/api/probes" {
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		writeJSON(w, http.StatusOK, a.runSequentialProbes(a.store.snapshot()))
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/nodes/"), "/")
	if len(parts) != 2 || r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, errors.New("接口不存在"))
		return
	}
	project, node, err := a.store.node(parts[0])
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	switch parts[1] {
	case "script":
		writeJSON(w, http.StatusOK, map[string]string{"script": scriptFor(project, node)})
	case "install-link":
		token, err := a.store.newToken(node.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		installURL := a.installBase(project) + "/install/" + token
		command := "curl -fsSL " + shellQuote(installURL) + " | sudo bash"
		if node.OS == "windows" {
			command = "irm " + psString(installURL) + " | iex"
		}
		png, err := qrcode.Encode(command, qrcode.Medium, 256)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"url": installURL, "command": command, "qrDataURL": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)})
	case "deploy":
		if node.OS != "linux" {
			writeError(w, http.StatusBadRequest, errors.New("Windows 节点请使用生成的 PowerShell 安装入口"))
			return
		}
		result, err := deploySSH(node, linuxScript(project, node), deployTimeout)
		if err != nil {
			writeError(w, http.StatusBadGateway, fmt.Errorf("SSH 部署 %s: %w", node.Name, err))
			return
		}
		if err := a.store.trustHost(node.ID, result.fingerprint); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"output": result.output, "fingerprint": result.fingerprint})
	default:
		writeError(w, http.StatusNotFound, errors.New("接口不存在"))
	}
}

func (a *app) install(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/install/")
	if token == "" || strings.Contains(token, "/") {
		http.Error(w, "安装链接无效", http.StatusNotFound)
		return
	}
	nodeID, err := a.store.consumeToken(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusGone)
		return
	}
	project, node, err := a.store.node(nodeID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if node.OS == "windows" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", "inline; filename=install-easytier.ps1")
		io.WriteString(w, windowsScript(project, node))
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	io.WriteString(w, linuxScript(project, node))
}
func (a *app) installBase(project Project) string {
	if project.ScriptBaseURL != "" {
		return strings.TrimRight(project.ScriptBaseURL, "/")
	}
	return a.publicBase
}

func scriptFor(project Project, node Node) string {
	if node.OS == "windows" {
		return windowsScript(project, node)
	}
	return linuxScript(project, node)
}
func decodeJSON(r *http.Request, value any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 2<<20)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("请求数据无效: %w", err)
	}
	return nil
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
func methodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed, errors.New("不支持的请求方法"))
}

type probeResult struct {
	NodeID     string          `json:"nodeId"`
	Name       string          `json:"name"`
	OverlayIP  string          `json:"overlayIp"`
	PingMS     float64         `json:"pingMs,omitempty"`
	Pong       json.RawMessage `json:"pong,omitempty"`
	Iperf      json.RawMessage `json:"iperf,omitempty"`
	PingError  string          `json:"pingError,omitempty"`
	IperfError string          `json:"iperfError,omitempty"`
}

const deployTimeout = 30 * time.Minute

func (a *app) runSequentialProbes(project Project) []probeResult {
	nodes := append([]Node{project.Relay}, project.Nodes...)
	client := &http.Client{Timeout: 8 * time.Second}
	results := make([]probeResult, 0, len(nodes))
	for _, node := range nodes {
		results = append(results, a.probeOne(project, node, client))
	}
	return results
}

func (a *app) probeOne(project Project, node Node, client *http.Client) probeResult {
	result := probeResult{NodeID: node.ID, Name: node.Name, OverlayIP: node.OverlayIP}
	if node.OS != "linux" {
		result.PingError = "一次性探针目前要求 Linux SSH 节点"
		return result
	}
	if node.OverlayIP == "" {
		result.PingError = "DHCP 网络下节点 IP 由 EasyTier 分配，暂不支持探针"
		return result
	}
	if err := startEphemeralProbe(node, a.installBase(project), project.ProbeToken); err != nil {
		result.PingError = err.Error()
		return result
	}
	defer cleanupProbe(node)
	body, _ := json.Marshal(map[string]string{"requestId": newID(), "controllerTime": time.Now().UTC().Format(time.RFC3339Nano), "machine": node.Name})
	request, _ := http.NewRequest(http.MethodPost, "http://"+net.JoinHostPort(node.OverlayIP, "19090")+"/v1/ping", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+project.ProbeToken)
	request.Header.Set("Content-Type", "application/json")
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		result.PingError = err.Error()
		return result
	}
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, 128<<10))
	response.Body.Close()
	if response.StatusCode != http.StatusOK || readErr != nil {
		result.PingError = response.Status
		return result
	}
	result.PingMS, result.Pong = float64(time.Since(started).Microseconds())/1000, payload
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	output, runErr := exec.CommandContext(ctx, "iperf3", "-J", "-c", node.OverlayIP, "-t", "3").Output()
	cancel()
	if runErr != nil {
		result.IperfError = runErr.Error()
	} else {
		result.Iperf = output
	}
	return result
}

// cleanupProbe 清掉目标机上残留的一次性探针进程与文件；所有退出路径都调用，
// 防止远端 node-agent/iperf3 永久驻留占住 19090 端口。
func cleanupProbe(node Node) {
	command := "rm -f /tmp/easytier-node-probe /tmp/easytier-node-probe.log /tmp/easytier-iperf3.log; " +
		"pkill -f /tmp/easytier-node-probe 2>/dev/null || true; " +
		"pkill -f " + shellQuote("iperf3 -s -1 -B "+node.OverlayIP) + " 2>/dev/null || true"
	_, _ = deploySSH(node, command, 60*time.Second)
}

func startEphemeralProbe(node Node, agentBase, token string) error {
	if strings.HasPrefix(agentBase, "http://127.") || strings.Contains(agentBase, "://localhost") {
		return errors.New("一次性探针需要可被目标机访问的安装脚本公开地址")
	}
	script := fmt.Sprintf(`set -eu
case "$(uname -m)" in
  x86_64|amd64) ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  armv7l|armv7) ARCH=armv7 ;;
  *) echo "unsupported architecture" >&2; exit 1 ;;
esac
curl --fail --location --retry 2 -o /tmp/easytier-node-probe %s/agents/node-agent-linux-${ARCH}
chmod 0700 /tmp/easytier-node-probe
nohup /tmp/easytier-node-probe --once --once-timeout 15m --listen %s --token %s --node-id %s --overlay-ip %s >/tmp/easytier-node-probe.log 2>&1 &
nohup iperf3 -s -1 -B %s >/tmp/easytier-iperf3.log 2>&1 &
`, shellQuote(strings.TrimRight(agentBase, "/")), shellQuote(net.JoinHostPort(node.OverlayIP, "19090")), shellQuote(token), shellQuote(node.ID), shellQuote(node.OverlayIP), shellQuote(node.OverlayIP))
	_, err := deploySSH(node, script, 60*time.Second)
	return err
}

type deployResult struct{ output, fingerprint string }

func deploySSH(node Node, script string, timeout time.Duration) (deployResult, error) {
	if node.Host == "" || node.SSHUser == "" {
		return deployResult{}, errors.New("Linux 节点需要 SSH 主机和用户")
	}
	var auth ssh.AuthMethod
	switch node.SSHAuth {
	case "password":
		if node.SSHPassword == "" {
			return deployResult{}, errors.New("未填写 SSH 密码")
		}
		auth = ssh.Password(node.SSHPassword)
	case "", "key":
		if node.SSHPrivateKey == "" {
			return deployResult{}, errors.New("未填写 SSH 私钥文件路径")
		}
		keyPath := node.SSHPrivateKey
		if strings.HasPrefix(keyPath, "~/") {
			home, _ := os.UserHomeDir()
			keyPath = filepath.Join(home, strings.TrimPrefix(keyPath, "~/"))
		}
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return deployResult{}, fmt.Errorf("读取 SSH 私钥: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return deployResult{}, fmt.Errorf("解析 SSH 私钥: %w", err)
		}
		auth = ssh.PublicKeys(signer)
	default:
		return deployResult{}, errors.New("SSH 登录方式必须是 key 或 password")
	}
	fingerprint := ""
	handshakeTimeout := 15 * time.Second
	if timeout < handshakeTimeout {
		handshakeTimeout = timeout
	}
	config := &ssh.ClientConfig{User: node.SSHUser, Auth: []ssh.AuthMethod{auth}, Timeout: handshakeTimeout, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		observed := ssh.FingerprintSHA256(key)
		if node.HostKeyFingerprint != "" && node.HostKeyFingerprint != observed {
			return fmt.Errorf("SSH 主机指纹不匹配：期望 %s，实际 %s", node.HostKeyFingerprint, observed)
		}
		fingerprint = observed
		return nil
	}}
	address := net.JoinHostPort(node.Host, fmt.Sprint(node.SSHPort))
	if _, _, err := net.SplitHostPort(node.Host); err == nil {
		address = node.Host
	}
	connection, err := net.DialTimeout("tcp", address, handshakeTimeout)
	if err != nil {
		return deployResult{}, err
	}
	defer connection.Close()
	// ssh.Dial 的 Timeout 只约束 TCP 拨号；握手（banner/kex/auth）必须自己给 deadline。
	if err := connection.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return deployResult{}, err
	}
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, address, config)
	if err != nil {
		return deployResult{}, err
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return deployResult{}, err
	}
	client := ssh.NewClient(clientConnection, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return deployResult{}, err
	}
	defer session.Close()
	var stdout, stderr bytes.Buffer
	session.Stdin = strings.NewReader(script)
	session.Stdout = &stdout
	session.Stderr = &stderr
	type runOutcome struct {
		result deployResult
		err    error
	}
	finished := make(chan runOutcome, 1)
	go func() {
		err := session.Run("bash -s")
		finished <- runOutcome{deployResult{output: stdout.String() + stderr.String(), fingerprint: fingerprint}, err}
	}()
	select {
	case outcome := <-finished:
		if outcome.err != nil {
			return deployResult{}, fmt.Errorf("远程脚本失败: %w\n%s", outcome.err, outcome.result.output)
		}
		return outcome.result, nil
	case <-time.After(timeout):
		_ = session.Close()
		_ = client.Close()
		return deployResult{}, fmt.Errorf("远程脚本执行超过 %s，已中止", timeout)
	}
}

func openBrowser(address string) {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("cmd", "/c", "start", "", address)
	case "darwin":
		command = exec.Command("open", address)
	default:
		command = exec.Command("xdg-open", address)
	}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	_ = command.Start()
}

func main() {
	var dataDir, listen, publicListen, publicBase, agentDir string
	flag.StringVar(&dataDir, "data-dir", "", "本地配置目录")
	flag.StringVar(&listen, "listen", "127.0.0.1:0", "本地管理监听地址；默认仅本机")
	flag.StringVar(&publicListen, "public-listen", "", "仅对外提供安装脚本与探针下载的监听地址，例如 0.0.0.0:8443；默认关闭")
	flag.StringVar(&publicBase, "public-base", "", "脚本下载使用的公开基址，例如 https://installer.example.com")
	flag.StringVar(&agentDir, "agent-dir", "", "节点探针二进制目录")
	flag.Parse()
	if dataDir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			base = "."
		}
		dataDir = filepath.Join(base, "easytier-team-installer")
	}
	state, err := loadStore(filepath.Join(dataDir, "state.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "启动本地服务器:", err)
		os.Exit(1)
	}
	localAddress := "http://" + listener.Addr().String()
	if agentDir == "" {
		executable, err := os.Executable()
		if err == nil {
			agentDir = filepath.Clean(filepath.Join(filepath.Dir(executable), "..", "agents"))
		}
	}
	application := &app{store: state, publicBase: publicBase, agentDir: agentDir}
	server := &http.Server{Handler: http.HandlerFunc(application.serveHTTP), ReadHeaderTimeout: 5 * time.Second}
	var publicServer *http.Server
	if publicListen != "" {
		publicListener, err := net.Listen("tcp", publicListen)
		if err != nil {
			fmt.Fprintf(os.Stderr, "启动公开安装服务: %v\n", err)
			os.Exit(1)
		}
		if application.publicBase == "" {
			application.publicBase = "http://" + publicListener.Addr().String()
		}
		publicServer = &http.Server{Handler: http.HandlerFunc(application.servePublic), ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := publicServer.Serve(publicListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Fprintln(os.Stderr, err)
			}
		}()
	}
	if application.publicBase == "" {
		application.publicBase = localAddress
	}
	application.publicBase = strings.TrimRight(application.publicBase, "/")
	fmt.Printf("组队安装器正在运行：%s\n", localAddress)
	if application.publicBase != localAddress {
		fmt.Printf("专属安装脚本基址：%s\n", application.publicBase)
	}
	if strings.Contains(application.publicBase, "://0.0.0.0") || strings.Contains(application.publicBase, "://[::]") {
		fmt.Fprintln(os.Stderr, "警告：public-base 为空且监听通配地址，自动推导的安装基址目标机无法访问；请显式设置 -public-base。")
	}
	openBrowser(localAddress)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, err)
		}
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	<-signals
	context, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(context)
	if publicServer != nil {
		_ = publicServer.Shutdown(context)
	}
}
