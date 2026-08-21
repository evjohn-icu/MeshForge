#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DIST="$ROOT/dist"
rm -rf "$DIST"

build_controller() {
  os=$1 arch=$2 output=$3
  mkdir -p "$(dirname "$output")"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$output" .
}

build_agent() {
  os=$1 arch=$2 output=$3
  mkdir -p "$(dirname "$output")"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$output" ./cmd/node-agent
}

build_controller linux amd64 "$DIST/linux-amd64/team-installer"
build_controller darwin amd64 "$DIST/macos-amd64/team-installer"
build_controller darwin arm64 "$DIST/macos-arm64/team-installer"
build_controller windows amd64 "$DIST/windows-amd64/team-installer.exe"

build_agent linux amd64 "$DIST/agents/node-agent-linux-x86_64"
build_agent linux arm64 "$DIST/agents/node-agent-linux-aarch64"
build_agent linux arm "$DIST/agents/node-agent-linux-armv7"
build_agent windows amd64 "$DIST/agents/node-agent-windows-x86_64.exe"

for package in "$DIST/linux-amd64" "$DIST/macos-amd64" "$DIST/macos-arm64"; do
  install -m 0755 "$ROOT/scripts/start.sh" "$package/start.sh"
done

for package in "$DIST/linux-amd64" "$DIST/macos-amd64" "$DIST/macos-arm64" "$DIST/windows-amd64"; do
  mkdir -p "$package/agents"
  cp "$DIST"/agents/* "$package/agents/"
done

echo "已生成跨平台入口：$DIST"

