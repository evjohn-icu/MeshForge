package main

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testProject() Project {
	return Project{
		Name:           "team",
		ReleaseVersion: "v2.6.4",
		NetworkName:    "team-network",
		NetworkSecret:  "sixteen-character-secret",
		GitHubProxy:    "https://ghfast.top/",
		Relay:          Node{ID: "relay0001", Role: "relay", Name: "relay", OS: "linux", OverlayIP: "10.144.144.1", Host: "relay.example.com", SSHPort: 22},
		Nodes:          []Node{{ID: "member01", Role: "member", Name: "office", OS: "linux", OverlayIP: "10.144.144.2", SSHPort: 22}},
	}
}

func TestNodeConfigUsesRelayEndpoints(t *testing.T) {
	project := testProject()
	config := nodeConfig(project, project.Nodes[0])
	for _, expected := range []string{
		`network_name = "team-network"`,
		`network_secret = "sixteen-character-secret"`,
		`uri = "tcp://relay.example.com:11010"`,
		`uri = "udp://relay.example.com:11010"`,
	} {
		if !strings.Contains(config, expected) {
			t.Fatalf("config missing %q:\n%s", expected, config)
		}
	}
}

func TestRelayWireGuardPortalConfiguration(t *testing.T) {
	project := testProject()
	project.WireGuardEnabled = true
	project.WireGuardPort = 11013
	project.WireGuardCIDR = "10.14.14.0/24"
	config := nodeConfig(project, project.Relay)
	for _, expected := range []string{
		"[vpn_portal_config]",
		`wireguard_listen = "0.0.0.0:11013"`,
		`client_cidr = "10.14.14.0/24"`,
	} {
		if !strings.Contains(config, expected) {
			t.Fatalf("WireGuard config missing %q:\n%s", expected, config)
		}
	}
	if !strings.Contains(linuxScript(project, project.Relay), "ufw allow 11013/udp") {
		t.Fatal("relay script does not open WireGuard UDP port")
	}
}

func TestInstallScriptsUseConfiguredProxy(t *testing.T) {
	project := testProject()
	linux := linuxScript(project, project.Nodes[0])
	if !strings.Contains(linux, `GITHUB_PROXY="https://ghfast.top/"`) || !strings.Contains(linux, "easytier-linux-${ARCH}-v2.6.4.zip") {
		t.Fatalf("linux script did not retain proxy and version:\n%s", linux)
	}
	windowsNode := project.Nodes[0]
	windowsNode.OS = "windows"
	windows := windowsScript(project, windowsNode)
	if !strings.Contains(windows, `$GitHubProxy = "https://ghfast.top/"`) || !strings.Contains(windows, "easytier-windows-$Arch-$Version.zip") {
		t.Fatalf("windows script did not retain proxy and version:\n%s", windows)
	}
}

func TestLinuxScriptPassesBashSyntaxCheck(t *testing.T) {
	project := testProject()
	scriptPath := t.TempDir() + "/install.sh"
	if err := os.WriteFile(scriptPath, []byte(linuxScript(project, project.Nodes[0])), 0700); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("bash", "-n", scriptPath).CombinedOutput(); err != nil {
		t.Fatalf("linux script has invalid bash syntax: %v\n%s", err, output)
	}
}

func TestDesktopLinuxScriptInstallsOfficialGUI(t *testing.T) {
	project := testProject()
	node := project.Nodes[0]
	node.LinuxDeviceType = "desktop"
	script := linuxScript(project, node)
	for _, expected := range []string{
		`LINUX_DEVICE_TYPE="desktop"`,
		`easytier-gui_${GUI_VERSION}_${DEB_ARCH}.deb`,
		`easytier-gui_${GUI_VERSION}_${GUI_ARCH}.AppImage`,
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("desktop script missing %q:\n%s", expected, script)
		}
	}
	if strings.Contains(linuxScript(project, project.Relay), `LINUX_DEVICE_TYPE="desktop"`) {
		t.Fatal("relay must never use desktop GUI mode")
	}
}

func TestLinuxScriptCoversRequestedDistributions(t *testing.T) {
	project := testProject()
	node := project.Nodes[0]
	node.LinuxDeviceType = "desktop"
	script := linuxScript(project, node)
	for _, expected := range []string{
		"nix profile install nixpkgs#curl nixpkgs#unzip",
		"nix run nixpkgs#appimage-run",
		"apk add --no-cache curl unzip",
		"rc-service \"$OPENRC_SERVICE\" restart",
		"pacman -Sy --noconfirm curl unzip",
		"pacman -Sy --noconfirm fuse2",
		"apt-get install -y curl unzip",
		"easytier-gui_${GUI_VERSION}_${DEB_ARCH}.deb",
		"dnf install -y curl unzip",
		"easytier-gui-${GUI_VERSION}-1.${RPM_ARCH}.rpm",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("distribution branch missing %q", expected)
		}
	}
}

func TestLinuxScriptHasChinaReachabilityFallback(t *testing.T) {
	script := linuxScript(testProject(), testProject().Nodes[0])
	for _, expected := range []string{
		"NETWORK_REGION=global",
		"https://mirrors.tuna.tsinghua.edu.cn https://mirrors.ustc.edu.cn",
		"GITHUB_PROXY=https://ghfast.top/",
		"configure_china_package_mirrors",
		"$CN_MIRROR/archlinux/\\$repo/os/\\$arch",
		"$CN_MIRROR/alpine",
		"https://mirrors.tuna.tsinghua.edu.cn/nix-channels/store",
		"restore_package_mirrors",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("network fallback missing %q", expected)
		}
	}
}

func TestInstallTokenIsSingleUse(t *testing.T) {
	state := &store{tokens: make(map[string]installToken)}
	state.tokens["token"] = installToken{NodeID: "node", ExpiresAt: time.Now().Add(time.Minute), Remaining: 1}
	id, err := state.consumeToken("token")
	if err != nil || id != "node" {
		t.Fatalf("first use = %q, %v", id, err)
	}
	if _, err := state.consumeToken("token"); err == nil {
		t.Fatal("consumed token remained valid")
	}
}

func TestInstallBasePrefersConfiguredAddress(t *testing.T) {
	application := app{publicBase: "http://127.0.0.1:8080"}
	project := testProject()
	project.ScriptBaseURL = "https://installer.example.com/"
	if actual := application.installBase(project); actual != "https://installer.example.com" {
		t.Fatalf("install base = %q", actual)
	}
}

func TestWebRootServesInterface(t *testing.T) {
	response := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/", nil)
	(&app{}).serveHTTP(response, request)
	if response.Code != 200 {
		t.Fatalf("web root status = %d", response.Code)
	}
	body := response.Body.String()
	if !strings.Contains(body, "组队安装器") || !strings.Contains(body, "安装脚本公开地址") {
		t.Fatalf("web root did not serve expected UI: %s", body)
	}
}

func TestDeploySSHStreamsGeneratedScript(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if string(password) != "test-password" {
			return nil, errors.New("bad password")
		}
		return nil, nil
	}}
	serverConfig.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan string, 1)
	go serveTestSSH(listener, serverConfig, received)

	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	result, err := deploySSH(Node{Host: host, SSHPort: port, SSHUser: "root", SSHAuth: "password", SSHPassword: "test-password"}, "echo deploy-smoke\n")
	if err != nil {
		t.Fatal(err)
	}
	if result.fingerprint == "" {
		t.Fatalf("SSH 主机指纹未返回：%#v", result)
	}
	if script := <-received; script != "echo deploy-smoke\n" {
		t.Fatalf("SSH received %q", script)
	}
}

func serveTestSSH(listener net.Listener, config *ssh.ServerConfig, received chan<- string) {
	connection, err := listener.Accept()
	if err != nil {
		return
	}
	defer connection.Close()
	serverConnection, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		return
	}
	defer serverConnection.Close()
	go ssh.DiscardRequests(requests)
	newChannel := <-channels
	if newChannel.ChannelType() != "session" {
		_ = newChannel.Reject(ssh.UnknownChannelType, "expected session")
		return
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer channel.Close()
	for request := range requests {
		if request.Type != "exec" {
			_ = request.Reply(false, nil)
			continue
		}
		var payload struct{ Command string }
		if err := ssh.Unmarshal(request.Payload, &payload); err != nil || payload.Command != "bash -s" {
			_ = request.Reply(false, nil)
			return
		}
		_ = request.Reply(true, nil)
		body, _ := io.ReadAll(channel)
		received <- string(body)
		_, _ = io.WriteString(channel, "remote complete\n")
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		return
	}
}
