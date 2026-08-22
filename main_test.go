package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
		IPv4CIDR:       "10.144.144.0/24",
		MagicDNS:       true,
		GitHubProxy:    "https://ghfast.top/",
		Relay:          Node{ID: "aa000001", Role: "relay", Name: "relay", OS: "linux", OverlayIP: "10.144.144.1", Host: "relay.example.com", SSHPort: 22},
		Nodes:          []Node{{ID: "bb000002", Role: "member", Name: "office", OS: "linux", OverlayIP: "10.144.144.2", SSHPort: 22}},
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
	if !strings.Contains(linux, `GITHUB_PROXY='https://ghfast.top/'`) || !strings.Contains(linux, "easytier-linux-${ARCH}-v2.6.4.zip") {
		t.Fatalf("linux script did not retain proxy and version:\n%s", linux)
	}
	windowsNode := project.Nodes[0]
	windowsNode.OS = "windows"
	windows := windowsScript(project, windowsNode)
	if !strings.Contains(windows, `$GitHubProxy = 'https://ghfast.top/'`) || !strings.Contains(windows, "easytier-windows-$Arch-$Version.zip") {
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
		`LINUX_DEVICE_TYPE='desktop'`,
		`easytier-gui_${GUI_VERSION}_${DEB_ARCH}.deb`,
		`easytier-gui_${GUI_VERSION}_${GUI_ARCH}.AppImage`,
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("desktop script missing %q:\n%s", expected, script)
		}
	}
	if strings.Contains(linuxScript(project, project.Relay), `LINUX_DEVICE_TYPE='desktop'`) {
		t.Fatal("relay must never use desktop GUI mode")
	}
}

func TestLinuxScriptCoversRequestedDistributions(t *testing.T) {
	project := testProject()
	node := project.Nodes[0]
	node.LinuxDeviceType = "desktop"
	script := linuxScript(project, node)
	for _, expected := range []string{
		"export DEBIAN_FRONTEND=noninteractive",
		"--retry-all-errors --connect-timeout 10 --max-time 300 --speed-limit 1024 --speed-time 30 -C -",
		"trap 'cleanup; exit 1' INT TERM HUP",
		"[ -f \"$backup\" ] || cp -p \"$source\" \"$backup\"",
		"警告：服务未保持运行",
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
	result, err := deploySSH(Node{Host: host, SSHPort: port, SSHUser: "root", SSHAuth: "password", SSHPassword: "test-password"}, "echo deploy-smoke\n", 30*time.Second)
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

func TestShellQuoteRoundTripsThroughBash(t *testing.T) {
	for _, value := range []string{"plain", "a'b", `$(id -u)`, `x"y`, "back`tick", `semi;pipe|`, "newline\ninside", "trailing space "} {
		command := "printf '%s' " + shellQuote(value)
		output, err := exec.Command("bash", "-c", command).CombinedOutput()
		if err != nil {
			t.Fatalf("bash rejected %q: %v", value, err)
		}
		if string(output) != value {
			t.Fatalf("round trip %q → %q", value, output)
		}
	}
}

func TestLinuxScriptEscapesHostileNodeName(t *testing.T) {
	project := testProject()
	node := project.Nodes[0]
	node.Name = `pc$(echo pwned) && touch /tmp/easytier-pwned`
	script := linuxScript(project, node)
	scriptPath := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("bash", "-n", scriptPath).CombinedOutput(); err != nil {
		t.Fatalf("hostile name broke script syntax: %v\n%s", err, output)
	}
	var line string
	for _, candidate := range strings.Split(script, "\n") {
		if strings.HasPrefix(candidate, "echo ") && strings.Contains(candidate, "已部署") {
			line = candidate
		}
	}
	if line == "" {
		t.Fatal("deployment echo line not found")
	}
	output, err := exec.Command("bash", "-c", line).CombinedOutput()
	if err != nil {
		t.Fatalf("hostile name broke the echo line: %v\n%s", err, output)
	}
	if string(output) != "EasyTier 节点 "+node.Name+" 已部署，虚拟 IP："+node.OverlayIP+"\n" {
		t.Fatalf("unexpected echo output: %q", output)
	}
	if _, err := os.Stat("/tmp/easytier-pwned"); err == nil {
		t.Fatal("injected command executed")
	}
}

func TestProjectValidationRejectsUnsafeNodeID(t *testing.T) {
	project := testProject()
	project.Nodes[0].ID = ";echo HI;"
	if err := validateProject(project); err == nil {
		t.Fatal("unsafe node ID passed validation")
	}
	project.Nodes[0].ID = "3f0c1b2e-5a6d-4f7a-8c9d-0e1f2a3b4c5d"
	if err := validateProject(project); err != nil {
		t.Fatalf("UUID node ID rejected: %v", err)
	}
}

func TestLoadStoreValidatesStateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	project := testProject()
	project.Nodes[0].ID = ";echo HI;"
	encoded, err := json.Marshal(project)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStore(path); err == nil {
		t.Fatal("invalid persisted state loaded without error")
	}
	if _, err := loadStore(filepath.Join(dir, "missing.json")); err != nil {
		t.Fatalf("fresh load failed: %v", err)
	}
}

func TestTrustHostConcurrentPersistsFingerprints(t *testing.T) {
	state := &store{tokens: make(map[string]installToken)}
	state.path = filepath.Join(t.TempDir(), "state.json")
	project := testProject()
	if err := state.save(project); err != nil {
		t.Fatal(err)
	}
	relayID, nodeID := project.Relay.ID, project.Nodes[0].ID
	const rounds = 50
	var wait sync.WaitGroup
	wait.Add(rounds * 2)
	for range rounds {
		go func() {
			defer wait.Done()
			if err := state.trustHost(relayID, "fp-relay"); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wait.Done()
			if err := state.trustHost(nodeID, "fp-node"); err != nil {
				t.Error(err)
			}
		}()
	}
	wait.Wait()
	saved := state.snapshot()
	if saved.Relay.HostKeyFingerprint != "fp-relay" || saved.Nodes[0].HostKeyFingerprint != "fp-node" {
		t.Fatalf("concurrent trustHost lost an update: relay=%q node=%q", saved.Relay.HostKeyFingerprint, saved.Nodes[0].HostKeyFingerprint)
	}
	content, err := os.ReadFile(state.path)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk Project
	if err := json.Unmarshal(content, &onDisk); err != nil {
		t.Fatalf("state file corrupted: %v", err)
	}
	if onDisk.Relay.HostKeyFingerprint != "fp-relay" || onDisk.Nodes[0].HostKeyFingerprint != "fp-node" {
		t.Fatal("on-disk state lost an update")
	}
}

func TestPublicListenerRejectsAdminRoutes(t *testing.T) {
	application := &app{store: &store{tokens: make(map[string]installToken)}}
	for _, path := range []string{"/api/project", "/", "/agents/", "/agents/node-agent"} {
		response := httptest.NewRecorder()
		application.servePublic(response, httptest.NewRequest("GET", path, nil))
		if response.Code == 200 {
			t.Fatalf("public listener served admin route %s", path)
		}
	}
	response := httptest.NewRecorder()
	application.servePublic(response, httptest.NewRequest("GET", "/install/unknown-token", nil))
	if response.Code != http.StatusGone {
		t.Fatalf("install with invalid token = %d, want 410", response.Code)
	}
}

func TestDeploySSHHandshakeTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		time.Sleep(30 * time.Second)
	}()
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	started := time.Now()
	_, err = deploySSH(Node{Host: host, SSHPort: port, SSHUser: "root", SSHAuth: "password", SSHPassword: "irrelevant"}, "echo hi\n", 2*time.Second)
	if err == nil {
		t.Fatal("handshake stall returned success")
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("handshake stall took %s, timeout not enforced", elapsed)
	}
}

func TestWindowsScriptQuotesHostileValues(t *testing.T) {
	project := testProject()
	node := project.Nodes[0]
	node.OS = "windows"
	node.Name = "weird'name$x"
	script := windowsScript(project, node)
	for _, expected := range []string{
		`--display-name 'EasyTier Team - weird''name$x'`,
		`Write-Host 'EasyTier 节点 weird''name$x 已部署，虚拟 IP：10.144.144.2' -ForegroundColor Green`,
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("windows script missing %q:\n%s", expected, script)
		}
	}
}

func TestAssignOverlayIPsFillsFromSubnet(t *testing.T) {
	project := testProject()
	project.Relay.OverlayIP = ""
	project.Nodes[0].OverlayIP = ""
	project.Nodes = append(project.Nodes, Node{ID: "cc000003", Name: "third", OS: "linux", OverlayIP: ""})
	assigned := assignOverlayIPs(project)
	if assigned.Relay.OverlayIP != "10.144.144.1" || assigned.Nodes[0].OverlayIP != "10.144.144.2" || assigned.Nodes[1].OverlayIP != "10.144.144.3" {
		t.Fatalf("auto assignment = %s / %s / %s", assigned.Relay.OverlayIP, assigned.Nodes[0].OverlayIP, assigned.Nodes[1].OverlayIP)
	}
	project.Nodes[0].OverlayIP = "10.144.144.9"
	assigned = assignOverlayIPs(project)
	if assigned.Nodes[0].OverlayIP != "10.144.144.9" {
		t.Fatalf("existing IP overwritten: %s", assigned.Nodes[0].OverlayIP)
	}
}

func TestNodeConfigMagicDNSAndHostname(t *testing.T) {
	project := testProject()
	config := nodeConfig(project, project.Nodes[0])
	for _, expected := range []string{`hostname = "office"`, "accept_dns = true"} {
		if !strings.Contains(config, expected) {
			t.Fatalf("config missing %q:\n%s", expected, config)
		}
	}
	project.MagicDNS = false
	if strings.Contains(nodeConfig(project, project.Nodes[0]), "accept_dns") {
		t.Fatal("magic dns disabled but accept_dns emitted")
	}
	project.DHCP = true
	config = nodeConfig(project, project.Nodes[0])
	if !strings.Contains(config, "dhcp = true") || strings.Contains(config, "ipv4 =") {
		t.Fatalf("dhcp config wrong:\n%s", config)
	}
	node := project.Nodes[0]
	node.Name = "我的 节点"
	config = nodeConfig(project, node)
	if !strings.Contains(config, `hostname = "node-bb000002"`) {
		t.Fatalf("hostile name hostname wrong:\n%s", config)
	}
}

func TestLoadStoreMigratesSubnet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	project := testProject()
	project.IPv4CIDR = ""
	encoded, err := json.Marshal(project)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	state, err := loadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if state.project.IPv4CIDR != "10.144.144.0/24" {
		t.Fatalf("migrated subnet = %q", state.project.IPv4CIDR)
	}
}

func TestValidateProjectRejectsIPOutsideSubnet(t *testing.T) {
	project := testProject()
	project.Nodes[0].OverlayIP = "10.99.99.2"
	if err := validateProject(project); err == nil {
		t.Fatal("IP outside subnet passed validation")
	}
}
