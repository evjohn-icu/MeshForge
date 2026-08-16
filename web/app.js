const $ = (selector) => document.querySelector(selector);
const api = async (path, options = {}) => {
  const response = await fetch(path, { headers: { "Content-Type": "application/json" }, ...options });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `请求失败（${response.status}）`);
  return payload;
};

let project;
const form = $("#project-form");
const dialog = $("#output-dialog");
const output = $("#output");
const qrCode = $("#qr-code");

function nodeId() { return crypto.randomUUID(); }
function emptyNode(role = "member") {
  const next = (project?.nodes?.length || 0) + 2;
  return { id: nodeId(), role, name: role === "relay" ? "relay-vps" : `node-${next}`, os: "linux", linuxDeviceType: role === "relay" ? "server" : "auto", overlayIP: `10.144.144.${next}`, host: "", sshPort: 22, sshUser: "root", sshAuth: "key", sshPrivateKey: "", sshPassword: "", hostKeyFingerprint: "" };
}
function field(label, key, value, type = "text", placeholder = "") {
  return `<label>${label}<input data-key="${key}" type="${type}" value="${escapeHtml(value ?? "")}" placeholder="${placeholder}"></label>`;
}
function selectField(label, key, value, options) {
  return `<label>${label}<select data-key="${key}">${options.map(([v, text]) => `<option value="${v}" ${v === value ? "selected" : ""}>${text}</option>`).join("")}</select></label>`;
}
function escapeHtml(value) { return String(value).replace(/[&<>'"]/g, ch => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", "'":"&#39;", '"':"&quot;" }[ch])); }
function nodeFields(node, includeRole = false) {
  return [
    field("节点名称", "name", node.name, "text", "例如：office-pc"),
    selectField("系统", "os", node.os, [["linux", "Linux"], ["windows", "Windows"]]),
    selectField("Linux 设备类型", "linuxDeviceType", node.linuxDeviceType || (node.role === "relay" ? "server" : "auto"), [["auto", "自动检测桌面"], ["desktop", "桌面设备（安装 GUI）"], ["server", "服务器（仅命令行）"]]),
    field("虚拟 IP", "overlayIP", node.overlayIP, "text", "10.144.144.2"),
    field("公网地址 / SSH 主机", "host", node.host, "text", "relay.example.com"),
    field("SSH 端口", "sshPort", node.sshPort || 22, "number"),
    field("SSH 用户", "sshUser", node.sshUser || "root", "text"),
    selectField("SSH 登录方式", "sshAuth", node.sshAuth || "key", [["key", "私钥文件"], ["password", "密码"]]),
    field("私钥文件路径", "sshPrivateKey", node.sshPrivateKey, "text", "~/.ssh/id_ed25519"),
    field("SSH 密码（本地保存）", "sshPassword", node.sshPassword, "password"),
    field("已信任主机指纹", "hostKeyFingerprint", node.hostKeyFingerprint, "text", "自动首次记录"),
    ...(includeRole ? [field("角色", "role", node.role, "hidden")] : []),
  ].join("");
}
function render() {
  ["name", "releaseVersion", "networkName", "networkSecret", "githubProxy", "scriptBaseURL", "wireGuardPort", "wireGuardCIDR"].forEach(key => form.elements[key].value = project[key] || "");
  form.elements.wireGuardEnabled.checked = Boolean(project.wireGuardEnabled);
  $("#relay-fields").innerHTML = nodeFields(project.relay, true);
  const container = $("#nodes"); container.innerHTML = "";
  project.nodes.forEach(node => {
    const card = $("#node-template").content.firstElementChild.cloneNode(true);
    card.dataset.id = node.id; card.querySelector(".node-title").textContent = node.name || "未命名节点";
    card.querySelector(".node-fields").innerHTML = nodeFields(node);
    card.querySelector(".remove-node").addEventListener("click", () => { project.nodes = project.nodes.filter(item => item.id !== node.id); render(); });
    card.querySelector("[data-key=name]").addEventListener("input", event => card.querySelector(".node-title").textContent = event.target.value || "未命名节点");
    container.append(card);
  });
  renderDeployments();
}
function readFields(container, base) {
  const next = { ...base };
  container.querySelectorAll("[data-key]").forEach(element => { next[element.dataset.key] = element.value.trim(); });
  next.sshPort = Number(next.sshPort || 22); return next;
}
function collectProject() {
  const next = { ...project };
  ["name", "releaseVersion", "networkName", "networkSecret", "githubProxy", "scriptBaseURL", "wireGuardPort", "wireGuardCIDR"].forEach(key => next[key] = form.elements[key].value.trim());
  next.wireGuardEnabled = form.elements.wireGuardEnabled.checked;
  next.wireGuardPort = Number(next.wireGuardPort || 11013);
  next.relay = readFields($("#relay-fields"), project.relay);
  next.nodes = [...$("#nodes").children].map(card => readFields(card.querySelector(".node-fields"), project.nodes.find(node => node.id === card.dataset.id)));
  return next;
}
function showOutput(title, message, text, qr = "") {
  $("#dialog-title").textContent = title; $("#dialog-message").textContent = message; output.textContent = text; qrCode.hidden = !qr; qrCode.src = qr || ""; dialog.showModal();
}
function button(label, action, className = "") { const item = document.createElement("button"); item.textContent = label; item.className = className; item.addEventListener("click", action); return item; }
function renderDeployments() {
  const nodes = [project.relay, ...project.nodes]; const list = $("#deployment-list"); list.innerHTML = "";
  list.append(button("顺序探针：POST/PONG + iperf3", runProbes, "primary"));
  nodes.forEach(node => {
    const row = document.createElement("div"); row.className = "deployment-row";
    const meta = document.createElement("div"); meta.className = "deploy-meta"; meta.innerHTML = `<strong>${escapeHtml(node.name || "未命名节点")}</strong><small>${escapeHtml(node.os)} · ${escapeHtml(node.overlayIP || "未分配 IP")} · ${escapeHtml(node.host || "未填写主机")}</small>`;
    const actions = document.createElement("div"); actions.className = "deploy-buttons";
    if (node.os === "linux") actions.append(button("SSH 部署", () => deploy(node), "ssh"));
    actions.append(button(node.os === "windows" ? "生成 PS1 与二维码" : "生成安装链接", () => installLink(node)));
    actions.append(button("查看脚本", () => viewScript(node)));
    row.append(meta, actions); list.append(row);
  });
}
async function viewScript(node) { try { const result = await api(`/api/nodes/${node.id}/script`, { method: "POST" }); showOutput(`${node.name} 的专属脚本`, "脚本尚未执行；确认内容后可复制或生成短期链接。", result.script); } catch (error) { showOutput("无法生成脚本", error.message, ""); } }
async function installLink(node) { try { const result = await api(`/api/nodes/${node.id}/install-link`, { method: "POST" }); showOutput(`${node.name} 的安装入口`, "链接仅能使用一次，60 分钟后失效。二维码包含同一条命令。", result.command, result.qrDataURL); } catch (error) { showOutput("无法生成安装入口", error.message, ""); } }
async function deploy(node) { try { showOutput(`正在部署 ${node.name}`, "SSH 连接与安装可能需要数分钟。", "正在执行…"); const result = await api(`/api/nodes/${node.id}/deploy`, { method: "POST" }); showOutput(`${node.name} 部署完成`, result.fingerprint ? `首次连接已记录主机指纹：${result.fingerprint}` : "SSH 安装完成。", result.output); } catch (error) { showOutput("SSH 部署失败", error.message, ""); } }
async function runProbes() { try { showOutput("正在顺序探测", "逐台启动临时探针、POST/PONG 并运行 iperf3。", "正在执行…"); const result = await api("/api/probes", { method: "POST" }); showOutput("顺序探测结果", "每台机器按配置顺序完成后才会开始下一台。", JSON.stringify(result, null, 2)); } catch (error) { showOutput("顺序探测失败", error.message, ""); } }

$("#add-node").addEventListener("click", () => { project.nodes.push(emptyNode()); render(); });
form.addEventListener("submit", async event => { event.preventDefault(); try { project = await api("/api/project", { method: "PUT", body: JSON.stringify(collectProject()) }); $("#status").textContent = "已保存到本机；现在可执行部署。"; render(); } catch (error) { showOutput("保存失败", error.message, ""); } });
$("#close-dialog").addEventListener("click", () => dialog.close());
$("#copy-output").addEventListener("click", async () => { await navigator.clipboard.writeText(output.textContent); $("#copy-output").textContent = "已复制"; setTimeout(() => $("#copy-output").textContent = "复制全部", 1200); });

(async () => { try { project = await api("/api/project"); if (!project.relay?.id) project.relay = emptyNode("relay"); project.nodes ||= []; render(); $("#status").textContent = "本地控制器已就绪。"; } catch (error) { $("#status").textContent = error.message; } })();
