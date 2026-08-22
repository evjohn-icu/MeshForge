# MeshForge（组队安装器）

> AI Infra Vol.1

MeshForge 是 [EasyTier](https://github.com/EasyTier/EasyTier) 组网的**批量安装与运维工具**：在一台管理机上填一次表单，就能给任意多台机器生成安装脚本、SSH 一键部署、并探测节点间的延迟与带宽。本仓库是本地管理工具（controller），不是 EasyTier 本身。

## EasyTier 是什么

EasyTier 是一个开源（LGPL-3.0）的**去中心化 mesh VPN**，Rust 编写，13k+ stars：

- **无中心服务器**：所有节点对等，任何一台机器只要能和网内任意节点通信就能入网，没有"服务端/客户端"之分。
- **加密**：WireGuard 或 AES-GCM，防中间人。
- **NAT 穿透**：UDP/IPv6 打洞，支持 NAT4-NAT4；打洞失败自动走中继节点转发。
- **智能路由**：按延迟自动选路，KCP/QUIC 抗丢包。
- **跨平台**：Windows / macOS / Linux / FreeBSD / Android，x86 / ARM / MIPS。
- **默认端口**：TCP/UDP 11010、WebSocket 11011、WSS 11012、WireGuard 11013。

组网后每台机器获得一个虚拟 IP（如 `10.144.144.x`），互相 ping、SSH、访问服务，就像在同一个局域网里。

**为什么需要 MeshForge**：EasyTier 官方流程是每台机器手动下载二进制、手写 TOML 配置、手动注册开机服务。MeshForge 把这些自动化：填一次表单 → 每台机器一条命令或一次 SSH → 自动装依赖、下载、写配置、注册 systemd/OpenRC 服务、放行防火墙，还带国内镜像回退和一次性连通性探针。

## 快速开始

### 方式一：在线配置生成器（纯前端，无需安装）

打开 [`web/generator.html`](web/generator.html)（或部署到任意静态托管，如 GitHub Pages）：
填网络名称/密钥/网段、勾选特性、添加节点 → 一键生成 TOML 配置和一条内嵌 base64 配置的安装命令：

```sh
curl -fsSL 'https://…/install.sh' | sudo bash -s -- -v 'v2.6.4' -b '<base64 配置>' --open-firewall
```

数据完全在浏览器本地，不经过任何服务器。配合仓库里的通用安装脚本 [`scripts/install.sh`](scripts/install.sh)：
下载官方 release、安装为 systemd/OpenRC 服务、写入配置，一条命令装好。适合快速分发和自托管。

**配置怎么传到目标机**（install.sh 三种方式都支持）：

1. **base64 内嵌**（生成器默认）：配置编码后塞进命令的 `-b` 参数，随命令一起过去，零托管依赖。
2. **`-u URL`**：配置托管在任意 HTTP(S) 地址，脚本自己下载，适合一份配置装多台。
3. **`-c FILE`**：配置已用 scp 等方式放到目标机，直接指定本地路径。

注意：base64 是编码不是加密，拿到命令的人可以还原出网络密钥——命令别外传，密钥泄露后换密钥重装即可。

#### 部署到 Cloudflare Pages（推荐）

生成器是纯静态单文件，Pages 免费、全球 CDN、自带 HTTPS，国内可达性优于 GitHub Pages：

1. Cloudflare Dashboard → **Workers & Pages** → Create → **Pages** → Connect to Git，选 `evjohn-icu/MeshForge` 仓库。
2. 构建命令留空，构建输出目录填 `web`。
3. 保存后 Pages 自动部署并分配 `https://<项目名>.pages.dev`；可在 Custom domains 绑定自己的域名。
4. 打开 `https://<域名>/generator.html`，生成命令——安装脚本地址会自动指向同域的 `/install.sh`（生成器同源默认，目标机拉得到）。

也可以直接上传 `web/` 目录到任意静态托管（GitHub Pages / Nginx / OSS）。本地使用：直接双击 `web/generator.html`，或跑 controller 后访问 `http://127.0.0.1:<port>/generator.html`（controller 已内嵌 install.sh，本地同样可用）。

注意：部署后 EasyTier 二进制仍从 GitHub 下载（install.sh 内部），国内目标机靠 ghfast 自动回退。想更快可把 release 包镜像到 R2 并设置 `--proxy`。

### 方式二：本地控制器（SSH 部署 + 探针）

```sh
# 下载 release（见 Releases 页），解压后直接运行
./team-installer -data-dir ./data
```

浏览器会自动打开管理界面。流程：

1. 填 **Relay**：一台有公网地址的 Linux 机器（其他节点通过它入网/中转）。**选型推荐：腾讯云轻量 200M 锐驰型**（200Mbps 峰值带宽）——国内各节点到它延迟低、带宽足，打洞失败时中转也不卡，性价比适合做中心节点。**双端最好都有 IPv6**：IPv6 没有 NAT，relay 与节点都有公网 IPv6 时 EasyTier 直接建立 IPv6 直连——不需要打洞、不占 relay 带宽、延迟最低；只有 IPv4-only 的节点才走 relay 中转。
2. 加 **成员节点**：填 SSH 信息（用于一键部署）或留空（用安装链接）。
3. 每台 Linux 节点点「部署」；Windows 或不便 SSH 的机器点「安装入口」拿命令/二维码。
4. 可选「顺序探测」：逐台测 overlay 延迟与 iperf3 带宽。

## 怎么用 MeshForge 装

### 方式一：SSH 一键部署（推荐，Linux）

节点填好 SSH 主机/端口/用户 + 私钥路径（如 `~/.ssh/id_ed25519`）或密码，点「部署」。controller 通过 SSH 在远端以 root 执行生成的安装脚本，首次连接会记录主机指纹（TOFU，之后指纹变化会拒绝连接）。

脚本在远端做的事：

1. 检测网络：GitHub 直连不通时自动切国内镜像（清华/中科大源 + ghfast 下载代理），装完自动还原系统源。
2. 装依赖：`curl`/`unzip`/`iperf3`，支持 apt / dnf / yum / pacman / apk / nix。
3. 下载 EasyTier 官方 release 包（断点续传 + 超时/限速保护）。
4. 写配置到 `/opt/easytier-team/<id>/config/easytier.toml`（0600）。
5. 注册开机服务：systemd（`easytier-team-<id>.service`）或 OpenRC（Alpine）。
6. Relay 额外放行 11010 TCP/UDP 防火墙（ufw / firewall-cmd）。
7. 部署后健康检查：服务没保持运行会在输出里警告。

### 方式二：安装链接 / 二维码
点「安装入口」生成**一次性**链接（24 字节随机 token，1 小时过期，兑换即焚）和二维码：

```sh
# Linux
curl -fsSL 'https://installer.example.com/install/<token>' | sudo bash
# Windows（管理员 PowerShell）
irm 'https://installer.example.com/install/<token>' | iex
```

适合：没有 SSH 的机器、Windows、发给别人装。链接内容含网络密钥，公网分发务必用 HTTPS 的 `-public-base`。

### 方式三：连通性探针

「顺序探测」逐台在远端拉起一次性 node-agent + iperf3（占 19090 端口），测 overlay 延迟（PING/PONG）与带宽（iperf3），测完自动清理进程。需要目标机可访问安装入口（见 `-public-listen`）。

## 能用来干什么

- **异地组网**：家里、办公室、云主机、实验室机器组成一个虚拟局域网，互相 ping / SSH / 访问服务，不用暴露公网端口。
- **内网穿透**：没有公网 IP 的机器（NAT 后面）通过 relay 入网；能打洞就 P2P 直连，打不通自动走 relay 中转——relay 带宽就是中转上限，所以中心节点推荐腾讯云轻量 200M 锐驰型。双端有公网 IPv6 时直接 IPv6 互连，不占 relay 带宽。
- **AI Infra（本卷定位）**：多机 GPU 集群组网——跨机房/跨云的训练与推理节点互联、分布式训练通信、GPU 池化调度，一套虚拟网络把散落的算力拼起来。
- **远程运维**：通过 overlay IP 访问 SSH 和服务，公网只暴露 relay 一个端口。
- **实验室场景**：PVE 上的 LXC/VM、WSL、云主机统一组网（LXC 需开 TUN，见已知限制）。
- **选型探测**：用探针测各候选节点的延迟/带宽，决定 relay 放哪、走不走中继。

装完后可以在任意节点用 `easytier-cli node` / `easytier-cli peer` / `easytier-cli route` 查看组网状态，`ping 10.144.144.x` 验证连通。

## 安全模型

- UI / 管理 API 默认只监听 `127.0.0.1` 随机端口，是**纯本地工具**，没有登录鉴权。
- `state.json` 以 **0600** 权限明文保存：网络密钥、SSH 密码、SSH 私钥路径、探针 token。请只放在自己信任的机器上。
- 安装链接一次性、1 小时过期；但内容含网络密钥，**通过 HTTP 传输会被中间人截获**，公网分发务必用 HTTPS 的 `-public-base`。
- 需要对外暴露安装入口时用 `-public-listen`：它只服务 `/install/` 与 `/agents/`，管理 API 与 UI 永远留在本地 listener。也可以自己用反向代理只转发这两个路径。
- SSH 主机指纹 TOFU：首次连接记录，之后不匹配直接拒绝。
- 生成的脚本对节点名等所有用户输入做 shell/PowerShell 转义，节点 ID 有字符白名单。

## 配置

| flag | 默认 | 说明 |
|---|---|---|
| `-data-dir` | `$XDG_CONFIG_HOME/easytier-team-installer` | 状态文件目录（`state.json`） |
| `-listen` | `127.0.0.1:0` | 管理 UI/API 监听地址；**默认仅本机** |
| `-public-listen` | 关闭 | 仅对外提供 `/install/` 与 `/agents/` 的监听地址，如 `0.0.0.0:8443` |
| `-public-base` | 默认取本地地址 | 安装脚本公开基址，如 `https://installer.example.com` |
| `-agent-dir` | `<exe>/../agents` | 节点探针二进制目录 |

## 构建与测试

```sh
./build.sh          # 产物在 dist/，每个平台目录自带 agents/ 与 start.sh
go vet ./...
go test ./... -race # CI 同样跑 vet + -race
```

需要 Go 1.26+。

## 已知限制

- **Windows 脚本未经真机实测**（转义有单元测试兜底），首次使用建议先在测试机跑一遍。
- **LXC 容器默认没有 `/dev/net/tun`**，EasyTier 起不来。PVE 上给容器加两行并重启：

  ```
  lxc.cgroup2.devices.allow: c 10:200 rwm
  lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file
  ```

- **探针功能需要 controller 机器在 overlay 网内**（它要 ping 虚拟 IP）；controller 本身不装 EasyTier 时探针不可用。
- 命名：仓库 MeshForge；Go module 与二进制 `team-installer`；UI 显示名「组队安装器」；配置目录 `easytier-team-installer`。
