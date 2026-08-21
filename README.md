# MeshForge（组队安装器）

> AI Infra Vol.1

本地管理员工具：为一组机器批量生成 EasyTier 组网安装脚本，支持 SSH 一键部署和节点连通性探测。

- UI / 管理 API 默认只监听 `127.0.0.1` 随机端口，是**纯本地工具**，没有登录鉴权。
- 仓库名 MeshForge；Go module 与二进制名 `team-installer`；UI 显示名「组队安装器」；配置目录 `easytier-team-installer`。

## 安全须知

- `state.json` 以 **0600** 权限明文保存：网络密钥、SSH 密码、SSH 私钥路径、探针 token。请只放在自己信任的机器上。
- 安装链接是一次性的（24 字节随机 token，1 小时过期，兑换即焚），但内容包含网络密钥，**通过 HTTP 传输会被中间人截获**；公网分发请务必配置 HTTPS 的 `-public-base`。
- 探针功能需要目标机可访问的安装入口：用 `-public-listen` 单独暴露，或自行在反向代理上只转发 `/install/` 与 `/agents/`。`-public-listen` 只服务这两个路径，管理 API 与 UI 永远留在本地 listener。

## 构建

```sh
./build.sh
```

产物在 `dist/`，每个平台目录自带 `agents/` 探针二进制与 Linux `start.sh`。需要 Go 1.26+。

## 运行

```sh
./team-installer -data-dir ./data
```

| flag | 默认 | 说明 |
|---|---|---|
| `-data-dir` | `$XDG_CONFIG_HOME/easytier-team-installer` | 状态文件目录（`state.json`） |
| `-listen` | `127.0.0.1:0` | 管理 UI/API 监听地址；**默认仅本机** |
| `-public-listen` | 关闭 | 仅对外提供 `/install/` 与 `/agents/` 的监听地址，如 `0.0.0.0:8443` |
| `-public-base` | 默认取本地地址 | 安装脚本公开基址，如 `https://installer.example.com` |
| `-agent-dir` | `<exe>/../agents` | 节点探针二进制目录 |

## 使用流程

1. 打开 UI，填 Relay（必须有公网地址的 Linux）与各成员节点（SSH 信息用于一键部署）。
2. 每台 Linux 节点可「部署」（走 SSH）；Windows 节点或不便 SSH 的机器用「安装入口」生成 `curl … \| sudo bash` 命令或二维码。
3. 「顺序探测」逐台在远端拉起临时 node-agent + iperf3（占 19090 端口），测延迟与带宽后自动清理；需要 `-public-base` 目标机可达。

## 测试

```sh
go vet ./...
go test ./... -race
```

CI（GitHub Actions）同样跑 vet 与 `-race`。
