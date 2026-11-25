# 链路观测

Docker 管理端和独立 Linux 探针。探针默认每分钟并行进行 TCPing 与 ICMP。管理端按节点地区和运营商显示结果，并比较大陆和境外探针对同一目标的可达性。

## 部署管理端

将本仓库的 compose.yaml 和 .env.example 放到管理主机。复制 .env.example 为 .env，填写管理员密码和节点可访问的 HTTPS 地址。将 HTTPS 反向代理指向本机 127.0.0.1:8080。

| 环境变量 | 用途 |
| --- | --- |
| ADMIN_PASSWORD | 首次登录的管理员密码，Compose 启动时仍需填写 |
| PUBLIC_URL | 探针访问的 HTTPS 源地址，例如 https://monitor.example.com |
| MANAGER_IMAGE | 管理端镜像，默认使用 ghcr.io/zikq-shmily/link-observatory:latest |
| MANAGER_PORT | 管理端发布到宿主机的端口，默认 8080 |
| RELEASE_URL | `latest`（默认）使用 GitHub 最新稳定版，也可填写固定版本的 Release 下载前缀 |
| INSTALL_SHA256 | 固定版本用于本地菜单更新的 install.sh 校验值，在该版本的 SHA256SUMS 中查看 |

首次部署和后续升级均可使用以下命令。数据存储在 monitor-data 持久卷的单实例 JSON 快照中。

~~~sh
docker compose pull manager
docker compose up -d --no-build
~~~

离线部署可从 GitHub Releases 下载本机架构的 Docker 镜像归档，按 SHA256SUMS 验证后用 docker load 导入，再把 MANAGER_IMAGE 设置为 link-observatory:<版本标签>。

登录后，从页面顶部的「修改密码」输入当前密码，并确认新密码。保存成功后，所有管理员会话会退出，需要用新密码重新登录。新密码的哈希保存在 `monitor-data` 卷中，容器重启或升级后继续使用新密码。网页改密后，编辑 `.env` 中的 `ADMIN_PASSWORD` 无法重置该密码。

## 邮件提醒

在管理端顶部打开「邮件提醒」，填写 SMTP 主机、端口、发件地址和收件地址。可选 TLS（常用 465）或 STARTTLS（常用 587）。需要身份验证时，填写 SMTP 用户名及密码或授权码。先点击「发送测试邮件」验证配置，再启用并保存所需的通知。已保存的 SMTP 密码留空即保留，密码保存在管理端的数据卷中。

探针超过 3 分钟未发送心跳时触发离线通知，再次上报心跳时触发恢复通知。TCPing 和 ICMP 分别检测，大陆至少两个运营商连续三轮对同一 IP 超时且境外同期成功时触发异常。原受影响的运营商连续两轮恢复且境外仍可达时触发对应协议的恢复。缺失结果、DNS 失败和探测不可用不计为超时。

「监测目标」和「探针节点」列表可拖动行首手柄排序。管理端保存顺序，网页刷新或重新登录后继续使用。

## 部署探针

1. 在管理端的「探针节点」添加节点，填写地区、运营商和观测分组。
2. 在「安装并注册」复制命令到探针 Linux 主机执行。命令按行展示参数，通过 `curl … | bash -s --` 运行 GitHub `main` 分支上的 `install.sh`，它会在执行时下载最新稳定发行版的安装文件。安装器再下载并校验对应架构的探针二进制。若配置固定版本，命令会直接使用该版本。一次性注册令牌有效期为 15 分钟。
   GitHub 下载受限时，勾选「使用 gh-proxy」并输入自定义 HTTPS 地址，例如 `https://gh-proxy.example.com` 或带路径的 `https://gh-proxy.example.com/cache`，再点击「生成命令」。下载时会在 GitHub 文件链接前加上这个前缀。脚本和二进制均采用该地址。探针仍直接连接管理端注册和上报。
3. 添加监测目标，填写 IPv4、IPv6 或完整域名，以及已知开放的 TCP 端口。比较大陆和境外的可达性需要至少两个不同运营商的大陆节点和一个境外节点。

域名目标需要 v0.1.2 或更新的探针。各节点每轮从本机解析 DNS，优先选择 IPv4，TCPing 和 ICMP 使用同一个地址。目标详情显示每个节点的解析 IP 或 DNS 错误。判定使用同一轮、同一目标 IP 和端口的结果。

目标详情展示最近 12 个已结束轮次，可查看每轮大陆和境外的 TCPing、ICMP 可达节点数与有效节点数。旧轮次可用保留的同轮原始样本补齐明细。

大陆至少两个不同运营商 TCPing 超时、同一探针的 ICMP 有回包，且境外 TCPing 成功时，连续三轮标记为「疑似 TCP 阻断」。若大陆两个运营商的 TCPing 和 ICMP 都超时，且境外两个协议都成功，连续三轮标记为「TCP 与 ICMP 均超时」。同一运营商在该轮有对应协议的成功结果时，不计入该协议的超时证据。已触发的事件在原受影响运营商及境外探针连续两轮测到相应协议恢复后关闭。

探针运行时使用单个静态二进制。root 安装后可执行 `/opt/link-observatory/install.sh`，程序和数据在 `/opt/link-observatory/nodes/<节点 ID>/`。普通账号的探针和脚本位于 `~/.local/share/link-monitor/nodes/<节点 ID>/`。后续操作使用安装时的账号。脚本使用主机已有的 Bash、wget、sha256sum 和 flock。ICMP 优先使用 Linux 普通 Echo 套接字。若进程已有 `CAP_NET_RAW`，可回退到原始套接字。两种方式均不可用时，节点的 ICMP 栏显示「不可用」，TCPing 继续运行。

在「探针节点 → 探测设置」可把所有节点的探测间隔设为 1 至 10 分钟。已升级到 v0.1.1 的探针自动读取并应用设置。v0.1.0 节点仍按每分钟探测，管理端仅采纳与当前间隔对齐的结果。

探针列表将上报版本与 GitHub 的最新稳定发行版比较。版本一致时显示 `latest`，鼠标悬停可查看实际版本号。

本地 `install.sh` 菜单提供启动 / 重启、更新 / 重装、卸载、当前运行状态及设置 GitHub 下载方式。选择「当前运行状态」或执行 `./install.sh --status` 即可查看进程、版本、管理端及下载方式。多个节点时用 `--node <节点 ID>` 指定。

更新时，脚本向管理端读取版本与 SHA-256，再按本地保存的下载方式从 GitHub 获取新版脚本和二进制。可从菜单更改或清除 gh-proxy。新版探针二进制与本地 `install.sh` 一起更新，并保留原有注册信息。gh-proxy 及新菜单需要 v0.1.10 或更新的安装脚本。旧节点可通过管理端的「更新命令」换用新版脚本。旧版 root 节点更新时会迁移到 `/opt/link-observatory`。

执行本地 `./install.sh uninstall` 会停止探针并离线删除该实例。root 主机有多个节点时，用 `/opt/link-observatory/install.sh --node <节点 ID> uninstall` 指定要卸载的节点。共享脚本和目录在卸载后仍可保留。管理端的「移除节点」用于吊销凭证。

## 路由追踪

在目标详情的「路由追踪」中启用定时追踪，可选择 5、15、30 或 60 分钟。现有探针升级后可以执行去程。在自己管理的目标主机执行「部署回程端」生成的独立 GitHub 安装命令，可从该主机追踪到各探针的公网出口。探针分别通过 ipify 获取 IPv4 和 IPv6 出口地址。家宽使用运营商 NAT 时，回程以观测到的公网地址为终点，可能只能观测到运营商网络。

安装和升级时优先复用本机支持 JSON 输出的 NextTrace，否则将 NextTrace Tiny 下载到实例目录。使用 gh-proxy 时，两个项目的 GitHub 下载均经该代理。NextTrace 的地理位置、ASN 和线路标签取决于上游数据，可用性随网络环境而异。路由失败时，原有 TCPing 和 ICMP 探测继续运行。

去程和回程按探针、地址族及实际目标 IP 分别比较。连续两轮确认同一跳点变化后写入「变化记录」。打开「邮件提醒」并勾选「路由变化」可接收含变化跳点的邮件。出口 IP 变化会单独记录，回程重新建立对比基线。

## GitHub 构建

推送分支触发 CI。推送 v0.1.1 这类版本标签触发 Release，生成 amd64 和 arm64 的 Linux 探针、管理端二进制、可导入的 Docker 镜像归档及校验清单。发行版内的 install.sh 由工作流注入探针二进制摘要，安装命令使用该发行版脚本。GHCR 发布对应版本和最新稳定版的 latest 标签。

本地开发使用 Go 1.26 或更新版本。管理端测试可运行 go test ./...，本地监听使用 ADDR=127.0.0.1:8080、PUBLIC_URL=http://localhost:8080，并设置 ADMIN_PASSWORD。
