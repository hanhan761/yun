# 云（`/yun`）

一个可移交给其他 Codex 智能体使用的 Linux / Windows SSH 控制 Skill：每台主机一个自描述 RSA-4096 PEM。换控制电脑时只携带 Skill 和 PEM，即可重建安全连接。支持两种系统的日常运维和文件传输，以及 Linux 上的持久计算任务。

Windows 接入见 [references/windows.md](references/windows.md)。登记时加
`--platform windows --role server`，此后 `probe` 自动使用 PowerShell；
`exec` 运行原生程序，`exec-script` 执行本地 UTF-8 `.ps1`，`upload` / `download`
通过 SFTP 处理 `C:/...` 路径。原有 Linux PEM 可继续使用，无需重新生成。
Windows 的 `tmux` 后台计算和远程桌面操作尚不支持。

![云 Skill：一台服务器一个 PEM 的完整流程](assets/yun-skill-flow.png)

## 两件套已经闭环

| 携带物 | 作用 |
| --- | --- |
| `yun` Skill | 固定的导入、SSH/SCP、服务器运维和持久计算流程 |
| `yun_TARGET.pem` | RSA 私钥，以及一行经过验证的公开连接资料 |

不需要携带原电脑的注册表、`known_hosts`、`.pub`、SSH config、SSH agent、MCP 或云厂商 SDK。`import-pem` 会从 PEM 重建注册表和严格 host-key cache；服务器端必须已经安装对应公钥，控制端仍需 Python 3、OpenSSH 和到服务器的网络可达性。

## 换一台电脑

安装 Skill，把 PEM 放在安全位置，然后执行：

```bash
python scripts/yunctl.py import-pem /absolute/path/yun_workstation.pem
python scripts/yunctl.py probe workstation
```

导入会完成以下检查：

- 收紧 PEM 的本机文件权限；
- 从私钥推导公钥并核对内嵌 client fingerprint；
- 核对目标名称、主机、端口、用户和角色；
- 核对内嵌 ED25519 host key 及其 SHA256 fingerprint；
- 自动生成外部注册表和专用 `known_hosts` cache。

导入后即可按目标名操作：

```bash
python scripts/yunctl.py exec workstation --read-only -- hostname
python scripts/yunctl.py submit workstation ./job.sh --name experiment --confirm-target workstation
```

## 第一次接入新服务器

先生成该服务器唯一的身份：

```bash
python scripts/yunctl.py keygen my-server
```

它会生成 `yun_my-server.pem` 和仅用于首次安装的 `yun_my-server.pem.pub`。通过可信控制台把 `.pub` 安装进服务器账户的 `authorized_keys`，独立核对服务器 ED25519 host key，然后登记并探测：

```bash
python scripts/yunctl.py register my-server \
  --host 203.0.113.10 \
  --port 22 \
  --user deploy \
  --pem /absolute/path/yun_my-server.pem \
  --known-hosts /absolute/path/yun_my-server.known_hosts \
  --host-fingerprint SHA256:VERIFIED_FINGERPRINT \
  --role server \
  --description "authorized server"

python scripts/yunctl.py probe my-server
python scripts/yunctl.py bundle-pem my-server
```

`bundle-pem` 先在同目录创建受限临时候选，确认 OpenSSH 解析出的 client fingerprint 完全不变，再原子替换原 PEM。不会留下第二份持久私钥，也不会改变服务器上的公钥。此后只需要携带 Skill 和这个 PEM。

完整接入见 [references/onboarding.md](references/onboarding.md)，普通运维见 [references/servers.md](references/servers.md)，持久计算闭环见 [references/compute.md](references/compute.md)。

## 安全边界

- 自描述头只包含公开连接事实；RSA 私钥正文不会进入 Skill、注册表、日志或 Git。
- 所有 SSH/SCP 调用使用 `-F none`，关闭环境 agent 和口令回退，只允许该 PEM。
- 每次网络操作都使用严格 host-key checking；禁止 `accept-new` 和关闭检查。
- 生产目标写操作仍需显式目标确认；“提交成功”仍不等于“计算完成”。
- PEM 为无人值守用途的无口令高权限凭据。任何拿到 PEM 且能访问目标网络的人都可能控制服务器，绝不能提交 GitHub、发送聊天或上传普通网盘。

```bash
python -m unittest discover -s tests -v
python -m py_compile scripts/yunctl.py
```
