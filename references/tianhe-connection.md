# 天河 / aTrust 安全连接

此参考适用于用户已授权的天河登录节点。实际地址、端口、SSH 账号、指纹及所有凭据保存在用户本机，不随 Skill 分享。VPN 账号与 SSH 账号可能不同；以各自经核实的资料为准。

## 本机准备

1. 用户自行完成 aTrust 登录及必要的验证码；客户端进程存在不代表登录已生效。
2. 从可信管理员或已验证渠道取得登录节点地址、SSH 账号和 Ed25519 主机指纹。建立用户专有的 profile，放在项目和 Git 仓库之外；不要从聊天记录、此文示例或未验证来源猜测连接资料。
3. profile 必须显式提供 target、host、port、username、host_key_type、host_fingerprint、trust_source 和 trust_evidence。以下仅展示字段，示例指纹是故意无效的占位符；替换并完成独立确认后才可连接：

   {
     "target": "tianhe-ln5",
     "host": "hpc.example.invalid",
     "port": 22,
     "username": "your_hpc_account",
     "host_key_type": "ssh-ed25519",
     "host_fingerprint": "SHA256:REPLACE_WITH_VERIFIED_FINGERPRINT",
     "trust_source": "independent_fingerprint_confirmation",
     "trust_evidence": "Describe the actual independent confirmation locally"
   }

4. Python 依赖安装在用户专有环境。Windows 无人值守执行使用隐藏子进程，保留完整 host-key 校验，不弹出控制台窗口。

## 认证与只读检查

运行 scripts/yun_tianhe_password.py 并传入 --profile 指向个人 profile。该基础会话仅提供 preflight、queue、close 三项只读动作，不负责上传或提交计算。

用户明确允许时，可通过私有 stdin 送入账号和密码，或使用 scripts/yun_tianhe_vault.py 将本机账号的凭据保存为 Windows CurrentUser DPAPI 密文。DPAPI 文件按目标和账号隔离，绑定目标、地址、端口、账号与主机指纹。密码不放在命令参数、环境变量、文档、日志或 Git；DPAPI 密文和 profile 也不随 Skill 分享。公开版使用的密文文件名和绑定可能与个人定制版不同，升级后不要复制或覆盖旧密文，按用户授权重新登记。

DPAPI 模式只在新建 SSH 连接通过 pin 校验后解密并尝试一次密码认证。私有 stdin / 用户手动输入模式先验证 pin，等待凭据后新建连接并再次验证 pin。指纹变化、凭据缺失、认证拒绝或认证结果未知时停止；不自动换旧密码，不绕过校验。多个本机观察器以认证互斥避免同时登录；AuthenticationBusy 表示未发送密码的本机互斥竞争，不是密码错误。

## 作业与监控

先只读核实远端主机、账号、配额和共享队列。计算通过调度器在计算节点执行；记录 JobID、工作目录、源码版本和原预算。若使用 PEM 登记的登录节点，可使用 yun_tianhe.py 的 submit-site，要求固定脚本 SHA256、明确目标和新的提交回执；密码基础会话没有提交功能，项目若需要密码路线提交，应使用经审查、有一次性回执与远端重查的项目控制器，不把密码插入命令。

排队和运行分开记录。登录中断或监控失联时，先按 JobID 和工作目录查真实状态；不因本机断连重复提交或取消计算。只有用户授权的固定只读观察器可以在原截止内恢复，不能利用观察恢复权限重启科学作业。

## 不上传的内容

密码、访问令牌、密钥、DPAPI 密文、实际 profile、主机指纹、私有地址、用户信息、私人通信和已有作业的项目路径都留在本机私有位置。分享 GitHub 时只提交脱敏的源码、模板和合成测试数据。
