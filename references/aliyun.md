# 阿里云：域名、DNS、备案与 OPC

## 先选实际能力

- 域名、云解析 DNS、ICP备案：优先使用已配置的官方 `aliyun-domain` MCP。先按本次任务发现对应工具；账号授权不等于每项 API 均有权限。
- 其他云产品：已登记主机内的操作继续走 yun 的固定身份 SSH 路径；阿里云账号级 ECS、存储等 API 需要该账号实际提供并授权的 OpenAPI MCP Core 或相应产品 MCP。不要从域名 MCP 的成功推断这些接口已接入。Core 端点由阿里云针对账号提供，不得猜测或扫描。
- OPC：先判断用户是否已有资源。只做 DNS/现有机器接入时不要选购套餐或创建服务器。若用户明确要求选型/开通，参考阿里云官方 advisor/deploy 最新版本，核对当前账号的实时价格、规格、地域和计费周期；只有用户明确确认具体费用和资源后才能购买。不得把使用 yun 或开始部署等同于付款许可。

## 已配置的域名 MCP

域名 MCP 地址从用户本机官方配置获取，不把账号专用端点放入 Skill 或仓库。通过实际注册的 MCP 名称使用；新注册的 MCP 可能需要重启 Codex 才会出现在工具列表。

Windows 控制端使用 `scripts/yun_aliyun_mcp.cjs` 包装官方 `mcp-remote-alibaba-cloud` 代理；此包装确保代理启动的后台进程隐藏窗口，但允许用户可见的浏览器授权页面。代理位于用户目录 `~/.config/yun/aliyun-mcp`，当前固定版本为 0.1.40，安装时禁用生命周期脚本并保留 npm 锁文件；不要静默升级。首次授权由用户在阿里云官方浏览器页面完成。认证成功、工具列表可用和具体 API 权限分别验证。

OAuth 缓存由代理保存在 `~/.config/yun/aliyun-domain-oauth`，属于明文敏感凭据，必须在 Skill 和项目以外；Windows 应只允许当前用户访问，Linux 应使用用户专有目录和权限。不要读取、打印、复制或上传缓存、授权 URL、验证码或令牌；不要启用代理调试日志。缺少授权或授权失效时让用户在官方页面重新授权，不要更换账号或尝试凭据兜底。

当前会话尚未加载新注册 MCP 时，使用以下**只读**适配器，必要时给每次调用 45 秒的有限期限：

```text
node <yun>/scripts/yun_aliyun.cjs dns-list <zone> [page]
node <yun>/scripts/yun_aliyun.cjs icp-status <domain> [page]
```

Windows 调用仍须从 node_repl 以 `windowsHide: true` 启动并捕获输出。先在本机通过 YUN_ALIYUN_DOMAIN_MCP_ENDPOINT 指定已验证的官方域名服务地址；该地址不能包含令牌或授权信息。适配器只暴露两种只读查询，不显示 TXT 值、备案订单号或主体信息；`has_more` 为 true 时继续所需页面。它不是 DNS 写入工具。账号密钥不存在或无法调用时如实报告，不通过 GUI 接管用户电脑。

## DNS 和备案闭环

1. 确认用户提供的精确域名、当前权威 DNS 提供商、账号和实际用途。查询指定 zone 的现有记录；不能因为域名已购买或公网 NS 可见，就假设当前账号有写权限。不要读取或展示 TXT 验证值，除非该确切任务需要且有安全的处理方式。
2. 备案状态按实际查询返回值报告。`待提交订单`、已提交、审核中和审核通过是不同状态；购买域名、打开 DNS 页面、申请证书均不代表备案通过。必要的人脸、短信和控制台提交由用户自行完成，不索取密码、验证码或身份证件。
3. 有明确的 DNS 变更目标时，记录完整的旧值、类型、线路、TTL 与回滚方式，先调用相应 MCP 预览。严格遵守该工具的 plan-id 和用户确认协议；未获所需确认或前置审核/服务验收未完成时不写入。写请求不要自动重试；结果不确定先按记录 ID 或精确 zone 只读回查。
4. 写后分别验证控制面记录、公开 DNS、TLS、网站/API 及其他受影响的既有服务。仅记录保存成功不是全网生效；保留准确回滚记录。内地接入须核实备案及接入商要求，切换前还要符合项目主机发布和空间规则。

## 其他产品和 OPC 接入

对于阿里云 OpenAPI MCP Core，优先使用已登记的 `openapi-mcp-core`。若尚未登记，使用用户在官方控制台提供的确切 Streamable HTTP 端点，核验官方域名和目标账号，再按照用户授权完成 OAuth。不得将账号专有端点、令牌或授权 URL 提交到项目、Skill 或日志；不要复制、改变已有域名 MCP 的授权缓存。先用 Core 的 API 定义工具核对参数，并只读查询精确目标资源以验证实际权限；再处理用户明确要求的变更。ECS/OSS 的写权限不得根据单次只读成功推断。域名 MCP 不能替代未连接的 ECS/OSS API。

主机内的配置和发布依然遵守 yun 的机器身份固定、共享锁、受限资源预检、外部构建、独立验证及回滚规则；OPC 的新资源流程不能覆盖这些要求，也不能移动或中断既有负载。

官方资料：
- [域名 CLI 与 MCP](https://wanwang.aliyun.com/cli/index)
- [域名 MCP DNS 操作](https://raw.githubusercontent.com/aliyun/alibabacloud-aiops-skills/master/skills/doweb/domain/alibabacloud-domain/references/domain.md)
- [ICP备案查询](https://raw.githubusercontent.com/aliyun/alibabacloud-aiops-skills/master/skills/doweb/domain/alibabacloud-domain/references/icp.md)
- [OPC skill 指南](https://help.aliyun.com/zh/ecs/opc-skill-experience-guidebook)
- [OpenAPI MCP Core](https://help.aliyun.com/zh/openapi/user-guide/openapi-mcp-server-guide)
