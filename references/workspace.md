# 初始化文件夹

`yunctl.py init` 初始化的是控制端目标登记表。项目文件夹使用
`scripts/yun_workspace.py init`，两者不同。

当用户说“用 yun 初始化这里/这个文件夹”时，“这里”就是当前工作目录。先读该目录
现有说明及 `.yun-workspace.json`；只有当前项目没有明确的目标或远端根目录时，
才补问缺少的值。不要使用其他项目的路径。

## 适用边界

- 选择用户指定的、已登记的 Linux 目标；该目标须同时有 `server` 与 `compute` 角色。
- 远端根目录必须由用户或项目现有约定明确给出，不能从别的项目复制路径。初次使用先按 Skill 入口执行 `yunctl.py init`、`targets`、`probe TARGET`。
- 当前通用发布器只支持单个 Linux 开发/计算目标。跨主机数据复制、Windows 工作区、生产部署和专用运行环境由对应流程单独处理；生产目标的源码同步须先走 Server 分支的部署安全门槛。
- 初始化会创建远端 `data/`、`runs/`、`cache/`、`envs/`、`workspace/{incoming,releases,manifests}`，不会移动、覆盖或删除已有项目数据。

## 空文件夹

```text
python scripts/yun_workspace.py init LOCAL_PATH --target TARGET --remote-root /data/PROJECT --confirm-target TARGET
```

本机创建 `.yun-workspace.json`、`YUN_WORKSPACE.md`、`AGENTS.md` 和基础 `.gitignore`。
不猜测语言栈，也不生成空的 `src`、环境或训练模板。远端准备前会 probe；目标或
路径验证失败时不写本机文件。仅需先写本地配置时，可加 `--local-only`，之后
同命令不带该参数准备远端。`--dry-run` 只显示计划。

## 已有项目

先看现有 `AGENTS.md`、同步脚本、Git 忽略规则与大目录，再执行同一 `init` 命令。
脚本只新增缺失的工作区配置和说明；已有 `AGENTS.md`、`.gitignore`、源码和数据均
保留。若工作区配置或说明已存在且内容不同，脚本停止，需人工核对。已有项目的
专用同步或环境约束可能比通用工作流更准确；冲突时按用户当前指示和项目事实
调整，而不要机械替换。

已有数据迁移是单独的、有界工作：列出精确源目录和目标路径，估算体积与远端空间，
上传或在远端获取，核对 SHA-256、文件数和字节数后再报告。初始化本身绝不删除
本机副本，也不自动把整个项目目录作为数据上传。

## 日常开发与发布

```text
python scripts/yun_workspace.py sync LOCAL_PATH --confirm-target TARGET
python scripts/yun_workspace.py sync LOCAL_PATH --confirm-target TARGET --dry-run
```

Git 项目默认发布已跟踪文件的当前工作树内容；新文件先加入 Git 索引。非 Git
项目扫描目录。两者都排除常见私钥、`.env`、数据、权重和运行产物，并对单文件
20 MiB、总计 250 MiB 设上限。发布前用 `--dry-run` 审阅文件清单，项目另有
敏感文件时先在项目流程中显式排除。大于上限或需要特别文件清单的项目可保留
专用同步脚本。

成功发布返回不可变路径 `/data/PROJECT/workspace/releases/RELEASE_ID`；
`workspace/current` 只指向最近发布版本。提交远端计算时先固定实际 release
路径，在作业中显式选择远端环境、输入和结果目录。用 `yunctl.py submit`、
`status`、`logs`、`fetch` 管理完整生命周期。大产物应直接写入项目远端
`runs/`，而不是依赖 Yun 作业元数据目录的 `results/`。

## 开发效率

这个通用入口减少了每个项目重复写 SSH、SCP、目标选择和源码打包逻辑。项目仍
负责自己的依赖环境、数据契约与任务脚本；首次接入已有项目的主要工作是识别
现有路径和迁移大数据。日常改代码后只需发布一次，再让任务固定使用返回的版本。
