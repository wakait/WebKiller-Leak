# WebKiller-Leak

**WebKiller-Leak** 是一个面向已授权 CTF 靶场和安全自查资产的 Web 信息泄露侦察工具。它使用 Go 1.22 标准库实现，流程包括探活、Git 仓库还原、`.DS_Store` 枚举、历史与工作区扫描，以及可选的 gitleaks 联动。

> 本项目只发送只读的 HTTP GET/HEAD 请求，不绕过认证、不利用漏洞、不发送写操作，也不会使用发现的密码或令牌。只能用于明确授权的靶场、测试系统或自有资产。

## 核心能力

- 并发探测 `.git`、`.DS_Store`、SVN、Mercurial、Bazaar 和目录列表泄露。
- 从 HEAD、refs、reflog、index、packed-refs 和 pack 元数据还原 Git 内容。
- 遇到散装对象目录拒绝访问时，优先枚举已知 SHA，再提供目录列表兜底和暴力枚举选项。
- 发现 `.pack/.idx` 后下载并尝试使用本地 Git 自动解包；没有 Git 时保留 pack 与原始证据并降级扫描。
- 启发式解析 `.DS_Store` 名称，并对候选路径进行 HEAD 可达性探测。
- 扫描工作区、Loose Object、Git 元数据、提交历史、reflog、stash 和 lost-found 内容。
- 内置 Flag、AWS Access Key、GitHub Token、私钥及通用密钥赋值规则，并对敏感值进行脱敏。
- 未指定 Flag 正则时，自动检测并解码 hex、base64、ASCII 二进制和 Unicode 实体编码形式的 Flag。
- 支持外部 gitleaks，但未安装或执行失败时不会阻断主流程。

## 快速开始

### 构建

```sh
go test ./...
go build -o WebKiller-leak .
```

程序直接运行且不带参数时会打印完整中文用法、参数列表和授权提示，然后正常退出；也可使用 `-h` 或 `--help` 查看。项目没有第三方 Go 依赖。也可以使用和 GitHub Actions 命名规则一致的本地构建脚本：

```sh
# 构建当前主机平台，默认版本取当前标签或 dev-<短提交号>
./scripts/build.sh

# 本地交叉构建 CI 支持的 Linux amd64、macOS amd64/arm64、Windows amd64
./scripts/build.sh all

# 指定版本号；输出目录也可通过 OUT_DIR 环境变量覆盖
./scripts/build.sh all v1.2.3
OUT_DIR=release VERSION=v1.2.3 ./scripts/build.sh all
```

Windows 用户可在 Git Bash 或 WSL 中运行该脚本。脚本设置 `CGO_ENABLED=0`，并将相同版本号写入文件名和 `-h` 帮助信息。

### 远程侦察

```sh
./WebKiller-leak -u https://authorized.example/
```

常用示例：

```sh
# 自定义 Flag 格式、并发数和限速
./WebKiller-leak -u https://authorized.example/ -p 'ctf\{[^}]+\}' -t 32 -rate 20

# 目标给出 .git 基础地址
./WebKiller-leak -u https://authorized.example/.git/ -o evidence

# objects目录禁止目录列表时启用枚举
./WebKiller-leak -u https://authorized.example/ -bruteforce

# 联动本地 gitleaks
./WebKiller-leak -u https://authorized.example/ -gitleaks

# 只探活、枚举 DS_Store 和扫描已知产物，不执行 Git 还原
./WebKiller-leak -u https://authorized.example/ -no-git
```

## 命令行参数

| 参数 | 默认值 | 说明 |
|---|---:|---|
| `-u` | 必填 | 目标站点或 `.git` 基础 URL。 |
| `-p` | 空 | 自定义 Flag 正则，使用 RE2 语法；留空时自动扫描明文 `flag{...}` 及 hex、base64、ASCII 二进制和 Unicode 实体编码形式。 |
| `-o` | `out` | 命中报告、仓库和证据的输出目录。 |
| `-t` | `16` | 并发工作协程数，范围为 1–256。 |
| `-bruteforce` | `false` | 启用 denied object 目录枚举和已知 SHA 精确枚举。 |
| `-gitleaks` | `false` | 如果系统 PATH 中存在 gitleaks，则执行全历史扫描。 |
| `-no-git` | `false` | 跳过 Git 仓库还原和 Git 历史遍历。 |
| `-timeout` | `15s` | 每个 HTTP 请求或下载的超时。 |
| `-rate` | `20` | HTTP 请求速率（请求/秒）；设为 `0` 可关闭限速。 |
| `-v` | `false` | 输出详细请求、模块和警告信息。 |

## 输出结构

```text
out/
├── findings.txt              # 去重后的命中报告，包含脱敏后的敏感值
├── dsstore.txt               # DS_Store 名称、来源、状态和可达性
├── missing_objects.txt       # Git 还原失败或缺失的对象
├── dsstore/
│   └── raw/                  # 原始 DS_Store 证据
└── repo/
    ├── .git/                 # 重建的最小 Git 元数据和 pack
    └── ...                   # 能成功还原的工作区文件
```

## 退出码

| 码 | 含义 |
|---:|---|
| `0` | 流程正常完成，未命中或已产生报告均可。 |
| `1` | 参数错误或正则不合法。 |
| `2` | 目标没有返回可识别的 HTTP 响应。 |
| `3` | 内部错误、落盘失败或外部流程执行失败。 |

收到 SIGINT 或 SIGTERM 时，工具会取消正在进行的工作并保留已经落盘的产物。

## 安全与合规边界

- 仅使用 GET/HEAD，不尝试认证绕过或漏洞利用。
- 所有远端路径在落盘前进行清洗、跨平台文件名转换和根目录前缀校验。
- 输出中的 AWS、GitHub、私钥和通用密钥值会部分脱敏。
- 文件大小、对象数量、下载总量、并发数和请求超时均有上限。
- 工具不保证能绕过所有 WAF、CDN、目录权限或对象存储策略。

## 构建与测试

```sh
go test ./...
test -z "$(gofmt -l .)"
./scripts/build.sh all
```

CI 在 Linux、macOS amd64/arm64 和 Windows amd64 上交叉构建根 CLI，并执行全量测试和格式检查。

正式 Release 由以 `v` 开头的 Git 标签触发，例如 `v1.1.0`。产物文件名会包含版本号、操作系统和架构；二进制自身的 `-h` 版本信息也会使用同一版本号。分支和 PR 构建使用 `dev-<短 SHA>` 作为版本标识。

Release 页面使用中文发行说明，并附带全部平台产物及 `SHA256SUMS.txt` 校验文件。
