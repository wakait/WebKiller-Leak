# WebKiller-Leak 架构设计

## 1. 范围

本项目提供只读、授权范围内的 Web 泄露侦察能力：

- 路径探活与内容指纹识别；
- 通过公开可访问的 Git 元数据和 loose object 重建仓库；
- `.DS_Store` 名称枚举；
- 工作区、对象、元数据及 Git 历史敏感信息扫描；
- 可选 gitleaks 联动。

工具不会发送 POST/PUT/DELETE，不执行认证绕过、不利用漏洞、不读取发现凭据对应的远程资源。

## 2. 模块划分

```text
main.go
  ├─ 参数解析、输出目录、信号处理、退出码
  └─ 四阶段流水线编排

internal/leak
  ├─ http.go       HTTP 客户端、重试、限速、统计
  ├─ probe.go      泄露路径探测与指纹
  ├─ git.go        Git 元数据、对象图、pack、暴力枚举与落盘
  ├─ dsstore.go    DS_Store 启发式解析和可达性探测
  ├─ scan.go       内置规则、历史扫描、报告、脱敏和去重
  └─ util.go       SHA-1、对象解析、路径安全、脱敏

scripts/build.sh
  └─ 本地单平台和 CI 矩阵跨平台构建

```

模块保持职责分离：能力模块不互相编排；所有网络访问通过 `leak.Client`；远端路径落盘统一经过安全路径校验。

## 3. 主流程

主 CLI 的执行顺序：

1. **探活**：并发检查已知泄露路径，以状态码和内容指纹确认结果。
2. **Git 还原**：发现 Git 泄露且未使用 `-no-git` 时执行。
3. **DS_Store 枚举**：发现确认的 `.DS_Store` 时下载并枚举名称。
4. **扫描**：扫描工作区、Loose Object、元数据、Git 历史和可选 gitleaks；写入 `findings.txt`。

任一步失败只记录警告或局部产物，不主动破坏已完成的前置步骤。

## 4. HTTP 基础设施

`Client` 使用共享的 `http.Transport` 和连接池：

- 支持并发上限、共享限速、指数退避和重试。
- 网络错误和 5xx最多重试两次，4xx 不重试。
- GET 有响应体上限，HEAD 只读取有限响应体。
- 自动跟随最多 10 次重定。
- TLS `InsecureSkipVerify` 仅用于已授权靶场常见自签证书。
- 保存请求数、重试数、错误数和下载字节数。

## 5. 泄露探测

探测器会检查：

- `.git/HEAD`、`.git/config`、refs、info/refs、logs、index、pack 元数据；
- `.DS_Store`；
- `.svn/entries`、`.svn/wc.db`；
- `.hg/hgrc`、`.bzr/README`；
- 站点根目录列表。

结果包含路径、类型、状态码、确认状态和说明。只有状态码和内容指纹同时满足要求才标记为确认泄露。

## 6. Git 还原

`Dumper` 的对象来源包括：

- HEAD 和 detached HEAD；
- 分支、标签和 packed-refs；
- HEAD reflog 与 refs reflog；
- stash、ORIG_HEAD、FETCH_HEAD 和变基相关元数据；
- index 中的路径与对象 SHA；
- graft、shallow 和 pack 素引。

BFS 对 commit、tree、blob、tag 对象图去重遍历。commit 和 tag 入队关联对象；tree 入队子对象；blob 按 index 路径落盘。

暴力枚举分为两层：

1. 先枚举已发现的 40 位 SHA 精确路径。
2. 再对 `objects/xx/` 做目录列表兜底；目录拒绝时保留警告并以已知对象为止，不盲目放大负载。

下载 pack 后优先使用本地 Git `unpack-objects` 解包；若 Git 不可用则保留 pack、idx 和原始证据，并写明人工补解包步骤。

资源限制包括最大对象数、最大单对象、最大 pack 和最大下载总量。

## 7. DS_Store 枚举

实现采用启发式而不是完整 Apple 私有格式解析：

- 识别 `Bud1/DSDB` 和 UTF-16BE 字符串；
- 从候选序列中过滤内部标记、纯数字和无效名称；
- 对根目录和常见目录递归下载最多若干层；
- 保留原始文件；
- 对候选条目发起 HEAD 可达性探测；
- 将重复条目去重并按目录排序。

该模块只枚举结构和名称，不下载 `.DS_Store` 声明的文件内容。

## 8. 扫描引擎

内置规则：

- 用户自定义 Flag 正则；未指定 `-p` 时默认扫描明文 `flag{...}` 以及 hex、base64、ASCII 二进制和 Unicode 实体编码形式，并将编码命中解码为明文后统一输出；
- `-----BEGIN ...PRIVATE KEY-----`；
- AWS `AKIA` Access Key ID；
- GitHub Personal/Platform/Refresh/User Token；
- 通用 password、secret、API key、token 赋值。

扫描顺序：

1. 工作区；
2. Git `log -p --all`；
3. reflog；
4. stash；
5. `git fsck --lost-found`；
6. Loose Object；
7. `.git` 元数据；
8. 可选 gitleaks；

没有 Git 时仍可扫描已落盘 Loose Object 和元数据。扫描结果按规则、值、路径、行号排序，并按规则加命中值去重。密钥类型值输出脱敏版本。

## 9. 路径安全

远端仓库路径会经过以下保护：

- 替换反斜杠；
- 拒绝绝对路径和 `..`；
- 拒绝 NUL、控制字符；
- 清洗 Windows 不兼容字符；
- 限制组件长度；
- 在写盘前使用根目录绝对路径和前缀校验；
- 重构树时拒绝穿越或非法组件。

## 10. 错误处理与降级

| 故障 | 降级行为 |
|---|---|
| 目标不可达 | 返回退出码 2。 |
| HEAD 403 | 尝试 reflog、refs、index 和已知元数据。 |
| object 目录拒绝 | 精确枚举已知 SHA；可选目录兜底。 |
| pack 场景 | 下载 pack/idx，尝试本地 Git 解包。 |
| 单对象 404 | 写入 missing_objects.txt，继续其他对象。 |
| 无 Git | 使用 Loose Object 和元数据扫描。 |
| 无 gitleaks | 静默跳过，保留内置规则。 |
| DS_Store 解析失败 | 保留原始文件并输出警告。 |
| 输出路径非法 | 返回落盘错误，不进行穿越写入。 |

## 11. 测试策略

- 单元测试：zlib、SHA-1、Git commit/tree/index/pack、路径安全、脱敏、正则和 DS_Store 字符串。
- 集成测试：本地 `httptest` 构造 Git 仓库、DS_Store 和拒绝目录响应。
- 历史回归：确认已删除提交、reflog、stash 和 dangling object 可被扫描。
- 端到端测试：参数校验、探活、部分失败、报告落盘和退出码。
- 格式与构建：`gofmt`、`go test ./...` 和多平台交叉构建。

## 12. 本地构建与发布

`scripts/build.sh` 与 GitHub Actions 使用相同的操作系统/架构矩阵和产物命名：

- `scripts/build.sh` 构建当前主机平台；
- `scripts/build.sh all` 构建 Linux amd64、macOS amd64/arm64、Windows amd64；
- 可通过位置参数或 `VERSION` 指定版本，通过 `OUT_DIR` 指定产物目录；
- 未指定版本时，优先使用当前 Git 标签，否则使用 `dev-<短提交号>`；
- 构建时使用 `CGO_ENABLED=0`，并将版本号写入二进制帮助信息。

正式发布由 `v*` Git 标签触发。工作流先执行测试，再构建全部平台产物，最后生成 SHA256 校验清单并发布中文 Release 说明。
