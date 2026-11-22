# WebKiller-Leak 中文发行说明

## 发布内容

本 Release 包含已通过测试、格式检查及多平台交叉构建的 WebKiller-Leak 单一命令行程序。

## 授权与合规

本工具仅用于：

- 明确授权的 CTF 靶场；
- 已获得书面授权的安全评估；
- 用户自己的资产或隔离测试环境。

工具只发送只读 HTTP GET/HEAD 请求，不执行漏洞利用、不绕过认证、不发送写操作，也不会使用发现的凭据。使用者应自行确保访问与数据处理符合适用法律和目标方规则。

## 核心能力

- 探测 `.git`、`.DS_Store`、SVN、Mercurial、Bazaar 和目录列表泄露。
- 还原 Git loose object、refs、reflog、index、commit、tree 和 blob。
- 已知 SHA 精确枚举优先，并在授权范围内提供受限目录列表兜底。
- 下载并尝试解包 `.pack/.idx`；无法使用 Git 时保留证据并降级扫描。
- 枚举 `.DS_Store` 文件名并进行只读可达性探测，不下载条目内容。
- 扫描工作区、历史提交、reflog、stash、lost-found 和 Loose Object。
- 内置 Flag、AWS AKIA、GitHub Token、私钥和通用密钥赋值规则。
- 未指定 Flag 正则时自动检测并解码 hex、base64、ASCII 二进制和 Unicode 实体编码的 Flag。
- 支持可选 gitleaks 联动；缺少外部工具时不会阻断主流程。

## 下载与校验

根据操作系统和架构选择对应产物。下载后请先校验 SHA256：

```sh
sha256sum -c SHA256SUMS.txt
```

Windows PowerShell 可使用：

```powershell
Get-FileHash .\WebKiller-leak-<版本>-windows-amd64.exe -Algorithm SHA256
```

## 快速使用

Linux 或 macOS：

```sh
chmod +x WebKiller-leak-<版本>-<系统>-<架构>
./WebKiller-leak-<版本>-<系统>-<架构> \
  -u https://authorized.example/ \
  -o out
```

Windows：

```powershell
.\WebKiller-leak-<版本>-windows-amd64.exe `
  -u https://authorized.example/ `
  -o out
```

常用参数：

- `-u`：目标基础 URL 或 `.git/` URL，必填。
- `-p`：自定义 Flag 正则；留空时自动扫描明文 `flag{...}` 及 hex、base64、ASCII 二进制和 Unicode 实体编码。
- `-o`：产物输出目录，默认为 `out`。
- `-t`：并发数，范围为 1–256，默认 16。
- `-rate`：请求速率（请求/秒），设为 `0` 可关闭限速。
- `-timeout`：每请求超时，默认 `15s`。
- `-bruteforce`：对象目录拒绝时启用受限枚举。
- `-gitleaks`：检测到 gitleaks 时执行全历史扫描。
- `-no-git`：跳过 Git 还原和 Git 历史遍历。
- `-v`：输出详细请求和模块日志。

## 产物说明

```text
out/
├── findings.txt              命中报告及脱敏结果
├── dsstore.txt               DS_Store 枚举和可达性
├── missing_objects.txt       未能获取的 Git 对象
├── dsstore/raw/              保留的原始 DS_Store 文件
└── repo/                     已还原的仓库与可用证据
```

## 退出码

- `0`：正常完成；未命中或已发现命中都属于正常结束。
- `1`：参数错误或正则不合法。
- `2`：目标没有返回可识别的 HTTP 响应。
- `3`：内部错误、落盘失败或执行过程异常。

收到中断信号时，工具会保留已经落盘的部分产物。

## 已知限制

- Git gc 后的场景可能依赖散装对象、目录权限或完整 pack。
- `.DS_Store` 为启发式解析，极端私有格式或特殊编码可能遗漏名称。
- SVN、Mercurial 和 Bazaar 当前主要提供探测能力，不承诺完整仓库还原。
- 正则命中不等同于业务层确认为有效 Flag，需要人工复核。

完整使用说明与架构设计请参阅仓库中的 `README.md` 和 `DESIGN.md`。
