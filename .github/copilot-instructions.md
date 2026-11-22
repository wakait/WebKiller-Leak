# Copilot 项目说明

## 默认语言

- 默认使用中文回复、解释和编写面向用户的文档；用户明确要求其他语言时再切换。
- Go 标识符、命令行参数、协议字段和必要的代码注释按代码库既有约定保留原文。

## 项目结构

- 本项目是 Go 1.22 模块，只保留根目录 `main.go` 一个 CLI 入口。
- 根 CLI 调用 `internal/leak` 下的远程侦察实现；不要新增或恢复独立的本地仓库扫描入口。
- README 和 DESIGN 应同时覆盖根 CLI 参数、流水线和产物格式。

## 构建、测试与格式

- 全量测试：`go test ./...`
- 单个测试：`go test ./internal/leak -run '^TestNormalizeBase$' -count=1`
- CI 格式检查：`test -z "$(gofmt -l .)"`
- 格式化 Go 文件：`gofmt -w <文件...>`
- 当前 CI 交叉构建根目录 CLI，目标为 Linux amd64、macOS amd64/arm64、Windows amd64，并分别上传工作流产物。

## 代码库约定

- `go.mod` 目前只声明模块路径和 Go 版本；新增依赖前应先确认必要性。
- 保持根 CLI 与 `internal/leak` 的职责分离，不新增第二个可执行入口。
- 网络测试应限制在本地测试夹具中。不得加入认证绕过、凭据使用或会改变目标状态的请求；网络功能仅限明确授权的测试范围。
