#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
用法：
  scripts/build.sh [host|all] [版本号]

模式：
  host  构建当前主机平台（默认）
  all   构建 CI 支持的 Linux、macOS 和 Windows 目标

版本号也可通过 VERSION 环境变量指定；未指定时优先使用当前 Git 标签，
否则使用 dev-<短提交号>。产物写入 dist/，可通过 OUT_DIR 覆盖。
EOF
}

mode="${1:-host}"
if [[ "$mode" == "-h" || "$mode" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "$mode" != "host" && "$mode" != "all" ]]; then
  echo "错误：未知构建模式：$mode" >&2
  usage >&2
  exit 2
fi

if [[ $# -gt 2 ]]; then
  echo "错误：参数过多" >&2
  usage >&2
  exit 2
fi

version="${2:-${VERSION:-}}"
if [[ -z "$version" ]]; then
  version="$(git describe --tags --exact-match HEAD 2>/dev/null || true)"
  if [[ -z "$version" ]]; then
    short_sha="$(git rev-parse --short=7 HEAD 2>/dev/null || true)"
    if [[ -n "$short_sha" ]]; then
      version="dev-${short_sha}"
    else
      version="dev-local"
    fi
  fi
fi

if [[ ! "$version" =~ ^[A-Za-z0-9._+-]+$ ]]; then
  echo "错误：版本号只能包含英文字母、数字、点、下划线、加号和连字符" >&2
  exit 2
fi

out_dir="${OUT_DIR:-dist}"
mkdir -p "$out_dir"

build_target() {
  local goos="$1"
  local goarch="$2"
  local extension=""
  if [[ "$goos" == "windows" ]]; then
    extension=".exe"
  fi

  local filename="WebKiller-leak-${version}-${goos}-${goarch}${extension}"
  echo "正在构建 ${filename}"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath \
      -ldflags="-s -w -X main.version=${version}" \
      -o "${out_dir}/${filename}" .
}

if [[ "$mode" == "host" ]]; then
  build_target "$(go env GOHOSTOS)" "$(go env GOHOSTARCH)"
else
  build_target linux amd64
  build_target darwin amd64
  build_target darwin arm64
  build_target windows amd64
fi

echo "构建完成：版本 ${version}，产物目录 ${out_dir}/"
