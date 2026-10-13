#!/usr/bin/env bash
set -euo pipefail

prefix="${OPENMILI_PREFIX:-${HOME}/.local/bin}"
repo="${OPENMILI_REPO:-OpenMili/OpenMili-Radar}"
version="${OPENMILI_VERSION:-latest}"
mkdir -p "$prefix"

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
if [[ -f "${root_dir}/go.mod" && -d "${root_dir}/cmd/openmili" ]]; then
  command -v go >/dev/null 2>&1 || { echo "未找到 Go 1.22+；从源码安装需要先安装 Go。" >&2; exit 1; }
  tmp="${prefix}/.openmili.tmp.$$"
  trap 'rm -f "$tmp"' EXIT
  (cd "$root_dir" && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$tmp" ./cmd/openmili)
  mv "$tmp" "${prefix}/openmili"
  chmod 0755 "${prefix}/openmili"
  echo "已从源码安装到 ${prefix}/openmili"
  exit 0
fi

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$os" in
  linux|darwin) ;;
  *) echo "不支持的系统：$os" >&2; exit 1 ;;
esac
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "不支持的架构：$arch" >&2; exit 1 ;;
esac
if [[ "$version" == "latest" ]]; then
  url="https://github.com/${repo}/releases/latest/download/openmili-${os}-${arch}"
  sums_url="https://github.com/${repo}/releases/latest/download/SHA256SUMS"
else
  url="https://github.com/${repo}/releases/download/${version}/openmili-${os}-${arch}"
  sums_url="https://github.com/${repo}/releases/download/${version}/SHA256SUMS"
fi
command -v curl >/dev/null 2>&1 || { echo "未找到 curl，无法下载发行版。" >&2; exit 1; }
tmp="${prefix}/.openmili.tmp.$$"
checksums="${prefix}/.openmili.sha256.$$"
cleanup() { rm -f "$tmp" "$checksums"; }
trap cleanup EXIT
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "$sums_url" --output "$checksums"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "$url" --output "$tmp"
asset="openmili-${os}-${arch}"
expected="$(awk -v name="$asset" '$2 == name {print $1; exit}' "$checksums")"
[[ "$expected" =~ ^[[:xdigit:]]{64}$ ]] || { echo "发布校验文件中缺少 ${asset}" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp" | awk '{print $1}')"
else
  actual="$(shasum -a 256 "$tmp" | awk '{print $1}')"
fi
[[ "$actual" == "$expected" ]] || { echo "SHA-256 校验失败" >&2; exit 1; }
chmod 0755 "$tmp"
mv "$tmp" "${prefix}/openmili"
echo "已安装 ${repo} ${version} 到 ${prefix}/openmili"
