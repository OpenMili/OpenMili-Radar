#!/usr/bin/env bash
set -euo pipefail

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
out_dir="${root_dir}/dist"
mkdir -p "$out_dir"

build_one() {
  local goos="$1" goarch="$2" suffix="$3"
  local name="openmili-${goos}-${goarch}${suffix}"
  echo "building ${name}"
  (cd "$root_dir" && GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "${out_dir}/${name}" ./cmd/openmili)
}

build_one linux amd64 ""
build_one linux arm64 ""
build_one darwin amd64 ""
build_one darwin arm64 ""
build_one windows amd64 ".exe"
build_one windows arm64 ".exe"

echo "artifacts written to ${out_dir}"
