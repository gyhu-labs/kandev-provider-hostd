#!/usr/bin/env bash
# Build the Kandev plugin package (docs/public/plugins-authoring.md "Package
# and data layout"): manifest.yaml, server/plugin-linux-amd64 (the plugin),
# server/hostd-edge-linux-amd64 (uploaded to each VM), README.md, LICENSE and
# a generated checksums.txt.
#
#   scripts/package.sh [OUT_DIR]      # version comes from package/manifest.yaml
#
# Output: OUT_DIR/kandev-provider-hostd-<version>.tar.gz and a .sha256 file.
# Reproducible: static binaries without build IDs, entry mtimes from the
# last commit (SOURCE_DATE_EPOCH).
set -euo pipefail

out="${1:-dist}"
version="$(sed -n 's/^version: *"\{0,1\}\([^"]*\)"\{0,1\} *$/\1/p' package/manifest.yaml | head -n1)"
[ -n "$version" ] || { echo "package.sh: no version in package/manifest.yaml" >&2; exit 1; }
if [ -n "${EXPECT_VERSION:-}" ] && [ "$EXPECT_VERSION" != "$version" ]; then
  echo "package.sh: manifest version $version != expected $EXPECT_VERSION" >&2
  exit 1
fi

stage=".build/stage"
rm -rf "$stage"
mkdir -p "$stage/server" "$out"
cp package/manifest.yaml "$stage/manifest.yaml"
cp README.md LICENSE "$stage/"

ldflags="-s -w -buildid="
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags "$ldflags" \
  -o "$stage/server/plugin-linux-amd64" ./cmd/kandev-provider-hostd
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags "$ldflags" \
  -o "$stage/server/hostd-edge-linux-amd64" ./cmd/hostd-edge

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
name="kandev-provider-hostd-${version}.tar.gz"
go run ./cmd/plugin-pack -dir "$stage" -out "$out/$name" -version "$version"
go run ./cmd/plugin-pack -verify "$out/$name" -version "$version"
(cd "$out" && sha256sum "$name" > "$name.sha256")
echo "version=$version" >> "${GITHUB_OUTPUT:-/dev/null}"
echo "package=$out/$name" >> "${GITHUB_OUTPUT:-/dev/null}"
cat "$out/$name.sha256"
