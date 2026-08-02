#!/usr/bin/env bash
#
# Build release binaries + tarballs + a checksums file for every shipped
# OS/arch pair.
#
# litevirt is a single combined binary: `litevirt daemon` is the cluster host
# and `litevirt <cmd>` (alias `lv`) is the CLI/UI client. The daemon needs
# Linux + KVM/QEMU, so the darwin artifacts are client-only — they drive a
# remote cluster over gRPC/mTLS but cannot host VMs locally. They ship anyway
# because managing a Linux cluster from a Mac laptop is a first-class case.
#
# Pure-Go cross-compile (CGO_ENABLED=0), so one Linux runner builds every
# platform with no extra toolchain.
#
# Env:
#   VERSION  release version, e.g. v1.2.0          (required)
#   COMMIT   commit sha for -X main.commit          (default: git HEAD)
#   OUTDIR   output directory                       (default: dist)
set -euo pipefail

VERSION="${VERSION:?VERSION is required (e.g. v1.2.0)}"
COMMIT="${COMMIT:-$(git rev-parse HEAD 2>/dev/null || echo none)}"
OUTDIR="${OUTDIR:-dist}"

# Shipped platforms. darwin/* are client-only (see header).
PLATFORMS=(
  linux/amd64
  linux/arm64
  darwin/amd64
  darwin/arm64
)

mkdir -p "$OUTDIR"
rm -f "$OUTDIR"/*.tar.gz "$OUTDIR"/*checksums.txt

for platform in "${PLATFORMS[@]}"; do
  goos="${platform%/*}"
  goarch="${platform#*/}"
  echo "building ${goos}/${goarch}..."
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o "$OUTDIR/litevirt" ./cmd/litevirt
  # Package the binary plus the muscle-memory `lv` symlink.
  ( cd "$OUTDIR" \
      && ln -sf litevirt lv \
      && tar -czf "litevirt-${VERSION}-${goos}-${goarch}.tar.gz" litevirt lv \
      && rm -f litevirt lv )
done

# One checksums file across every artifact; brew-formula.sh reads it.
( cd "$OUTDIR" && sha256sum ./*.tar.gz > "litevirt-${VERSION}-checksums.txt" )
ls -l "$OUTDIR"
