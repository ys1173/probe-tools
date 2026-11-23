#!/usr/bin/env bash
# Builds the hub and probe container images with docker buildx.
#
#   scripts/build-images.sh                       both images for the local platform, loaded into the local daemon
#   scripts/build-images.sh --multi-arch          linux/amd64 + linux/arm64 (PLATFORMS to change), pushed to a registry
#   scripts/build-images.sh --multi-arch --output type=oci,dest=dist/probe-images.oci.tar   (any buildx --output)
#   scripts/build-images.sh hub|probe             only one of them
#
# Environment:
#   VERSION     image/binary version; default `git describe --tags --always --dirty`, or "dev"
#   REGISTRY    image name prefix, default "probetools" -> probetools/hub:<version>, probetools/probe:<version>
#   PLATFORMS   multi-arch platform list, default linux/amd64,linux/arm64
#
# A multi-arch image cannot be loaded into the local daemon, so --multi-arch pushes unless --output is given.
# The build stage cross-compiles on the host platform, so no emulation is needed.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

multi=0
output=""
targets=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --multi-arch)
      multi=1
      shift
      ;;
    --output)
      [[ $# -ge 2 ]] || {
        echo "--output needs a value" >&2
        exit 1
      }
      output="$2"
      shift 2
      ;;
    hub | probe)
      targets+=("$1")
      shift
      ;;
    -h | --help)
      sed -n '2,/^set -euo/{/^set -euo/!p;}' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "unknown argument: $1 (try --help)" >&2
      exit 1
      ;;
  esac
done
[[ ${#targets[@]} -gt 0 ]] || targets=(hub probe)

version="${VERSION:-}"
if [[ -z "${version}" ]]; then
  version="$(git describe --tags --always --dirty 2>/dev/null || true)"
fi
version="${version:-dev}"
version="${version//[^A-Za-z0-9._+-]/-}"
registry="${REGISTRY:-probetools}"

for target in "${targets[@]}"; do
  image="${registry}/${target}"
  args=(buildx build
    -f "deploy/docker/Dockerfile.${target}"
    --build-arg "VERSION=${version}"
    -t "${image}:${version}" -t "${image}:latest")
  if [[ ${multi} -eq 1 ]]; then
    args+=(--platform "${PLATFORMS:-linux/amd64,linux/arm64}")
    if [[ -n "${output}" ]]; then
      args+=(--output "${output}")
    else
      args+=(--push)
    fi
  elif [[ -n "${output}" ]]; then
    args+=(--output "${output}")
  else
    args+=(--load)
  fi
  echo "==> ${image}:${version}"
  docker "${args[@]}" .
done
