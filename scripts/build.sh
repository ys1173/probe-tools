#!/usr/bin/env bash
# Cross-compiles probe and probe-hub for linux/amd64 and linux/arm64 into dist/, and packs a probe release tarball
# per architecture for servers that run the probe natively under systemd. Needs only Docker (via scripts/go).
#
#   scripts/build.sh                 version from `git describe --tags --always --dirty`, or "dev"
#   VERSION=v1.2.3 scripts/build.sh  explicit version
#   ARCHES="amd64" scripts/build.sh  build one architecture only
#
# Output:
#   dist/linux-<arch>/probe, dist/linux-<arch>/probe-hub          static binaries (CGO_ENABLED=0)
#   dist/probe-<version>-linux-<arch>.tar.gz                      probe, install.sh, probe.service, probe.yaml, INSTALL.txt
#   dist/SHA256SUMS
#
# Files under dist/ are written by the Go container, so on a Linux host they may be owned by root.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

version="${VERSION:-}"
if [[ -z "${version}" ]]; then
  version="$(git describe --tags --always --dirty 2>/dev/null || true)"
fi
version="${version:-dev}"
# The version ends up in file names and ldflags: keep it to a safe character set.
version="${version//[^A-Za-z0-9._+-]/-}"

read -r -a arches <<<"${ARCHES:-amd64 arm64}"

mkdir -p dist
echo "building ${version} for: ${arches[*]}"

for arch in "${arches[@]}"; do
  out="dist/linux-${arch}"
  mkdir -p "${out}"
  echo "==> linux/${arch}"
  # scripts/go passes GOOS and GOARCH through to the container. -o is relative to /src, which is this repo.
  GOOS=linux GOARCH="${arch}" "${root}/scripts/go" build -trimpath \
    -ldflags "-s -w -X probetools/internal/probe.Version=${version}" \
    -o "${out}/probe" ./cmd/probe
  GOOS=linux GOARCH="${arch}" "${root}/scripts/go" build -trimpath \
    -ldflags "-s -w -X probetools/internal/hub.Version=${version}" \
    -o "${out}/probe-hub" ./cmd/probe-hub

  name="probe-${version}-linux-${arch}"
  stage="dist/.stage/${name}"
  rm -rf "${stage}"
  mkdir -p "${stage}"
  install -m 0755 "${out}/probe" "${stage}/probe"
  install -m 0755 deploy/linux/install.sh "${stage}/install.sh"
  install -m 0644 deploy/linux/probe.service "${stage}/probe.service"
  install -m 0644 deploy/linux/probe.yaml "${stage}/probe.yaml"
  cat >"${stage}/INSTALL.txt" <<TXT
probe ${version} (linux/${arch})

Install on a Linux server with systemd, as root:

  tar xzf ${name}.tar.gz
  cd ${name}
  sudo PROBE_ENROLL_TOKEN=<token from the hub> ./install.sh     # or leave the variable out and type it when asked

Then edit /etc/probe/probe.yaml: set hub_url and the targets section (targets.mode must be "open" or "closed";
the probe will not start without it), and, if the hub uses a private CA, ca_file. Start (or restart) with:

  sudo systemctl restart probe
  journalctl -u probe -f

install.sh needs no network access. It installs /usr/local/bin/probe, a "probe" system user, /etc/probe/probe.yaml
(kept if it exists), /etc/probe/probe.env (the enrolment token, mode 0600) and the probe.service unit, checks the
config with "probe check-config", and starts the service. Run it again with a newer tarball to upgrade.

The enrolment token is single use. Once the probe has enrolled it keeps its identity in /var/lib/probe.

Remove with:   sudo ./install.sh --uninstall           (keeps /etc/probe and /var/lib/probe)
               sudo ./install.sh --uninstall --purge   (deletes them and the probe user)
TXT

  # Reproducible ownership inside the archive; no macOS extended-attribute files.
  if tar --version 2>/dev/null | grep -q 'GNU tar'; then
    tar --owner=0 --group=0 --numeric-owner -C dist/.stage -czf "dist/${name}.tar.gz" "${name}"
  else
    COPYFILE_DISABLE=1 tar --no-xattrs --uid 0 --gid 0 --uname root --gname root -C dist/.stage -czf "dist/${name}.tar.gz" "${name}"
  fi
  rm -rf "${stage}"
done
rmdir dist/.stage 2>/dev/null || true

(
  cd dist
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum ./*.tar.gz linux-*/probe linux-*/probe-hub >SHA256SUMS
  else
    shasum -a 256 ./*.tar.gz linux-*/probe linux-*/probe-hub >SHA256SUMS
  fi
)

echo "done:"
ls -1 dist/*.tar.gz
