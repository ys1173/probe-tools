#!/usr/bin/env bash
# TESTING ONLY. Creates a throwaway CA and a hub server certificate under deploy/central/certs/ so you can try the
# hub and a probe together. Do not use these for a real deployment: the CA key sits next to the server key, the
# validity is short, and tls.key is made world-readable so the hub container (uid 65532) can read it. For a real
# deployment use a certificate from your own CA or ACME, and chown 65532:65532 + chmod 0400 the key.
#
#   scripts/dev-certs.sh                       SANs: localhost, hub, 127.0.0.1
#   scripts/dev-certs.sh hub.test 10.1.2.3     SANs: exactly the names/IPs given (IPs are detected)
#   DAYS=30 scripts/dev-certs.sh               certificate lifetime in days (default 90)
#
# Writes ca.crt, ca.key, tls.crt, tls.key. Point the probe at ca.crt (ca_file) and use a host name from the SANs in
# its hub_url. openssl runs in a container, so only Docker is needed.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dir="${root}/deploy/central/certs"
days="${DAYS:-90}"
image="${OPENSSL_IMAGE:-alpine/openssl}"

names=("$@")
[[ ${#names[@]} -gt 0 ]] || names=(localhost hub 127.0.0.1)

# subjectAltName entries: an IPv4/IPv6 literal becomes IP:, anything else DNS:.
san=""
for n in "${names[@]}"; do
  if [[ "${n}" =~ ^[0-9.]+$ || "${n}" == *:* ]]; then
    san+="IP:${n},"
  else
    san+="DNS:${n},"
  fi
done
san="${san%,}"

mkdir -p "${dir}"
# Keys and certificates must never be committed.
printf '*\n!.gitignore\n' >"${dir}/.gitignore"

cat >"${dir}/.openssl-ext.cnf" <<CNF
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = ${san}
CNF

# Run as the invoking user so the files are not owned by root.
docker run --rm --user "$(id -u):$(id -g)" -v "${dir}:/certs" -w /certs --entrypoint sh "${image}" -euc "
  openssl ecparam -name prime256v1 -genkey -noout -out ca.key
  openssl req -x509 -new -key ca.key -sha256 -days ${days} -subj '/CN=probe-dev-ca' \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' -out ca.crt
  openssl ecparam -name prime256v1 -genkey -noout -out tls.key
  openssl req -new -key tls.key -subj '/CN=${names[0]}' -out tls.csr
  openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days ${days} -sha256 \
    -extfile .openssl-ext.cnf -out tls.crt
  rm -f tls.csr ca.srl .openssl-ext.cnf
"
chmod 0644 "${dir}/tls.key" "${dir}/tls.crt" "${dir}/ca.crt"
chmod 0600 "${dir}/ca.key"

echo "created in ${dir}:"
echo "  tls.crt tls.key   hub listener certificate (SANs: ${san})"
echo "  ca.crt            give this to the probe: ca_file: <path to ca.crt>"
echo "                    (docker probe: mount it at /etc/probe/ca.crt and set ca_file: /etc/probe/ca.crt)"
echo "FOR TESTING ONLY."
