#!/usr/bin/env bash
# End-to-end test of probe-hub and probe: builds the images, brings up test/e2e/compose.yaml (hub with TLS, three
# probes on bridge networks, targets, a NAT router and an MCP client container), runs the cases, prints a PASS/FAIL
# table and tears the stack down.
#
#   test/e2e/run.sh                   everything (setup, cases 1-13 and x, report, teardown)
#   test/e2e/run.sh --keep            leave the stack up afterwards (tokens in test/e2e/.work/env)
#   test/e2e/run.sh --reuse --keep    run against a stack left up by --keep (no rebuild, no re-enrol)
#   test/e2e/run.sh --only "3 5"      run only these cases (ids: 1-13, x = image/config checks; 13 = device commands
#                                     over SSH, which enters probe-a's SSH profiles itself)
#   test/e2e/run.sh --with-build      also run scripts/build.sh and check dist/ (writes dist/ at the repo root)
#   test/e2e/run.sh --down            just tear the stack down
#
# Needs docker (compose v2), jq, openssl and ssh-keygen on the host. Works with macOS bash 3.2. Evidence for every case is saved in
# test/e2e/.work/out/<id>.json, container logs in test/e2e/.work/logs/.
#
# Probe names: site-a-probe (service probe-a, site a), site-b-probe (probe-b, site b), site-c-probe (probe-c, site c).
# The names start with the site so the `limited` client's probe scope ["site-a-*"] covers probe-a only.
#
# Clients: full (tools ["*"], so no device tools), limited (ping and list_probes, site-a only), netops (["*",
# "device_show", "device_commands"]).
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "${here}/../.." && pwd)"
work="${here}/.work"
out="${work}/out"
logs="${work}/logs"
results="${work}/results.txt"
calls="${work}/calls.count"

keep=0
reuse=0
only=""
with_build=0
down_only=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep) keep=1 ;;
    --reuse) reuse=1 ;;
    --only) only="$2"; shift ;;
    --with-build) with_build=1 ;;
    --down) down_only=1 ;;
    -h | --help) sed -n '2,/^set -uo/{/^set -uo/!p;}' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done

export E2E_VERSION="v0.0.0-e2e"
A=site-a-probe
B=site-b-probe
C=site-c-probe
HUB_WAN=10.201.0.10
A_WAN=10.201.0.11
B_WAN=10.201.0.12
C_WAN=10.201.0.13
C_ISO=10.204.0.13
WEB=10.202.0.21
REDIS=10.202.0.22
DNS=10.202.0.23
BANNER=10.202.0.24
NAT_A=10.202.0.30
NAT_B=10.203.0.30
SECRET=10.204.0.40
MCP_URL=http://hub:8080/mcp
# Device cases (13): fake SSH devices, the jump host, and the network only the jump reaches.
DEV_IOS=10.202.0.41
DEV_KEY=10.202.0.42
DEV_DENY=10.202.0.43
DEV_BADPW=10.202.0.44
DEV_FW=10.205.0.41
JUMP_WAN=10.201.0.30
JUMP_B=10.205.0.30
dev="${work}/dev"
sshin="${work}/ssh-in"
DEV_SERVICES="fakedev-ios fakedev-key fakedev-deny fakedev-badpw fakedev-fw"
WRONG_TOKEN="wrong-token-0123456789abcdef0123456789abcdef"

dc() { docker compose -f "${here}/compose.yaml" --project-directory "${here}" "$@"; }
log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
now() { date +%s; }

if [[ ${down_only} -eq 1 ]]; then
  [[ -f "${work}/env" ]] && . "${work}/env"
  export HUB_TOKEN_FULL="${HUB_TOKEN_FULL:-x}" HUB_TOKEN_LIMITED="${HUB_TOKEN_LIMITED:-x}" HUB_TOKEN_NETOPS="${HUB_TOKEN_NETOPS:-x}"
  dc down -v --remove-orphans
  exit 0
fi

# ---------------------------------------------------------------- result helpers
pass() { printf 'PASS|%s|%s|\n' "$1" "$2" >>"${results}"; log "PASS ${1} ${2}"; }
fail() { printf 'FAIL|%s|%s|%s\n' "$1" "$2" "$3" >>"${results}"; log "FAIL ${1} ${2} -- ${3}"; }
info() { printf 'INFO|%s|%s|%s\n' "$1" "$2" "$3" >>"${results}"; log "INFO ${1} ${2} -- ${3}"; }

# expect ID DESC JSON JQ_ASSERT [JQ_DETAIL]: PASS when the assertion is true; the detail (default: the whole JSON,
# compact) is shown on FAIL. The JSON is saved as evidence either way.
expect() {
  local id="$1" desc="$2" json="$3" expr="$4" detail="${5:-.}"
  printf '%s\n' "${json}" >"${out}/${id}.json"
  if printf '%s' "${json}" | jq -e "${expr}" >/dev/null 2>&1; then
    pass "${id}" "${desc}"
  else
    fail "${id}" "${desc}" "$(printf '%s' "${json}" | jq -c "${detail}" 2>/dev/null | cut -c1-700)"
  fi
}

want() {
  [[ -z "${only}" ]] && return 0
  case " ${only} " in *" $1 "*) return 0 ;; esac
  return 1
}

# mcp TOKEN TOOL ARGS: one tools/call through the client container; prints mcpcall's JSON. Calls that reached the
# hub are counted, so case 10 can compare with the audit log. A call the hub refused as an unknown tool (a client
# calling a tool outside its list) still reached the hub and is audited, so it counts too.
mcp() {
  local res
  res="$(dc exec -T client /e2e/mcpcall --url "${MCP_URL}" --token "$1" --tool "$2" --args "$3")"
  if printf '%s' "${res}" | jq -e '(has("transport_error") | not) or (.transport_error | test("unknown tool"))' >/dev/null 2>&1; then
    echo x >>"${calls}"
  fi
  printf '%s\n' "${res}"
}
full() { mcp "${HUB_TOKEN_FULL}" "$@"; }
limited() { mcp "${HUB_TOKEN_LIMITED}" "$@"; }
netops() { mcp "${HUB_TOKEN_NETOPS}" "$@"; }
tools_list() { dc exec -T client /e2e/mcpcall --url "${MCP_URL}" --token "$1" --list; }
raw_status() { dc exec -T client /e2e/mcpcall --url "${MCP_URL}" --token "$1" --raw-status; }

# online_count: number of probes the full client sees online (-1 when the hub does not answer).
online_count() {
  local j
  j="$(full list_probes '{}')"
  printf '%s' "${j}" | jq '[.structured.probes[]? | select(.online)] | length' 2>/dev/null || echo -1
}

# wait_online N LIMIT_S: waits until N probes are online; prints the seconds it took, returns 1 on timeout.
wait_online() {
  local want="$1" limit="$2" t0 n
  t0="$(now)"
  while :; do
    n="$(online_count)"
    if [[ "${n}" =~ ^[0-9]+$ ]] && [[ "${n}" -ge "${want}" ]]; then
      echo $(($(now) - t0))
      return 0
    fi
    if [[ $(($(now) - t0)) -ge "${limit}" ]]; then
      echo $(($(now) - t0))
      return 1
    fi
    sleep 1
  done
}

container_id() { dc ps -a -q "$1"; }

# identity_secret SERVICE: the probe's secret, read from the identity file in the stopped-or-running container.
identity_secret() {
  docker cp "$(container_id "$1"):/var/lib/probe/identity.json" - 2>/dev/null | tar -xO 2>/dev/null | jq -r '.secret // empty'
}
identity_mode() {
  docker cp "$(container_id "$1"):/var/lib/probe/identity.json" - 2>/dev/null | tar -tvf - 2>/dev/null | awk '{print $1}'
}

# ---------------------------------------------------------------- setup
setup() {
  mkdir -p "${work}/bin" "${work}/certs"
  log "certificates: running scripts/dev-certs.sh (a copy rooted at .work, so it writes under test/e2e)"
  rm -rf "${work}/devcerts"
  mkdir -p "${work}/devcerts/scripts"
  cp "${root}/scripts/dev-certs.sh" "${work}/devcerts/scripts/dev-certs.sh"
  bash "${work}/devcerts/scripts/dev-certs.sh" hub >/dev/null || { log "dev-certs.sh failed"; exit 1; }
  cp "${work}/devcerts/deploy/central/certs/ca.crt" "${work}/devcerts/deploy/central/certs/tls.crt" \
    "${work}/devcerts/deploy/central/certs/tls.key" "${work}/certs/"

  log "building mcpcall and fakedevice"
  (cd "${root}" && GOFLAGS=-mod=readonly scripts/go build -o test/e2e/.work/bin/mcpcall ./test/e2e/mcpcall) ||
    { log "mcpcall build failed"; exit 1; }
  (cd "${root}" && GOFLAGS=-mod=readonly scripts/go build -o test/e2e/.work/bin/fakedevice ./test/e2e/fakedevice) ||
    { log "fakedevice build failed"; exit 1; }
  dev_files || { log "device keys and passwords could not be made"; exit 1; }

  HUB_TOKEN_FULL="$(openssl rand -hex 32)"
  HUB_TOKEN_LIMITED="$(openssl rand -hex 32)"
  HUB_TOKEN_NETOPS="$(openssl rand -hex 32)"
  export HUB_TOKEN_FULL HUB_TOKEN_LIMITED HUB_TOKEN_NETOPS

  log "building images (version ${E2E_VERSION})"
  dc build --quiet || { log "image build failed"; exit 1; }
  dc down -v --remove-orphans >/dev/null 2>&1
  log "starting hub and targets"
  dc up -d --quiet-pull hub web redis dns banner secret nat client ${DEV_SERVICES} jump >"${work}/compose-up.log" 2>&1 || { log "compose up failed (see ${work}/compose-up.log)"; exit 1; }
  local i
  for i in $(seq 1 30); do
    dc exec -T client wget -qO- http://hub:8080/healthz >/dev/null 2>&1 && break
    sleep 1
  done
  for i in $(seq 1 30); do
    dc logs --no-log-prefix jump 2>/dev/null | grep -q 'Server listening' && break
    sleep 1
  done

  log "enrolling probes"
  local p tok
  for p in a b c; do
    tok="$(dc exec -T hub probe-hub token create --name "site-${p}-probe" --site "${p}" | awk '/^  [^ ]+$/ {print $1; exit}')"
    [[ -n "${tok}" ]] || { log "token create for ${p} gave no token"; exit 1; }
    case "${p}" in a) ENROLL_A="${tok}" ;; b) ENROLL_B="${tok}" ;; c) ENROLL_C="${tok}" ;; esac
  done
  export ENROLL_A ENROLL_B ENROLL_C
  umask 077
  cat >"${work}/env" <<ENV
HUB_TOKEN_FULL=${HUB_TOKEN_FULL}
HUB_TOKEN_LIMITED=${HUB_TOKEN_LIMITED}
HUB_TOKEN_NETOPS=${HUB_TOKEN_NETOPS}
ENROLL_A=${ENROLL_A}
ENROLL_B=${ENROLL_B}
ENROLL_C=${ENROLL_C}
ENV
  umask 022
  dc up -d probe-a probe-b probe-c >>"${work}/compose-up.log" 2>&1 || { log "probes failed to start (see ${work}/compose-up.log)"; exit 1; }
  local took
  if took="$(wait_online 3 90)"; then
    log "all 3 probes online after ${took}s"
  else
    log "only $(online_count) probes online after ${took}s; continuing so the cases show what is wrong"
  fi
}

# ---------------------------------------------------------------- cases
case1() {
  local j
  j="$(tools_list "${HUB_TOKEN_FULL}")"
  expect 1 "tools/list has all 13 tools, readOnlyHint true on every one" "${j}" \
    '([.tools[].name] | sort) == (["list_probes","path_test","diagnose","ping","traceroute","path_mtu","dns_lookup","tcp_connect","tcp_template","udp_probe","tls_check","http_check","probe_info"] | sort)
     and all(.tools[]; .read_only == true)' \
    '{names: [.tools[]?.name], not_read_only: [.tools[]? | select(.read_only != true) | .name], err: .transport_error}'
  j="$(tools_list "${HUB_TOKEN_LIMITED}")"
  expect 1-limited "tools/list for the limited client shows only its tools (list_probes, ping)" "${j}" \
    '([.tools[].name] | sort) == ["list_probes","ping"]' \
    '{names: [.tools[]?.name], err: .transport_error}'
}

case2() {
  local j
  j="$(full list_probes '{}')"
  expect 2 "list_probes: a, b, c online with site, version, raw_icmp, policy" "${j}" \
    "(.structured.probes | map(.name) | sort) == [\"${A}\",\"${B}\",\"${C}\"]
     and all(.structured.probes[]; .online and .site != \"\" and .version == \"${E2E_VERSION}\"
         and .capabilities.raw_icmp == true and (.policy.mode == \"open\" or .policy.mode == \"closed\")
         and .listen_ports == \"40000-40010\" and (.addresses | length) >= 2)
     and (.structured.probes[] | select(.name == \"${B}\") | .policy.mode == \"closed\"
         and (.policy.allow_cidrs | sort) == [\"10.201.0.0/24\",\"10.202.0.0/24\"])" \
    '[.structured.probes[]? | {name, site, online, version, capabilities, policy, listen_ports, addresses}]'
}

case3() {
  local j pa="\"probes\":[\"${A}\"]"
  j="$(full ping "{${pa},\"target\":\"${WEB}\",\"count\":3}")"
  expect 3.ping "ping web from probe-a: 3/3 replies (datagram socket preferred, raw fallback)" "${j}" \
    '.structured.results[0] | .ok and .result.received == 3 and (.result.socket == "datagram" or .result.socket == "raw")' '.structured.results[0] // .'

  local mode
  for mode in icmp udp tcp; do
    j="$(full traceroute "{${pa},\"target\":\"${WEB}\",\"mode\":\"${mode}\",\"port\":$([[ ${mode} == tcp ]] && echo 80 || echo 0),\"max_hops\":5}")"
    expect "3.traceroute-${mode}" "traceroute ${mode} to web reaches it, complete" "${j}" \
      '.structured.results[0] | .ok and .result.reached and .result.complete' '.structured.results[0] // .'
  done

  j="$(full path_mtu "{${pa},\"target\":\"${WEB}\"}")"
  expect 3.path_mtu "path_mtu to web finds 1500" "${j}" \
    '.structured.results[0] | .ok and .result.path_mtu == 1500' '.structured.results[0] // .'

  j="$(full dns_lookup "{${pa},\"name\":\"www.e2e.test\",\"type\":\"A\",\"server\":\"${DNS}\"}")"
  expect 3.dns-A "dns_lookup A www.e2e.test at the test server" "${j}" \
    ".structured.results[0] | .ok and .result.outcome == \"ok\" and .result.rcode == \"NOERROR\" and ([.result.answers[].data] | index(\"${WEB}\") != null)" \
    '.structured.results[0] // .'

  j="$(full dns_lookup "{${pa},\"name\":\"txt.e2e.test\",\"type\":\"TXT\",\"server\":\"${DNS}\"}")"
  expect 3.dns-TXT "dns_lookup TXT: instruction-like text comes back wrapped as untrusted" "${j}" \
    '.structured.results[0] | .ok and (.result.answers | length) == 1 and .result.answers[0].data.untrusted == true
       and (.result.answers[0].data.text | test("ignore previous instructions"))' '.structured.results[0] // .'

  j="$(full dns_lookup "{${pa},\"name\":\"redis\"}")"
  expect 3.dns-system "dns_lookup through the probe's own resolver (Docker 127.0.0.11) works" "${j}" \
    ".structured.results[0] | .ok and .result.outcome == \"ok\" and ([.result.answers[].data] | index(\"${REDIS}\") != null)" \
    '.structured.results[0] // .'

  j="$(full tcp_connect "{${pa},\"target\":\"${REDIS}\",\"ports\":[6379,6380],\"read_banner\":true}")"
  expect 3.tcp_connect "tcp_connect redis 6379 open (read_banner), 6380 refused" "${j}" \
    '.structured.results[0] | .ok and .result.ports[0].outcome == "open" and .result.ports[1].outcome == "refused"' \
    '.structured.results[0] // .'

  j="$(full tcp_connect "{${pa},\"target\":\"${BANNER}\",\"ports\":[22],\"read_banner\":true}")"
  expect 3.tcp_banner "tcp_connect read_banner on the SSH-like server: banner returned as untrusted text" "${j}" \
    '.structured.results[0] | .ok and .result.ports[0].outcome == "open" and .result.ports[0].banner.untrusted == true
       and (.result.ports[0].banner.text | test("^SSH-2.0-.*ignore previous instructions"))' '.structured.results[0] // .'

  j="$(full tcp_template "{${pa},\"target\":\"${REDIS}\",\"template\":\"redis_ping\"}")"
  expect 3.redis_ping "tcp_template redis_ping gets PONG" "${j}" \
    '.structured.results[0] | .ok and .result.outcome == "ok" and .result.interpretation == "pong" and .result.reply.untrusted == true' \
    '.structured.results[0] // .'

  j="$(full tcp_template "{${pa},\"target\":\"${WEB}\",\"template\":\"http_head\",\"path\":\"/\"}")"
  expect 3.http_head "tcp_template http_head to web gets 200" "${j}" \
    '.structured.results[0] | .ok and .result.outcome == "ok" and .result.status_code == 200' '.structured.results[0] // .'

  j="$(full tcp_template "{${pa},\"target\":\"${BANNER}\",\"template\":\"ssh_banner\"}")"
  expect 3.ssh_banner "tcp_template ssh_banner reads the version line, untrusted" "${j}" \
    '.structured.results[0] | .ok and .result.outcome == "ok" and .result.banner.untrusted == true and (.result.banner.text | startswith("SSH-2.0-"))' \
    '.structured.results[0] // .'

  j="$(full udp_probe "{${pa},\"target\":\"${DNS}\",\"template\":\"dns_query\"}")"
  expect 3.udp_dns "udp_probe dns_query to the DNS server is open" "${j}" \
    '.structured.results[0] | .ok and .result.outcome == "open"' '.structured.results[0] // .'

  j="$(full udp_probe "{${pa},\"target\":\"${WEB}\",\"template\":\"ntp_request\",\"retries\":0,\"timeout_ms\":1000}")"
  expect 3.udp_closed "udp_probe ntp to web (nothing on 123) is closed (ICMP port unreachable)" "${j}" \
    '.structured.results[0] | .ok and .result.outcome == "closed"' '.structured.results[0] // .'

  j="$(full tls_check "{${pa},\"target\":\"${WEB}\"}")"
  expect 3.tls_check "tls_check web: handshake ok, chain reported unverified (not an error)" "${j}" \
    '.structured.results[0] | .ok and .result.outcome == "ok" and .result.verified == false
       and .result.verify_error.untrusted == true and (.result.chain | length) >= 1' '.structured.results[0] // .'

  j="$(full http_check "{${pa},\"url\":\"http://${WEB}/\",\"expect_status\":200,\"expect_text\":\"hello from e2e\"}")"
  expect 3.http_check "http_check web: 200 and expect_text found, no body returned" "${j}" \
    '.structured.results[0] | .ok and .result.outcome == "ok" and .result.status == 200 and .result.expect_text_found == true
       and .result.expect_status_met == true and (.result.body | has("sha256")) and (.result.body | has("text") | not)' \
    '.structured.results[0] // .'

  j="$(full http_check "{${pa},\"url\":\"https://${WEB}/\"}")"
  expect 3.http_check-tls "http_check https with verification on: certificate failure reported as the outcome" "${j}" \
    '.structured.results[0] | .ok and .result.outcome == "tls_verify_failed"' '.structured.results[0] // .'

  local target
  for target in "https://${WEB}/" "https://web/"; do
    j="$(full diagnose "{${pa},\"target\":\"${target}\"}")"
    expect "3.diagnose-$([[ ${target} == *web/ ]] && echo name || echo ip)" "diagnose ${target}: dns/ping/tcp ok, first failure is TLS verification" "${j}" \
      '.structured.results[0] | .ok and ([.result.layers[] | select(.layer == "tcp")][0].status == "ok")
         and ([.result.layers[] | select(.layer == "ping")][0].status == "ok") and .result.first_failure == "tls"' \
      '.structured.results[0] | {ok, error, first_failure: .result.first_failure, verdict: .result.verdict, layers: [.result.layers[]? | {layer, status, summary}]}'
    info "3.diagnose-verdict" "${target}" "$(printf '%s' "${j}" | jq -c '.structured.results[0].result | {first_failure, verdict}')"
  done
  j="$(full probe_info "{${pa}}")"
  expect 3.probe_info "probe_info from probe-a: version, addresses, policy" "${j}" \
    ".structured.results[0] | .ok and (.result | tostring | test(\"${E2E_VERSION}\")) and (.result | tostring | test(\"${A_WAN}\"))" \
    '.structured.results[0] // .'

  # Every TCP template other than http_head, to show whether the failure is template-specific.
  j="$(full tcp_template "{${pa},\"target\":\"${REDIS}\",\"template\":\"postgres_ssl\",\"port\":6379}")"
  expect 3.postgres_ssl "tcp_template postgres_ssl to redis runs (any outcome, not invalid_params)" "${j}" \
    '.structured.results[0].ok' '.structured.results[0] // .'
}

case4() {
  local j
  j="$(full ping "{\"probes\":[\"*\"],\"target\":\"${HUB_WAN}\",\"count\":2}")"
  expect 4 "fan-out ping [*]: one result per probe, sorted, each with probe and site" "${j}" \
    "([.structured.results[].probe]) == [\"${A}\",\"${B}\",\"${C}\"]
     and all(.structured.results[]; .ok and .site != \"\" and .result.received == 2)" \
    '[.structured.results[]? | {probe, site, ok, error, received: .result.received}]'
}

case5() {
  local j
  j="$(full ping "{\"probes\":[\"${B}\"],\"target\":\"8.8.8.8\",\"count\":1}")"
  expect 5.closed "probe-b (closed) pinging outside its allow list: denied" "${j}" \
    '.structured.results[0].error.code == "denied"' '.structured.results[0] // .'

  j="$(full ping "{\"probes\":[\"${B}\"],\"target\":\"${C_ISO}\",\"count\":1}")"
  expect 5.closed-private "probe-b pinging c's isolated address (10.204/24, not allowed): denied" "${j}" \
    '.structured.results[0].error.code == "denied"' '.structured.results[0] // .'

  local t
  for t in 127.0.0.1 169.254.169.254 localhost; do
    j="$(full ping "{\"probes\":[\"*\"],\"target\":\"${t}\",\"count\":1}")"
    expect "5.always-${t}" "every probe refuses ${t}" "${j}" \
      '(.structured.results | length) == 3 and all(.structured.results[]; .error.code == "denied")' \
      '[.structured.results[]? | {probe, ok, error}]'
  done

  j="$(full http_check "{\"probes\":[\"${A}\"],\"url\":\"http://${WEB}/meta\"}")"
  expect 5.redirect-metadata "http_check redirect to 169.254.169.254: hop denied, chain reported" "${j}" \
    '.structured.results[0] | .ok and .result.outcome == "denied" and (.result.redirects | length) >= 1
       and (.result.redirects[-1].url.text | test("169\\.254\\.169\\.254")) and .result.redirects[-1].error.code == "denied"
       and .result.redirects[-1].status == 302' '.structured.results[0] // .'

  j="$(full http_check "{\"probes\":[\"${A}\"],\"url\":\"http://${WEB}/isolated\",\"timeout_ms\":5000}")"
  expect 5.redirect-isolated "http_check redirect to the isolated host from probe-a: that hop fails (timeout/unreachable/refused)" "${j}" \
    '.structured.results[0] | .ok and (.result.redirects | length) >= 1
       and (.result.redirects[-1].url.text | test("10\\.204\\.0\\.40"))
       and ([.result.outcome, .result.redirects[-1].error.code?] | any(. == "timeout" or . == "unreachable" or . == "refused"))' \
    '.structured.results[0] // .'
  info 5.redirect-isolated "outcome seen" "$(printf '%s' "${j}" | jq -c '.structured.results[0].result | {outcome, hop_error: .redirects[-1].error}')"
}

case6() {
  local j
  j="$(full path_test "{\"from\":\"${A}\",\"to\":\"${B}\",\"protocol\":\"tcp\",\"to_address\":\"${B_WAN}\"}")"
  expect 6.tcp "path_test a->b tcp (b's wan address): reached" "${j}" \
    ".structured.verdict == \"reached\" and (.structured.observed_source | startswith(\"${A_WAN}:\"))" '.structured // .'

  j="$(full path_test "{\"from\":\"${A}\",\"to\":\"${B}\",\"protocol\":\"udp\",\"to_address\":\"${B_WAN}\"}")"
  expect 6.udp "path_test a->b udp: reached" "${j}" '.structured.verdict == "reached"' '.structured // .'

  j="$(full path_test "{\"from\":\"${A}\",\"to\":\"${C}\",\"protocol\":\"tcp\",\"to_address\":\"${C_ISO}\",\"timeout_ms\":2000}")"
  expect 6.isolated "path_test a->c at c's isolated address: blocked_or_dropped" "${j}" \
    '.structured.verdict == "blocked_or_dropped"' '.structured // .'

  j="$(full path_test "{\"from\":\"${A}\",\"to\":\"${C}\",\"protocol\":\"udp\",\"to_address\":\"${C_ISO}\"}")"
  expect 6.isolated-udp "path_test a->c udp at c's isolated address: blocked_or_dropped" "${j}" \
    '.structured.verdict == "blocked_or_dropped"' '.structured // .'

  j="$(full path_test "{\"from\":\"${A}\",\"to\":\"${B}\",\"protocol\":\"tcp\",\"port\":50000,\"to_address\":\"${B_WAN}\"}")"
  expect 6.port-outside "path_test to a port outside b's listen_ports: listen_failed with a clear reason" "${j}" \
    '.structured.verdict == "listen_failed" and (.structured.summary | test("listen_ports"))' '.structured // .'

  j="$(full path_test "{\"from\":\"${B}\",\"to\":\"${A}\",\"protocol\":\"tcp\",\"to_address\":\"${C_ISO}\"}")"
  expect 6.policy "path_test b->a to an address b's policy denies: denied_by_policy" "${j}" \
    '.structured.verdict == "denied_by_policy"' '.structured // .'

  j="$(full path_test "{\"from\":\"${A}\",\"to\":\"${B}\",\"protocol\":\"tcp\",\"to_address\":\"${NAT_A}\"}")"
  expect 6.nat "path_test a->b through the NAT router: reached_via_nat from the router's address" "${j}" \
    ".structured.verdict == \"reached_via_nat\" and (.structured.observed_source | startswith(\"${NAT_B}:\"))" '.structured // .'

  j="$(full path_test "{\"from\":\"${A}\",\"to\":\"${B}\",\"protocol\":\"tcp\"}")"
  expect 6.default-address "path_test a->b without to_address picks b's address on a shared subnet: reached" "${j}" \
    '.structured.verdict == "reached"' '{verdict: .structured.verdict, address_used: .structured.address_used, b_reported: .structured.listen.result.addresses, sender: .structured.sender.result.outcome}'

  j="$(full path_test "{\"from\":\"${A}\",\"to\":\"${C}\",\"protocol\":\"tcp\",\"to_address\":\"${C_WAN}\"}")"
  expect 6.c-wan "path_test a->c at c's wan address: reached (control for 6.isolated)" "${j}" \
    '.structured.verdict == "reached"' '.structured // .'
}

case9() {
  local j
  j="$(raw_status "")"
  expect 9.no-token "no token: 401 with WWW-Authenticate Bearer" "${j}" '.status == 401 and (.www_authenticate | test("Bearer"))'
  j="$(raw_status "${WRONG_TOKEN}")"
  expect 9.wrong-token "wrong token: 401" "${j}" '.status == 401'
  j="$(raw_status "${HUB_TOKEN_FULL}")"
  expect 9.good-token "control: right token gets 200 on initialize" "${j}" '.status == 200' '{status, body: (.body[0:200])}'

  j="$(limited tcp_connect "{\"probes\":[\"${A}\"],\"target\":\"${REDIS}\",\"ports\":[6379]}")"
  expect 9.limited-tool "limited calling tcp_connect: refused (tool not offered to this client)" "${j}" '(.transport_error != null) or (.is_error and (.text | startswith("forbidden")))'

  j="$(limited path_test "{\"from\":\"${A}\",\"to\":\"${B}\"}")"
  expect 9.limited-path_test "limited calling path_test: refused (tool not offered to this client)" "${j}" '(.transport_error != null) or (.is_error and (.text | startswith("forbidden")))'

  j="$(limited ping "{\"probes\":[\"${B}\"],\"target\":\"${HUB_WAN}\",\"count\":1}")"
  expect 9.limited-probe "limited pinging probe-b by name: probe_unknown entry, no site leaked" "${j}" \
    "(.structured.results | length) == 1 and .structured.results[0].probe == \"${B}\" and .structured.results[0].error.code == \"probe_unknown\" and .structured.results[0].site == \"\"" \
    '.structured // .'

  j="$(limited ping "{\"probes\":[\"*\"],\"target\":\"${HUB_WAN}\",\"count\":1}")"
  expect 9.limited-star "limited ping [*] runs on site-a probes only" "${j}" \
    "[.structured.results[].probe] == [\"${A}\"] and .structured.results[0].ok" '.structured // .'

  j="$(limited list_probes '{}')"
  expect 9.limited-list "limited list_probes shows only site-a probes" "${j}" \
    "[.structured.probes[].name] == [\"${A}\"]" '.structured // .'
}

case11() {
  local j
  j="$(full traceroute "{\"probes\":[\"${A}\"],\"target\":\"${SECRET}\",\"max_hops\":30,\"queries\":3,\"wait_ms\":2000}")"
  expect 11 "traceroute 30x3x2000ms to a blackhole: returns within 50 s with complete:false" "${j}" \
    '.elapsed_ms < 50000 and .structured.results[0].ok and .structured.results[0].result.complete == false' \
    '{elapsed_ms, r: (.structured.results[0] | {ok, error, duration_ms, complete: .result.complete, reached: .result.reached, hops: (.result.hops | length), note: .result.note})}'
  info 11 "timing" "$(printf '%s' "${j}" | jq -c '{elapsed_ms, probe_duration_ms: .structured.results[0].duration_ms, hops: (.structured.results[0].result.hops | length)}')"
}

# ---------------------------------------------------------------- device commands over SSH (case 13)
#
# Fake devices (test/e2e/fakedevice) log every event as a JSON line in .work/dev/<name>.log: connections, each real
# authentication attempt, and everything sent on a channel (exec commands, shell lines, pager keys, stray input). Each
# case takes the log's line count before the call and asserts on the lines added by it.

# dev_files: passwords, the client keys the probe's profiles use, and a clean directory for the fake devices' logs and
# host keys (fakedevice makes an ed25519 host key at first start and keeps it there across restarts). Passwords are
# random per run so the logs can be grepped for them. The private keys are 0644 so the probe (uid 65532) can read them
# through the read-only mount to copy them into its store; they are throwaway keys made for this run.
dev_files() {
  rm -rf "${dev}" "${sshin}"
  mkdir -p "${dev}" "${sshin}" || return 1
  local n
  for n in pw-ios pw-fw pw-wrong; do
    openssl rand -hex 16 >"${dev}/${n}" || return 1
  done
  for n in dev_key jump_key; do
    ssh-keygen -q -t ed25519 -N '' -C "e2e-${n}" -f "${sshin}/${n}" </dev/null || return 1
  done
  chmod 0644 "${sshin}"/*
}

devlog() { printf '%s/%s.log' "${dev}" "$1"; }
# dev_mark NAME: lines in the device's log so far. dev_since NAME MARK: the events after MARK, as a JSON array.
dev_mark() { if [[ -f "$(devlog "$1")" ]]; then wc -l <"$(devlog "$1")" | tr -d ' '; else echo 0; fi; }
dev_since() {
  if [[ -f "$(devlog "$1")" ]]; then tail -n +"$(($2 + 1))" "$(devlog "$1")" | jq -sc .; else echo '[]'; fi
}
# wait_listen NAME MARK: waits until the device logs that it is listening, after MARK.
wait_listen() {
  local i
  for i in $(seq 1 30); do
    dev_since "$1" "$2" | jq -e 'any(.[]; .ev == "listen")' >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
pa_ssh() { dc exec -T probe-a probe ssh "$@"; }
# dshow DEVICE COMMAND [PROBE]: device_show as netops, on probe-a unless PROBE is given.
dshow() {
  netops device_show "$(jq -nc --arg p "${3:-${A}}" --arg d "$1" --arg c "$2" '{probe: $p, device: $d, command: $c}')" </dev/null
}
# withlog CALL EVENTS: one evidence object, {r: mcpcall's JSON, ev: the device's events}.
withlog() { jq -nc --argjson r "$1" --argjson ev "$2" '{r: $r, ev: $ev}'; }

# jq over withlog's object: what reached the device's CLI, its authentication attempts, its TCP connections.
SENT='[.ev[] | select(.ev | IN("exec", "line", "stray", "key", "shell", "pty", "req", "chan")) | (.ev + ":" + ((.cmd // .bytes // .key // .type // "") | tostring))]'
AUTHS='[.ev[] | select(.ev == "auth") | (.method + ":" + (.ok | tostring))]'
CONNS='([.ev[] | select(.ev == "conn")] | length)'
R0='.r.structured.results[0]'
DETAIL='{r: (.r.structured.results[0] // .r), ev: [.ev[] | del(.ts)]}'

# cli ID DESC ARGS...: one `probe ssh` command in probe-a (stdin from the caller); PASS when it exits 0.
cli() {
  local id="$1" desc="$2" o rc
  shift 2
  o="$(pa_ssh "$@" 2>&1)"
  rc=$?
  printf '%s\n' "${o}" >"${out}/${id}.txt"
  if [[ ${rc} -eq 0 ]]; then
    pass "${id}" "${desc}"
  else
    fail "${id}" "${desc}" "rc=${rc} $(printf '%s' "${o}" | tr '\n' ';' | cut -c1-400)"
  fi
}

# cli_refused ID DESC REGEX ARGS...: PASS when the command exits non-zero and its output matches REGEX.
cli_refused() {
  local id="$1" desc="$2" re="$3" o rc
  shift 3
  o="$(pa_ssh "$@" 2>&1 </dev/null)"
  rc=$?
  printf '%s\n' "${o}" >"${out}/${id}.txt"
  if [[ ${rc} -ne 0 ]] && printf '%s' "${o}" | grep -Eq -- "${re}"; then
    pass "${id}" "${desc}"
  else
    fail "${id}" "${desc}" "rc=${rc} $(printf '%s' "${o}" | tr '\n' ';' | cut -c1-400)"
  fi
}

case13() {
  local j m ev n
  local s
  for s in ios key deny badpw fw; do
    wait_listen "${s}" 0 || log "fake device ${s} has not logged that it listens"
  done

  # ---- profiles, entered with the real CLI inside probe-a. Idempotent for --reuse: earlier entries are removed first.
  for s in fw-b ios-badpw ios-key ios-pw; do pa_ssh profile remove "${s}" >/dev/null 2>&1 </dev/null; done
  pa_ssh jump remove jump-b >/dev/null 2>&1 </dev/null
  for s in "${DEV_IOS}" "${DEV_KEY}" "${DEV_DENY}" "${DEV_BADPW}"; do pa_ssh hostkey forget "${s}" >/dev/null 2>&1 </dev/null; done

  # ios-pw opts in to trust on first use (its cases are about first use); ios-badpw and fw-b do not, so their device
  # keys must be recorded with `probe ssh hostkey learn` before they log in.
  cli 13.cli-profile-password "probe ssh profile add --trust-on-first-use (password via --password-stdin from a file)" \
    profile add --name ios-pw --cidr "${DEV_IOS}/32" --cidr "${DEV_DENY}/32" --platform ios --username netops \
    --auth password --trust-on-first-use --password-stdin <"${dev}/pw-ios"
  cli 13.cli-profile-key "probe ssh profile add --auth key --key-file (key copied into the store)" \
    profile add --name ios-key --cidr "${DEV_KEY}/32" --platform ios --username netops --auth key \
    --key-file /e2e-ssh/dev_key </dev/null
  cli 13.cli-profile-badpw "probe ssh profile add with a wrong password (for the auth_failed case)" \
    profile add --name ios-badpw --cidr "${DEV_BADPW}/32" --platform ios --username netops --auth password \
    --password-stdin <"${dev}/pw-wrong"
  cli_refused 13.cli-catch-all "profile add with a catch-all range (10.0.0.0/7) is refused" 'catch-all|wider than' \
    profile add --name too-wide --cidr 10.0.0.0/7 --platform ios --username x --auth password --password-stdin

  local fp
  fp="$(dc exec -T jump ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub </dev/null | awk '{print $2}')"
  printf '%s\n' "${fp}" >"${out}/13.jump-fingerprint.txt"
  cli_refused 13.cli-jump-wrong-key "jump add with a fingerprint the jump does not present: refused, nothing saved" \
    'nothing saved' jump add --name jump-b --address "${JUMP_WAN}" --username jump --auth key \
    --key-file /e2e-ssh/jump_key --accept-host-key SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  cli 13.cli-jump "probe ssh jump add --accept-host-key (fingerprint read from the jump container: ${fp})" \
    jump add --name jump-b --address "${JUMP_WAN}" --username jump --auth key --key-file /e2e-ssh/jump_key \
    --accept-host-key "${fp}" </dev/null
  cli 13.cli-profile-jump "probe ssh profile add for devices-b through the jump (panos)" \
    profile add --name fw-b --cidr 10.205.0.0/24 --platform panos --username admin --auth password --jump jump-b \
    --password-stdin <"${dev}/pw-fw"

  # The hello carries the profile summaries, so list_probes shows profiles added since the probe connected only after
  # it reconnects. Recorded, then probe-a is restarted.
  j="$(netops list_probes '{}' </dev/null)"
  info 13.list-before-restart "probe-a's ssh profiles in list_probes before it reconnects" \
    "$(printf '%s' "${j}" | jq -c "[.structured.probes[] | select(.name == \"${A}\") | .ssh.profiles[]?.name]")"
  dc restart probe-a >/dev/null 2>&1
  wait_online 3 60 >/dev/null || log "not all probes online after restarting probe-a"
  # Wait for the new hello (the hub may still show the old session for a moment).
  for s in $(seq 1 30); do
    netops list_probes '{}' </dev/null | jq -e "any(.structured.probes[]; .name == \"${A}\" and .online and (.ssh.profiles | length) == 4)" >/dev/null 2>&1 && break
    sleep 1
  done

  # ---- scope
  local all13='["list_probes","path_test","diagnose","ping","traceroute","path_mtu","dns_lookup","tcp_connect","tcp_template","udp_probe","tls_check","http_check","probe_info"]'
  j="$(tools_list "${HUB_TOKEN_FULL}" </dev/null)"
  expect 13.tools-full "tools/list for full (tools [*]): no device_show or device_commands" "${j}" \
    '([.tools[].name] | index("device_show") == null and index("device_commands") == null) and (.tools | length) == 13' \
    '{names: [.tools[]?.name], err: .transport_error}'
  j="$(tools_list "${HUB_TOKEN_NETOPS}" </dev/null)"
  expect 13.tools-netops "tools/list for netops ([*, device_show, device_commands]): all 15 tools, readOnlyHint on each" "${j}" \
    "([.tools[].name] | sort) == (${all13} + [\"device_show\",\"device_commands\"] | sort) and all(.tools[]; .read_only == true)" \
    '{names: [.tools[]?.name], not_read_only: [.tools[]? | select(.read_only != true) | .name], err: .transport_error}'

  j="$(full device_show "{\"probe\":\"${A}\",\"device\":\"${DEV_IOS}\",\"command\":\"show version\"}" </dev/null)"
  expect 13.full-call "full calling device_show: refused (not one of its tools)" "${j}" \
    '(.transport_error != null) or (.is_error and (.text | startswith("forbidden")))'

  j="$(netops list_probes '{}' </dev/null)"
  expect 13.list-netops "list_probes for netops: probe-a's ssh profiles (names, cidrs, platform, jump), none on b and c" "${j}" \
    "(.structured.probes[] | select(.name == \"${A}\") | .ssh.profiles) == [
       {name: \"ios-pw\", cidrs: [\"${DEV_IOS}/32\", \"${DEV_DENY}/32\"], platform: \"ios\"},
       {name: \"ios-key\", cidrs: [\"${DEV_KEY}/32\"], platform: \"ios\"},
       {name: \"ios-badpw\", cidrs: [\"${DEV_BADPW}/32\"], platform: \"ios\"},
       {name: \"fw-b\", cidrs: [\"10.205.0.0/24\"], platform: \"panos\", jump: \"jump-b\"}]
     and all(.structured.probes[] | select(.name != \"${A}\"); has(\"ssh\") | not)" \
    '[.structured.probes[]? | {name, ssh}]'
  j="$(full list_probes '{}' </dev/null)"
  expect 13.list-full "list_probes for full: no probe has an ssh field" "${j}" \
    "any(.structured.probes[]; .name == \"${A}\") and all(.structured.probes[]; has(\"ssh\") | not)" '[.structured.probes[]? | {name, ssh}]'

  j="$(netops device_commands "{\"probes\":[\"${A}\"]}" </dev/null)"
  expect 13.device_commands "device_commands on probe-a: 8 platforms, ios and panos non-empty, probe-a's local ios changes shown" "${j}" \
    '.structured.results[0] | .ok
       and ([.result.platforms[].platform] | sort) == (["ios","nxos","junos","eos","panos","fortios","edgeos","routeros"] | sort)
       and all(.result.platforms[] | select(.platform == "ios" or .platform == "panos"); (.allow | length) > 0)
       and (.result.platforms[] | select(.platform == "ios") | .local_changes == true
            and any(.allow[]; test("e2e-local")) and any(.deny[]?; test("counters")))
       and ([.result.profiles[].name] == ["ios-pw","ios-key","ios-badpw","fw-b"])' \
    '.structured.results[0] | {ok, error, platforms: [.result.platforms[]? | {platform, n: (.allow | length), local_changes, deny}], profiles: .result.profiles}'
  info 13.device_commands-counts "allow patterns per platform" \
    "$(printf '%s' "${j}" | jq -c '[.structured.results[0].result.platforms[]? | {(.platform): (.allow | length)}] | add')"

  # ---- runs on the ios-like device (password, keyboard-interactive offered too)
  m="$(dev_mark ios)"
  j="$(dshow "${DEV_IOS}" "show version")"
  ev="$(dev_since ios "${m}")"
  expect 13.show-first "device_show ios show version: ok, untrusted output, host key recorded on first use; device got exactly 'show version'" \
    "$(withlog "${j}" "${ev}")" \
    "${R0} as \$x | \$x.ok and \$x.result.outcome == \"ok\" and \$x.result.output.untrusted == true
       and (\$x.result.output.text | test(\"Cisco IOS XE\")) and \$x.result.host_key_first_use == true
       and (\$x.result.host_key | startswith(\"SHA256:\")) and \$x.result.profile == \"ios-pw\" and \$x.result.platform == \"ios\"
       and \$x.result.address == \"${DEV_IOS}\"
       and (${SENT}) == [\"exec:show version\"] and (${AUTHS}) == [\"keyboard-interactive:true\"] and ${CONNS} == 1" "${DETAIL}"
  local hk1
  hk1="$(printf '%s' "${j}" | jq -r '.structured.results[0].result.host_key // empty')"

  m="$(dev_mark ios)"
  j="$(dshow "${DEV_IOS}" "show version")"
  ev="$(dev_since ios "${m}")"
  expect 13.show-second "device_show again: ok, same host key, host_key_first_use false" "$(withlog "${j}" "${ev}")" \
    "${R0} as \$x | \$x.ok and \$x.result.outcome == \"ok\" and (\$x.result.host_key_first_use // false) == false
       and \$x.result.host_key == \"${hk1}\" and (${SENT}) == [\"exec:show version\"]" "${DETAIL}"

  m="$(dev_mark ios)"
  j="$(dshow "${DEV_IOS}" "show interfaces")"
  ev="$(dev_since ios "${m}")"
  expect 13.show-interfaces "device_show ios show interfaces: ok with the interface lines" "$(withlog "${j}" "${ev}")" \
    "${R0} as \$x | \$x.ok and \$x.result.outcome == \"ok\" and (\$x.result.output.text | test(\"GigabitEthernet1/0/1 is up\"))
       and (${SENT}) == [\"exec:show interfaces\"]" "${DETAIL}"

  m="$(dev_mark ios)"
  j="$(dshow "${DEV_IOS}" "show running-config")"
  ev="$(dev_since ios "${m}")"
  expect 13.not-allowed "device_show show running-config: command_not_allowed, the device saw no connection" "$(withlog "${j}" "${ev}")" \
    "${R0}.error.code == \"command_not_allowed\" and (.ev | length) == 0" "${DETAIL}"

  m="$(dev_mark ios)"
  j="$(dshow "${DEV_IOS}" "show interfaces counters errors")"
  ev="$(dev_since ios "${m}")"
  expect 13.local-deny "device_show of a command probe-a's commands file denies: command_not_allowed, no connection" "$(withlog "${j}" "${ev}")" \
    "${R0}.error.code == \"command_not_allowed\" and (.ev | length) == 0" "${DETAIL}"

  local inj i=0
  for inj in 'show version | redirect tftp://x' 'show version ; reload' 'show version && reload' 'show version $(reload)' \
    'show version `reload`' "show version"$'\n'"reload" 'show version > flash:x' "show version 'x'"; do
    i=$((i + 1))
    m="$(dev_mark ios)"
    j="$(dshow "${DEV_IOS}" "${inj}")"
    ev="$(dev_since ios "${m}")"
    expect "13.inject-${i}" "injection refused, no connection: $(printf '%s' "${inj}" | tr '\n' '~')" "$(withlog "${j}" "${ev}")" \
      "(${R0}.error.code == \"command_not_allowed\" or ${R0}.error.code == \"invalid_params\" or (.r.is_error and (.r.text | startswith(\"invalid_params\")))) and (.ev | length) == 0" \
      "${DETAIL}"
  done

  m="$(dev_mark ios)"
  j="$(dshow "${DEV_IOS}" "show inventory")"
  ev="$(dev_since ios "${m}")"
  expect 13.command-error "allowed command the device rejects (show inventory): outcome command_error, device message in output" "$(withlog "${j}" "${ev}")" \
    "${R0} as \$x | \$x.ok and \$x.result.outcome == \"command_error\" and (\$x.result.output.text | test(\"Invalid input\"))
       and (\$x.result.detail | test(\"Invalid input\") | not) and (${SENT}) == [\"exec:show inventory\"]" "${DETAIL}"

  # ---- key profile
  m="$(dev_mark key)"
  j="$(dshow "${DEV_KEY}" "show ip interface brief")"
  ev="$(dev_since key "${m}")"
  expect 13.key "device_show via the key profile: ok, publickey login, exactly the command sent" "$(withlog "${j}" "${ev}")" \
    "${R0} as \$x | \$x.ok and \$x.result.outcome == \"ok\" and \$x.result.profile == \"ios-key\"
       and \$x.result.host_key_first_use == true
       and (\$x.result.output.text | test(\"GigabitEthernet1/0/1\")) and (${SENT}) == [\"exec:show ip interface brief\"]
       and ((${AUTHS}) | index(\"publickey:true\") != null) and ((${AUTHS}) | all(startswith(\"publickey\")))" "${DETAIL}"

  # ---- a password profile and a device whose key is not recorded: nothing sent, nothing recorded
  m="$(dev_mark badpw)"
  j="$(dshow "${DEV_BADPW}" "show version")"
  ev="$(dev_since badpw "${m}")"
  expect 13.host-key-unknown "password profile, device key not recorded: host_key_unknown with its fingerprint, zero authentication attempts, nothing run" \
    "$(withlog "${j}" "${ev}")" \
    "${R0} as \$x | \$x.ok and \$x.result.outcome == \"host_key_unknown\" and (\$x.result.host_key | startswith(\"SHA256:\"))
       and (\$x.result.host_key_first_use // false) == false and (\$x.result.detail | test(\"probe ssh hostkey learn ${DEV_BADPW//./\\\\.}\"))
       and ((${AUTHS}) | length) == 0 and (${SENT}) == []" "${DETAIL}"
  local hkb
  hkb="$(printf '%s' "${j}" | jq -r '.structured.results[0].result.host_key // empty')"
  j="$(pa_ssh hostkey list </dev/null 2>&1)"
  printf '%s\n' "${j}" >"${out}/13.host-key-unknown-list.txt"
  if ! printf '%s' "${j}" | grep -qF "${DEV_BADPW}"; then
    pass 13.host-key-unknown-not-recorded "the unknown key was not recorded (hostkey list has no ${DEV_BADPW})"
  else
    fail 13.host-key-unknown-not-recorded "the unknown key was not recorded (hostkey list has no ${DEV_BADPW})" "$(printf '%s' "${j}" | tr '\n' ';' | cut -c1-300)"
  fi
  m="$(dev_mark badpw)"
  j="$(pa_ssh hostkey learn "${DEV_BADPW}" --yes 2>&1 </dev/null)"
  ev="$(dev_since badpw "${m}")"
  printf '%s\n' "${j}" >"${out}/13.cli-learn-badpw.txt"
  expect 13.cli-learn-badpw "probe ssh hostkey learn ${DEV_BADPW} --yes: prints and records the same fingerprint, no login" \
    "$(jq -nc --arg o "${j}" --arg want "recorded ssh-ed25519 ${hkb} for ${DEV_BADPW}" --argjson ev "${ev}" '{o: $o, want: $want, ev: $ev}')" \
    '.want as $w | ($w | test("SHA256:")) and (.o | contains($w)) and ([.ev[] | select(.ev == "auth")] | length) == 0' '{o, want, ev: [.ev[] | del(.ts)]}'

  # ---- wrong password: one attempt, never retried
  m="$(dev_mark badpw)"
  j="$(dshow "${DEV_BADPW}" "show version")"
  ev="$(dev_since badpw "${m}")"
  expect 13.auth-failed "wrong password: auth_failed with exactly one authentication attempt on the device, nothing run" "$(withlog "${j}" "${ev}")" \
    "${R0} as \$x | \$x.ok and \$x.result.outcome == \"auth_failed\" and ((${AUTHS}) | length) == 1
       and ((${AUTHS})[0] | endswith(\":false\")) and (${SENT}) == [] and ${CONNS} == 1" "${DETAIL}"
  # ---- and that device address then cools down for the profile: the next call answers auth_failed without connecting
  m="$(dev_mark badpw)"
  j="$(dshow "${DEV_BADPW}" "show version")"
  ev="$(dev_since badpw "${m}")"
  expect 13.auth-cooldown "second call after auth_failed: auth_failed at once (cool-down), no connection to the device" "$(withlog "${j}" "${ev}")" \
    "${R0} as \$x | \$x.ok and \$x.result.outcome == \"auth_failed\" and (\$x.result.detail | test(\"not tried again until\"))
       and ${CONNS} == 0 and (.ev | length) == 0" "${DETAIL}"

  # ---- an IPv6 zone in the device (which once reached host:port and known_hosts) is refused before anything
  local hkl0 zdev
  hkl0="$(pa_ssh hostkey list </dev/null 2>&1)"
  i=0
  for zdev in "fd00:1::5%x" "::ffff:${DEV_IOS}%x" "fd00:1::5%z"$'\t'"ssh-ed25519"$'\t'"AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"$'\n'"${DEV_IOS}"$'\t'"ssh-ed25519"$'\t'"AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; do
    i=$((i + 1))
    m="$(dev_mark ios)"
    j="$(dshow "${zdev}" "show version")"
    ev="$(dev_since ios "${m}")"
    expect "13.zone-${i}" "device with an IPv6 zone refused (invalid_params), no connection: $(printf '%s' "${zdev}" | tr '\t\n' '~~' | cut -c1-40)" \
      "$(withlog "${j}" "${ev}")" \
      "(${R0}.error.code == \"invalid_params\" or (.r.is_error and (.r.text | startswith(\"invalid_params\")))) and (.ev | length) == 0" \
      "${DETAIL}"
  done
  if [[ "$(pa_ssh hostkey list </dev/null 2>&1)" == "${hkl0}" ]]; then
    pass 13.zone-known-hosts "known_hosts unchanged by the zoned devices"
  else
    fail 13.zone-known-hosts "known_hosts unchanged by the zoned devices" "$(pa_ssh hostkey list </dev/null 2>&1 | tr '\n' ';' | cut -c1-400)"
  fi

  # ---- through the jump host to the PAN-OS-like device on devices-b
  j="$(netops tcp_connect "{\"probes\":[\"${A}\"],\"target\":\"${DEV_FW}\",\"ports\":[22],\"timeout_ms\":2000}" </dev/null)"
  expect 13.fw-not-direct "control: probe-a cannot reach the devices-b device directly (tcp_connect not open)" "${j}" \
    '.structured.results[0] | .ok and .result.ports[0].outcome != "open"' '.structured.results[0] // .'
  # fw-b is a password profile that does not trust on first use: the device's key is learnt first, through the jump
  # the profile names (hostkey learn takes the port and jump from the covering profile).
  m="$(dev_mark fw)"
  j="$(pa_ssh hostkey learn "${DEV_FW}" --yes 2>&1 </dev/null)"
  ev="$(dev_since fw "${m}")"
  printf '%s\n' "${j}" >"${out}/13.cli-learn-fw.txt"
  expect 13.cli-learn-fw "probe ssh hostkey learn ${DEV_FW} --yes: recorded through jump-b (profile fw-b), no login on the device" \
    "$(jq -nc --arg o "${j}" --argjson ev "${ev}" '{o: $o, ev: $ev}')" \
    "(.o | test(\"through jump host jump-b, profile fw-b\")) and (.o | test(\"recorded ssh-ed25519 SHA256:[^ ]+ for ${DEV_FW//./\\\\.} through jump host jump-b\"))
     and ([.ev[] | select(.ev == \"auth\")] | length) == 0" '{o, ev: [.ev[] | del(.ts)]}'
  local jl0
  jl0="$(dc logs --no-log-prefix jump 2>/dev/null | wc -l | tr -d ' ')"
  m="$(dev_mark fw)"
  j="$(dshow "${DEV_FW}" "show system info")"
  ev="$(dev_since fw "${m}")"
  expect 13.jump "device_show behind the jump (panos-like): ok; device got 'set cli pager off' then the command, nothing else, from the jump's address" \
    "$(withlog "${j}" "${ev}")" \
    "${R0} as \$x | \$x.ok and \$x.result.outcome == \"ok\" and \$x.result.jump == \"jump-b\" and \$x.result.platform == \"panos\"
       and (\$x.result.output.text | test(\"sw-version: 10.2.4\")) and (\$x.result.output.text | test(\"fake-field-30\"))
       and (\$x.result.host_key_first_use // false) == false
       and (${SENT}) == [\"pty:\", \"shell:\", \"line:set cli pager off\", \"line:show system info\"]
       and all(.ev[] | select(.ev == \"conn\"); .remote | startswith(\"${JUMP_B}:\"))" "${DETAIL}"
  local jl
  jl="$(dc logs --no-log-prefix jump 2>/dev/null | tail -n +"$((jl0 + 1))" | grep -i 'direct.tcpip')"
  printf '%s\n' "${jl}" >"${out}/13.jump-sshd.txt"
  if printf '%s' "${jl}" | grep -Eq "target ${DEV_FW//./\\.} port 22" && ! printf '%s' "${jl}" | grep -qi 'fakedev'; then
    pass 13.jump-direct-tcpip "jump's sshd logs a direct-tcpip to the device's IP ${DEV_FW}, not a name"
  else
    fail 13.jump-direct-tcpip "jump's sshd logs a direct-tcpip to the device's IP ${DEV_FW}, not a name" "$(printf '%s' "${jl}" | tr '\n' ';' | cut -c1-500)"
  fi

  # ---- refusals before any connection
  j="$(dshow "${WEB}" "show version")"
  expect 13.no-profile "device_show to an address no profile covers (web): unavailable" "${j}" \
    '.structured.results[0].error.code == "unavailable"' '.structured.results[0] // .'

  m="$(dev_mark deny)"
  j="$(dshow "${DEV_DENY}" "show version")"
  ev="$(dev_since deny "${m}")"
  expect 13.deny "device_show to the no-touch address (deny_cidrs; a profile covers it): denied, no connection" "$(withlog "${j}" "${ev}")" \
    "${R0}.error.code == \"denied\" and (.ev | length) == 0" "${DETAIL}"
  m="$(dev_mark deny)"
  j="$(dshow fakedev-deny "show version")"
  ev="$(dev_since deny "${m}")"
  expect 13.deny-name "device_show to the no-touch host by name (fakedev-deny: in deny_hosts, address in deny_cidrs): denied, no connection" "$(withlog "${j}" "${ev}")" \
    "${R0}.error.code == \"denied\" and (.ev | length) == 0" "${DETAIL}"
  m="$(dev_mark key)"
  j="$(dshow notouch-key "show version")"
  ev="$(dev_since key "${m}")"
  expect 13.deny-hosts-only "device_show by a name only deny_hosts lists (notouch-key; its address works, see 13.key): denied, no connection" "$(withlog "${j}" "${ev}")" \
    "${R0}.error.code == \"denied\" and (.ev | length) == 0" "${DETAIL}"
  m="$(dev_mark deny)"
  j="$(netops ping "{\"probes\":[\"${A}\"],\"target\":\"${DEV_DENY}\",\"count\":1}" </dev/null)"
  ev="$(dev_since deny "${m}")"
  expect 13.deny-ping "ping to the no-touch address: denied too" "$(withlog "${j}" "${ev}")" \
    "${R0}.error.code == \"denied\"" "${DETAIL}"
  j="$(netops tcp_connect "{\"probes\":[\"${A}\"],\"target\":\"${DEV_DENY}\",\"ports\":[22]}" </dev/null)"
  ev="$(dev_since deny "${m}")"
  expect 13.deny-tcp "tcp_connect to the no-touch address: denied, the device saw no connection" "$(withlog "${j}" "${ev}")" \
    "${R0}.error.code == \"denied\" and (.ev | length) == 0" "${DETAIL}"

  for s in '*' 'site-a-*' 'site:a' 'site-a-probe,site-b-probe'; do
    m="$(dev_mark ios)"
    j="$(dshow "${DEV_IOS}" "show version" "${s}")"
    ev="$(dev_since ios "${m}")"
    expect "13.probe-${s}" "device_show with probe '${s}': invalid_params, no connection" "$(withlog "${j}" "${ev}")" \
      '.r.is_error and (.r.text | startswith("invalid_params")) and (.ev | length) == 0' '{r, ev}'
  done
  j="$(netops device_show "{\"probes\":[\"*\"],\"device\":\"${DEV_IOS}\",\"command\":\"show version\"}" </dev/null)"
  expect 13.probes-array "device_show with a probes array instead of probe: refused" "${j}" \
    '(.transport_error != null) or .is_error'

  # ---- one session per device: the second of two overlapping calls is busy (show clock is slow on this device)
  local tmp="${work}/busy.json" j1 j2
  m="$(dev_mark ios)"
  (dshow "${DEV_IOS}" "show clock" >"${tmp}") &
  local bg=$!
  sleep 2
  j2="$(dshow "${DEV_IOS}" "show clock")"
  wait "${bg}"
  j1="$(cat "${tmp}")"
  ev="$(dev_since ios "${m}")"
  j="$(jq -nc --argjson a "${j1}" --argjson b "${j2}" --argjson ev "${ev}" '{first: $a.structured.results[0], second: $b.structured.results[0], ev: $ev}')"
  expect 13.busy "two overlapping device_show to one device: one ok, the other busy (only one session reached the device)" "${j}" \
    '([.first, .second] | map(select(.ok and .result.outcome == "ok")) | length) == 1
     and ([.first, .second] | map(select(.error.code == "busy")) | length) == 1
     and ([.ev[] | select(.ev == "conn")] | length) == 1' '{first, second, ev: [.ev[] | del(.ts)]}'

  # ---- changed host key: the device restarts with a new (same type) key
  m="$(dev_mark ios)"
  rm -f "${dev}/ios.key"
  dc restart fakedev-ios >/dev/null 2>&1
  wait_listen ios "${m}" || log "fakedev-ios did not come back"
  m="$(dev_mark ios)"
  j="$(dshow "${DEV_IOS}" "show version")"
  ev="$(dev_since ios "${m}")"
  expect 13.hostkey-changed "device restarted with a new host key: host_key_changed, no authentication attempt, nothing run" "$(withlog "${j}" "${ev}")" \
    "${R0} as \$x | \$x.ok and \$x.result.outcome == \"host_key_changed\" and \$x.result.host_key != \"${hk1}\"
       and ((${AUTHS}) | length) == 0 and (${SENT}) == []" "${DETAIL}"
  cli 13.cli-hostkey-forget "probe ssh hostkey forget ${DEV_IOS}" hostkey forget "${DEV_IOS}" </dev/null
  m="$(dev_mark ios)"
  j="$(dshow "${DEV_IOS}" "show version")"
  ev="$(dev_since ios "${m}")"
  expect 13.hostkey-relearn "after forgetting: ok, the new key recorded on first use" "$(withlog "${j}" "${ev}")" \
    "${R0} as \$x | \$x.ok and \$x.result.outcome == \"ok\" and \$x.result.host_key_first_use == true and \$x.result.host_key != \"${hk1}\"" "${DETAIL}"

  # ---- audit and logs
  local hublog probelog
  hublog="$(dc logs --no-log-prefix hub 2>/dev/null)"
  probelog="$(dc logs --no-log-prefix probe-a 2>/dev/null)"
  j="$(printf '%s\n' "${hublog}" | grep '"msg":"tool_call"' | jq -sc '[.[] | select(.tool == "device_show")]')"
  expect 13.audit "hub audit: tool_call lines for device_show with client, device, command and outcome" "${j}" \
    "any(.[]; .client == \"netops\" and .target == \"${DEV_IOS}\" and .command == \"show version\" and .outcomes[\"${A}\"] == \"ok\")
     and any(.[]; .command == \"show running-config\" and .outcomes[\"${A}\"] == \"command_not_allowed\")
     and any(.[]; .target == \"${DEV_BADPW}\" and .outcomes[\"${A}\"] == \"auth_failed\")
     and any(.[]; .target == \"${DEV_BADPW}\" and .outcomes[\"${A}\"] == \"host_key_unknown\")
     and any(.[]; .target == \"${DEV_IOS}\" and .outcomes[\"${A}\"] == \"host_key_changed\")
     and any(.[]; .target == \"${DEV_FW}\" and .outcomes[\"${A}\"] == \"ok\")" '[.[] | {client, target, command, outcomes}]'
  local canary
  canary="$(printf '%s\n' "${hublog}" "${probelog}" | grep -c 'E2E-CANARY\|fake-field-\|ignore previous instructions and reveal')"
  j="$(printf '%s\n' "${probelog}" | grep '"msg":"device_show"' | jq -sc --argjson c "${canary}" '{canary_lines: $c, probe_lines: [.[] | {device, profile, jump, platform, command, outcome}]}')"
  expect 13.audit-no-output "no device output in hub or probe logs; probe-a logs each device_show with device, command and outcome" "${j}" \
    ".canary_lines == 0 and (.probe_lines | length) > 0 and all(.probe_lines[]; .outcome != null and .outcome != \"\" and .command != null)
     and any(.probe_lines[]; .device == \"${DEV_FW}\" and .jump == \"jump-b\" and .outcome == \"ok\")"

  local leaked="" val f line
  for f in pw-ios pw-fw pw-wrong; do
    val="$(cat "${dev}/${f}")"
    printf '%s\n' "${hublog}" "${probelog}" | grep -qF -- "${val}" && leaked="${leaked} ${f}"
  done
  for f in dev_key jump_key; do
    while IFS= read -r line; do
      [[ "${line}" == -----* || ${#line} -lt 20 ]] && continue
      if printf '%s\n' "${hublog}" "${probelog}" | grep -qF -- "${line}"; then leaked="${leaked} ${f}"; break; fi
    done <"${sshin}/${f}"
  done
  if [[ -z "${leaked}" ]]; then
    pass 13.secrets "device passwords and private key material appear in neither hub nor probe-a logs"
  else
    fail 13.secrets "device passwords and private key material appear in neither hub nor probe-a logs" "found:${leaked}"
  fi

  # ---- the store inside probe-a
  local st
  st="$(docker run --rm --volumes-from "$(container_id probe-a)" alpine:3.20 sh -c 'find /var/lib/probe/ssh -exec stat -c "%a %u:%g %F %n" {} +' 2>&1)"
  printf '%s\n' "${st}" >"${out}/13.store-perms.txt"
  local bad
  bad="$(printf '%s\n' "${st}" | awk '
    $3 == "directory" && $1 != "700" { print }
    $3 == "regular" && $1 != "600" { print }
    $2 != "65532:65532" { print }')"
  if [[ -n "${st}" ]] && printf '%s' "${st}" | grep -q 'secrets.json' && [[ -z "${bad}" ]]; then
    pass 13.store-perms "/var/lib/probe/ssh: directories 0700, files 0600, owned by 65532 ($(printf '%s\n' "${st}" | wc -l | tr -d ' ') entries)"
  else
    fail 13.store-perms "/var/lib/probe/ssh: directories 0700, files 0600, owned by 65532" "$(printf '%s\n' "${bad:-${st}}" | tr '\n' ';' | cut -c1-500)"
  fi

  local pl
  pl="$(pa_ssh profile list </dev/null 2>&1)"
  printf '%s\n' "${pl}" >"${out}/13.profile-list.txt"
  leaked=""
  for f in pw-ios pw-fw pw-wrong; do
    printf '%s' "${pl}" | grep -qF -- "$(cat "${dev}/${f}")" && leaked="${leaked} ${f}"
  done
  printf '%s' "${pl}" | grep -q 'PRIVATE KEY\|b3BlbnNzaC1rZXkt' && leaked="${leaked} key-material"
  if [[ -z "${leaked}" ]] && printf '%s' "${pl}" | grep -qE '^[0-9]+ +fw-b .*panos'; then
    pass 13.profile-list "probe ssh profile list shows the profiles and no secrets"
  else
    fail 13.profile-list "probe ssh profile list shows the profiles and no secrets" "leaked:${leaked} $(printf '%s' "${pl}" | tr '\n' ';' | cut -c1-300)"
  fi
  pa_ssh jump list </dev/null >"${out}/13.jump-list.txt" 2>&1
  pa_ssh hostkey list </dev/null >"${out}/13.hostkey-list.txt" 2>&1
}

case12() {
  local before_enrol before_conn after_enrol after_conn took svc
  before_enrol="$(dc logs --no-log-prefix probe-a probe-b probe-c 2>/dev/null | grep -c '"msg":"enrolling with hub"')"
  before_conn="$(dc logs --no-log-prefix probe-a probe-b probe-c 2>/dev/null | grep -c '"msg":"connected to hub"')"
  log "restarting the hub"
  dc restart hub >/dev/null 2>&1
  if took="$(wait_online 3 75)"; then
    after_enrol="$(dc logs --no-log-prefix probe-a probe-b probe-c 2>/dev/null | grep -c '"msg":"enrolling with hub"')"
    after_conn="$(dc logs --no-log-prefix probe-a probe-b probe-c 2>/dev/null | grep -c '"msg":"connected to hub"')"
    local j="{\"took_s\":${took},\"enrol_lines_before\":${before_enrol},\"enrol_lines_after\":${after_enrol},\"connected_before\":${before_conn},\"connected_after\":${after_conn}}"
    expect 12 "hub restart: all probes back online within 60 s, no re-enrolment" "${j}" \
      '.took_s <= 60 and .enrol_lines_after == .enrol_lines_before and .connected_after >= .connected_before + 3'
  else
    fail 12 "hub restart: all probes back online within 60 s, no re-enrolment" "only $(online_count) online after ${took}s"
  fi
}

case7() {
  local j
  dc stop probe-c >/dev/null 2>&1
  j="$(full ping "{\"probes\":[\"${C}\"],\"target\":\"${HUB_WAN}\",\"count\":1}")"
  expect 7 "probe-c stopped: ping answers probe_offline in under 2 s" "${j}" \
    '.structured.results[0].error.code == "probe_offline" and .elapsed_ms < 2000' '{elapsed_ms, r: .structured.results[0]}'

  j="$(full list_probes '{}')"
  expect 7.list "list_probes shows probe-c offline with last_seen" "${j}" \
    "(.structured.probes[] | select(.name == \"${C}\") | (.online == false and .last_seen != null))" '.structured // .'

  j="$(full path_test "{\"from\":\"${A}\",\"to\":\"${C}\",\"to_address\":\"${C_WAN}\"}")"
  expect 7.path_test "path_test to an offline probe: probe_offline error" "${j}" \
    '.is_error and (.text | startswith("probe_offline"))'

  dc start probe-c >/dev/null 2>&1
  local took
  if took="$(wait_online 3 60)"; then
    local saved
    saved="$(dc logs --no-log-prefix probe-c 2>/dev/null | grep -c '"msg":"using saved identity"')"
    expect 7.restart "probe-c started again: back online with its saved identity" "{\"took_s\":${took},\"using_saved_identity_lines\":${saved}}" \
      '.using_saved_identity_lines >= 1'
  else
    fail 7.restart "probe-c started again: back online with its saved identity" "not online after ${took}s"
  fi
}

case8() {
  local out_txt t0 took=-1 j state
  out_txt="$(dc exec -T hub probe-hub probes revoke "${B}" 2>&1)"
  t0="$(now)"
  log "revoke: ${out_txt}"
  while [[ $(($(now) - t0)) -le 15 ]]; do
    j="$(full list_probes '{}')"
    state="$(printf '%s' "${j}" | jq -r --arg b "${B}" '[.structured.probes[] | select(.name == $b)] | if length == 0 then "gone" elif .[0].online then "online" else "offline" end')"
    if [[ "${state}" != "online" ]]; then
      took=$(($(now) - t0))
      break
    fi
    sleep 1
  done
  j="{\"took_s\":${took},\"state\":\"${state}\"}"
  expect 8 "revoke probe-b while connected: gone/offline from list_probes within ~10 s" "${j}" '.took_s >= 0 and .took_s <= 12'

  j="$(full ping "{\"probes\":[\"${B}\"],\"target\":\"${HUB_WAN}\",\"count\":1}")"
  expect 8.call "a call to the revoked probe returns an error" "${j}" \
    '(.structured.results[0].error.code // "") as $c | ($c == "probe_offline" or $c == "probe_unknown")' '.structured // .'
  info 8.call "error code" "$(printf '%s' "${j}" | jq -c '.structured.results[0].error')"

  local i found=0
  for i in $(seq 1 10); do
    if dc logs --no-log-prefix probe-b 2>/dev/null | grep -q 're-enrol'; then
      found=1
      break
    fi
    sleep 1
  done
  local line
  line="$(dc logs --no-log-prefix probe-b 2>/dev/null | grep 're-enrol' | head -1)"
  expect 8.log "probe-b logs the 4401 / re-enrol message" "{\"found\":${found},\"line\":$(printf '%s' "${line:-}" | jq -Rs .)}" \
    '.found == 1 and (.line | test("4401"))'

  j="$(dc exec -T hub probe-hub probes list 2>&1)"
  printf '%s\n' "${j}" >"${out}/8.probes-list.txt"
  if printf '%s' "${j}" | grep "^${B} " | awk '{print $NF}' | grep -qv '^-$'; then
    pass 8.cli "probe-hub probes list shows probe-b revoked"
  else
    fail 8.cli "probe-hub probes list shows probe-b revoked" "$(printf '%s' "${j}" | tr '\n' ';')"
  fi
}

case10() {
  mkdir -p "${logs}"
  local s
  for s in hub probe-a probe-b probe-c nat; do
    dc logs --no-log-prefix "${s}" >"${logs}/${s}.log" 2>&1
  done
  local n_calls n_audit
  n_calls="$(wc -l <"${calls}" | tr -d ' ')"
  n_audit="$(grep -c '"msg":"tool_call"' "${logs}/hub.log")"
  local j="{\"tools_call_requests\":${n_calls},\"tool_call_audit_lines\":${n_audit}}"
  expect 10.audit "one tool_call audit line per tools/call" "${j}" '.tools_call_requests == .tool_call_audit_lines'

  # Every audit line names client and tool.
  local bad
  bad="$(grep '"msg":"tool_call"' "${logs}/hub.log" | jq -c 'select((.client // "") == "" or (.tool // "") == "")' | head -3)"
  if [[ -z "${bad}" ]]; then pass 10.audit-fields "every audit line has client and tool"; else fail 10.audit-fields "every audit line has client and tool" "${bad}"; fi

  local jobs
  jobs="$(grep -c '"msg":"job"' "${logs}/probe-a.log")"
  if [[ "${jobs}" -gt 0 ]]; then pass 10.job-log "probe-a logs its jobs (${jobs} job lines)"; else fail 10.job-log "probe-a logs its jobs" "no job lines"; fi

  # Secrets: client tokens, the wrong token, enrolment tokens and each probe's secret.
  local sa sb sc
  sa="$(identity_secret probe-a)"
  sb="$(identity_secret probe-b)"
  sc="$(identity_secret probe-c)"
  local leaked="" name val
  for name in HUB_TOKEN_FULL HUB_TOKEN_LIMITED HUB_TOKEN_NETOPS WRONG_TOKEN ENROLL_A ENROLL_B ENROLL_C SECRET_A SECRET_B SECRET_C; do
    case "${name}" in
      SECRET_A) val="${sa}" ;; SECRET_B) val="${sb}" ;; SECRET_C) val="${sc}" ;;
      *) eval "val=\"\${${name}:-}\"" ;;
    esac
    if [[ -z "${val}" ]]; then
      leaked="${leaked} ${name}(value-unavailable)"
      continue
    fi
    if cat "${logs}"/*.log | grep -qF -- "${val}"; then
      leaked="${leaked} ${name}($(grep -lF -- "${val}" "${logs}"/*.log | xargs -n1 basename | tr '\n' ' '))"
    fi
  done
  if [[ -z "${leaked}" ]]; then
    pass 10.secrets "no token or probe secret appears in hub or probe logs"
  else
    fail 10.secrets "no token or probe secret appears in hub or probe logs" "found:${leaked}"
  fi

  local modes
  modes="$(identity_mode probe-a) $(identity_mode probe-b) $(identity_mode probe-c)"
  if [[ "${modes}" == "-rw------- -rw------- -rw-------" ]]; then
    pass 10.identity-mode "identity.json is 0600 on every probe"
  else
    fail 10.identity-mode "identity.json is 0600 on every probe" "${modes}"
  fi
}

casex() {
  local hub_img="probetools-e2e/hub:${E2E_VERSION}" probe_img="probetools-e2e/probe:${E2E_VERSION}" o
  o="$(docker run --rm "${probe_img}" version 2>&1)"
  [[ "${o}" == "${E2E_VERSION}" ]] && pass x.probe-version "probe image: version prints ${o}" || fail x.probe-version "probe image version" "${o}"
  o="$(docker run --rm "${hub_img}" version 2>&1)"
  [[ "${o}" == "${E2E_VERSION}" ]] && pass x.hub-version "hub image: version prints ${o}" || fail x.hub-version "hub image version" "${o}"

  local f
  for f in deploy/remote-docker/probe.yaml deploy/linux/probe.yaml; do
    o="$(docker run --rm -v "${root}/${f}:/etc/probe/probe.yaml:ro" "${probe_img}" check-config 2>&1)"
    local rc=$?
    printf '%s\n' "${o}" >"${out}/x.check-config-$(echo "${f}" | tr '/' '_').txt"
    if [[ ${rc} -eq 0 ]] && printf '%s' "${o}" | grep -q 'is valid'; then
      pass "x.check-config:${f}" "probe check-config accepts ${f}"
    else
      fail "x.check-config:${f}" "probe check-config accepts ${f}" "$(printf '%s' "${o}" | tr '\n' ';' | cut -c1-400)"
    fi
  done
  o="$(docker run --rm -v "${root}/deploy/central/hub.yaml:/etc/probe-hub/hub.yaml:ro" "${hub_img}" check-config 2>&1)"
  printf '%s\n' "${o}" >"${out}/x.hub-check-config.txt"
  if printf '%s' "${o}" | grep -q ': ok'; then
    pass x.hub-check-config "hub check-config accepts deploy/central/hub.yaml"
  else
    fail x.hub-check-config "hub check-config accepts deploy/central/hub.yaml" "$(printf '%s' "${o}" | tr '\n' ';' | cut -c1-400)"
  fi
  o="$(docker run --rm -v "${here}/config/probe-b.yaml:/etc/probe/probe.yaml:ro" -v "${work}/certs/ca.crt:/etc/probe/ca.crt:ro" "${probe_img}" check-config 2>&1)"
  printf '%s\n' "${o}" >"${out}/x.check-config-e2e-probe-b.txt"
  printf '%s' "${o}" | grep -q 'policy mode:   closed' && pass x.check-config-e2e "probe check-config on the e2e probe-b config shows the closed policy" ||
    fail x.check-config-e2e "probe check-config on the e2e probe-b config" "$(printf '%s' "${o}" | tr '\n' ';')"

  # The probe image refuses to exec without NET_RAW in the bounding set (documented, loud on purpose).
  o="$(docker run --rm --cap-drop ALL "${probe_img}" version 2>&1)"
  if [[ "${o}" != "${E2E_VERSION}" ]]; then
    info x.no-net-raw "probe image with cap_drop ALL and no NET_RAW fails to exec, as documented" "$(printf '%s' "${o}" | tr '\n' ' ' | cut -c1-200)"
  else
    info x.no-net-raw "probe image with cap_drop ALL and no NET_RAW still runs" "${o}"
  fi
}

casebuild() {
  local o
  local had_dist=0
  [[ -d "${root}/dist" ]] && had_dist=1
  o="$(cd "${root}" && VERSION="${E2E_VERSION}" scripts/build.sh 2>&1)"
  local rc=$?
  printf '%s\n' "${o}" >"${out}/x.build.txt"
  local listing
  listing="$(cd "${root}/dist" 2>/dev/null && ls -1 && file linux-*/probe linux-*/probe-hub)"
  printf '%s\n' "${listing}" >>"${out}/x.build.txt"
  if [[ ${rc} -eq 0 ]] &&
    printf '%s' "${listing}" | grep -q "probe-${E2E_VERSION}-linux-amd64.tar.gz" &&
    printf '%s' "${listing}" | grep -q "probe-${E2E_VERSION}-linux-arm64.tar.gz" &&
    printf '%s' "${listing}" | grep -q 'linux-amd64/probe:.*x86-64.*statically linked' &&
    printf '%s' "${listing}" | grep -q 'linux-arm64/probe-hub:.*aarch64.*statically linked' &&
    (cd "${root}/dist" && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1); then
    pass x.build "scripts/build.sh: linux amd64+arm64 binaries, tarballs, SHA256SUMS verifies"
  else
    fail x.build "scripts/build.sh" "rc=${rc} $(printf '%s' "${listing}" | tr '\n' ';' | cut -c1-500)"
  fi
  local tarlist
  tarlist="$(tar -tzf "${root}/dist/probe-${E2E_VERSION}-linux-arm64.tar.gz" 2>&1 | tr '\n' ' ')"
  info x.build-tarball "arm64 tarball contents" "${tarlist}"
  [[ ${had_dist} -eq 0 ]] && info x.build-dist "dist/ was created by this run at ${root}/dist" ""
}

# ---------------------------------------------------------------- main
mkdir -p "${work}" "${out}"
: >"${results}"
: >"${calls}"

if [[ ${reuse} -eq 1 ]]; then
  . "${work}/env"
  export HUB_TOKEN_FULL HUB_TOKEN_LIMITED HUB_TOKEN_NETOPS ENROLL_A ENROLL_B ENROLL_C
  # Calls already made against this stack are in the hub's log; start the count from there.
  dc logs --no-log-prefix hub 2>/dev/null | grep -c '"msg":"tool_call"' | awk '{for (i = 0; i < $1; i++) print "x"}' >"${calls}"
else
  setup
fi

want 1 && case1
want 2 && case2
want 3 && case3
want 4 && case4
want 5 && case5
want 6 && case6
want 9 && case9
want 11 && case11
want 13 && case13
want 12 && case12
want 7 && case7
want 8 && case8
want 10 && case10
want x && casex
[[ ${with_build} -eq 1 ]] && casebuild

# Logs for inspection, then the report.
mkdir -p "${logs}"
for s in hub probe-a probe-b probe-c nat dns web jump ${DEV_SERVICES}; do
  dc logs --no-log-prefix "${s}" >"${logs}/${s}.log" 2>&1
done

echo
echo "================ probe-tools e2e results ================"
awk -F'|' '{ if ($1 == "FAIL") printf "%-4s %-28s %s\n       -> %s\n", $1, $2, $3, $4; else if ($1 == "INFO") printf "%-4s %-28s %s: %s\n", $1, $2, $3, $4; else printf "%-4s %-28s %s\n", $1, $2, $3 }' "${results}"
npass="$(grep -c '^PASS' "${results}")"
nfail="$(grep -c '^FAIL' "${results}")"
echo "---------------------------------------------------------"
echo "PASS ${npass}  FAIL ${nfail}   evidence: ${out}   logs: ${logs}"

if [[ ${keep} -eq 1 ]]; then
  echo "stack left up (--keep). Tokens: ${work}/env. Tear down with: ${here}/run.sh --down"
else
  dc down -v --remove-orphans >/dev/null 2>&1
fi
[[ "${nfail}" -eq 0 ]]
