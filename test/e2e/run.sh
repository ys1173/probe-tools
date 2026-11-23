#!/usr/bin/env bash
# End-to-end test of probe-hub and probe: builds the images, brings up test/e2e/compose.yaml (hub with TLS, three
# probes on bridge networks, targets, a NAT router and an MCP client container), runs the cases, prints a PASS/FAIL
# table and tears the stack down.
#
#   test/e2e/run.sh                   everything (setup, cases 1-12 and x, report, teardown)
#   test/e2e/run.sh --keep            leave the stack up afterwards (tokens in test/e2e/.work/env)
#   test/e2e/run.sh --reuse --keep    run against a stack left up by --keep (no rebuild, no re-enrol)
#   test/e2e/run.sh --only "3 5"      run only these cases (ids: 1-12, x = image/config checks)
#   test/e2e/run.sh --with-build      also run scripts/build.sh and check dist/ (writes dist/ at the repo root)
#   test/e2e/run.sh --down            just tear the stack down
#
# Needs docker (compose v2), jq and openssl on the host. Works with macOS bash 3.2. Evidence for every case is saved in
# test/e2e/.work/out/<id>.json, container logs in test/e2e/.work/logs/.
#
# Probe names: site-a-probe (service probe-a, site a), site-b-probe (probe-b, site b), site-c-probe (probe-c, site c).
# The names start with the site so the `limited` client's probe scope ["site-a-*"] covers probe-a only.
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
WRONG_TOKEN="wrong-token-0123456789abcdef0123456789abcdef"

dc() { docker compose -f "${here}/compose.yaml" --project-directory "${here}" "$@"; }
log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
now() { date +%s; }

if [[ ${down_only} -eq 1 ]]; then
  [[ -f "${work}/env" ]] && . "${work}/env"
  export HUB_TOKEN_FULL="${HUB_TOKEN_FULL:-x}" HUB_TOKEN_LIMITED="${HUB_TOKEN_LIMITED:-x}"
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

  log "building mcpcall"
  (cd "${root}" && GOFLAGS=-mod=readonly scripts/go build -o test/e2e/.work/bin/mcpcall ./test/e2e/mcpcall) ||
    { log "mcpcall build failed"; exit 1; }

  HUB_TOKEN_FULL="$(openssl rand -hex 32)"
  HUB_TOKEN_LIMITED="$(openssl rand -hex 32)"
  export HUB_TOKEN_FULL HUB_TOKEN_LIMITED

  log "building images (version ${E2E_VERSION})"
  dc build --quiet || { log "image build failed"; exit 1; }
  dc down -v --remove-orphans >/dev/null 2>&1
  log "starting hub and targets"
  dc up -d --quiet-pull hub web redis dns banner secret nat client >"${work}/compose-up.log" 2>&1 || { log "compose up failed (see ${work}/compose-up.log)"; exit 1; }
  local i
  for i in $(seq 1 30); do
    dc exec -T client wget -qO- http://hub:8080/healthz >/dev/null 2>&1 && break
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
  for name in HUB_TOKEN_FULL HUB_TOKEN_LIMITED WRONG_TOKEN ENROLL_A ENROLL_B ENROLL_C SECRET_A SECRET_B SECRET_C; do
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
  export HUB_TOKEN_FULL HUB_TOKEN_LIMITED ENROLL_A ENROLL_B ENROLL_C
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
want 12 && case12
want 7 && case7
want 8 && case8
want 10 && case10
want x && casex
[[ ${with_build} -eq 1 ]] && casebuild

# Logs for inspection, then the report.
mkdir -p "${logs}"
for s in hub probe-a probe-b probe-c nat dns web; do
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
