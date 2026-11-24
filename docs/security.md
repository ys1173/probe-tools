# Security

What protects what, which addresses are always refused, what "read-only" covers, and the limits that are known and
accepted. Design rules behind these are in [DESIGN.md](../DESIGN.md); device command safety in detail in
[device-commands.md](device-commands.md#which-commands-are-allowed).

## Security model

- **The probe's policy decides.** The hub and the agent can narrow a request, never widen it. A probe refuses to start
  without `targets.mode`.
- **All targets go through the policy.** The probe resolves each name itself, checks every address, and connects to
  the checked address, so a DNS answer that changes or a redirect cannot reach a refused address. Checks never use a
  proxy (`HTTPS_PROXY` is for the probe's link to the hub only).
- **Fixed checks only.** No shell, no free payloads, no range scans, no relaying or tunnelling, nothing that changes a
  target. Response bodies are never returned. The one tool that takes text from the agent is `device_show`
  ([what it sends](device-commands.md#what-it-sends-to-a-device)).
- **Target text is marked.** Text the target controls is returned as `untrusted`, with control and invisible
  formatting characters escaped and a length limit.
- **Identity.** Enrolment tokens are single use and fix the probe's name and site. The hub stores hashes of tokens and
  probe secrets. `identity.json` is mode 0600. Admin is by local command only.
- **Client scopes.** Each client has its own client token, probe scope and tool list; a probe outside its scope looks
  the same as one that does not exist. Limits: 20 probes per call, 8 concurrent calls per client, and per-probe
  limits on concurrent jobs and on jobs per resolved target address per minute (different spellings of one address
  share the limit).
- **Hub hardening.** `/v1/enroll` is unauthenticated, so it is limited per client address (IPv4, or IPv6 /64): attempts
  per minute, handlers at once, 10 s to send the body, a 4 KiB body; every refused token gets the same 401.
  `/v1/connect` counts failed authentications per address; a valid credential is always accepted.
- **Device credentials never leave the probe.** The hub learns only each profile's name, ranges, platform and jump
  host name. The store refuses symbolic links, directories not owned by its user with mode 0700, and files not owned
  by its user with mode 0600.
- **Privilege.** The probe needs only `CAP_NET_RAW` (traceroute and raw ICMP). In Docker it runs as uid 65532 with all
  other capabilities dropped, a read-only root filesystem and `no-new-privileges`; under systemd it is sandboxed. The
  hub needs no capabilities.
- **Exposure.** The hub's compose file publishes the probe listener (8443) on all interfaces and MCP (8080) on
  loopback only. Restrict 8443 to the probe sites in the hub host's firewall where you can, and publish MCP beyond
  loopback only with TLS ([remote MCP](deploy.md#remote-mcp-over-tls)).

## Always refused addresses

In both modes: loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`, which includes cloud
metadata at `169.254.169.254`), `0.0.0.0/8`, multicast, reserved (`240.0.0.0/4`, including broadcast),
`100.100.100.200` and `fd00:ec2::254` (cloud metadata), Teredo (`2001::/32`), the probe's own interface addresses, and
the directed broadcast address of each of the probe's IPv4 networks. If the probe cannot list its own addresses, it
refuses every target until it can. IPv6 forms that carry an IPv4 address (NAT64 `64:ff9b::/96`, 6to4 `2002::/16`,
IPv4-compatible and IPv4-translated) are checked on the embedded IPv4 address too; the local-use NAT64 prefix
`64:ff9b:1::/48` is refused unless `allow_cidrs` lists it.

## What read-only means

Every MCP tool is marked `readOnlyHint: true`, and no tool changes a target's configuration or state. That does not
mean "sends nothing":

- Every check makes real connections and sends packets to the target: ICMP, DNS queries, TCP handshakes, a TLS
  handshake, and for `http_check` (and `diagnose`'s HTTP layer) a real `GET` or `HEAD` request.
- `tcp_template` and `udp_probe` send small fixed requests (`HEAD`, `PING`, `EHLO probe.invalid` then `QUIT`, an
  SSLRequest, a DNS or NTP query, an SNMPv3 discovery). Nothing the agent types is sent.
- `path_test` opens a listening port from `listen_ports` on the receiving probe for up to 20 s, and the sender sends
  one fixed line, `probe-path-test <nonce>`.
- `device_show` logs in to the device (it appears in the device's login records and AAA accounting), runs one
  allowed command, and on EdgeOS (`terminal length 0`) and PAN-OS (`set cli pager off`) first sends one paging
  setting that lasts only for that session.

## Known limits

Accepted, for now:

- **`allow_hosts` trusts DNS.** Whoever controls DNS for an allowed domain can point a name at other hosts (except
  always-refused and `deny_cidrs` addresses). For a hard boundary use `allow_cidrs` and `deny_cidrs`.
- **`dns_lookup` without `server` is not policy-checked**, and the names it looks up never are.
- **`http_check` can confirm guessed content** through its body hash and `expect_text`. Do not allow targets whose
  content you would not want guessed.
- **Rate limits slow, they do not prevent.** An agent can still make many calls to allowed targets, up to 10 ports per
  `tcp_connect`.
- **The `/v1/connect` failure limiter fails open when its table is full** of addresses. Probes are still
  authenticated.
- **Enrolment can be held up** by many slow request bodies; connected probes are not affected. Behind a reverse proxy
  on 8443, all probes share one address for these limits.
- **Root on a probe host** can read `identity.json` and the SSH store (secrets are plain files, mode 0600), impersonate
  the probe and change its policy. A stolen probe identity can also mislead `path_test` about the receiver's
  addresses. Revoke a probe whose host you no longer trust, and use device accounts that can only read.
- **Your own NAT64 prefix is not recognised.** List a network-specific prefix in `deny_cidrs`, or use closed mode.
- **A client token grants everything in its scope.** MCP is plain HTTP unless you configure TLS or a proxy; a bearer
  token on plain HTTP can be read on the network. On agent hosts the token sits in the MCP client's configuration
  (for Claude Code, `~/.claude.json`) and possibly shell history.
- **Prompt injection is the agent's problem.** The hub marks untrusted text; it cannot stop an agent acting on it.
  Device output is a likely place for it.
- **A local allow pattern can widen reads.** `^show running-config$` passes the floor, and a configuration dump can
  hold secrets. A local file cannot allow a write, reload or shell that the floor knows about.
- **The floor is a word list.** The shortest abbreviations (one letter, or below a word's minimum) and state-changing
  words it does not name can pass under a broad local pattern.
- **Repeated calls can still lock an account, slowly.** The cool-down is in memory (a restart clears it) and ends when
  it expires or the secret changes. With `ssh.auth_failure_cooldown_s: 0` only the per-target rate limit is left.
- **Trust on first use, where it applies,** accepts an attacker who is in the path at the first connection (and, for a
  password profile that opted in, gives them the password). Record checked keys first to avoid it.
- **`probe ssh test` runs in its own process**: it shares neither the running probe's one-session-per-device lock, rate
  limiter nor cool-down, so repeated tests with a wrong password can lock a shared account.
