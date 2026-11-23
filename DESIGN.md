# Design

A hub and remote probes for network troubleshooting by AI agents. The hub is an MCP server; probes run checks from
where they are installed. Probes always connect out to the hub. The only inbound traffic a probe accepts is a path_test arrival, on a port from its own `listen_ports`, while that test runs.

```
agent (any MCP client) --MCP over HTTP, bearer token--> hub <--WebSocket, opened by the probe-- probe (site A)
                                                          ^------------------------------------- probe (site B)
```

## Components

| Path | What |
|---|---|
| `cmd/probe-hub` | hub binary: serves probes (enrol, WebSocket link) and agents (MCP), plus admin commands |
| `cmd/probe` | probe binary: connects out to the hub and runs checks |
| `internal/protocol` | the contract: wire messages, check parameters and limits, result envelope, error codes, untrusted text |
| `internal/policy` | the probe's target policy; every check reaches targets only through it |
| `internal/check` | the check interface (`Func`, `Env`, `Registry`, `Decode`) |
| `internal/checks/icmp` | ping, traceroute, path_mtu; raw-socket capability detection |
| `internal/checks/pathtest` | listen_start, listen_collect, path_send (the probe side of path_test) |
| `internal/checks/info` | probe_info |
| `internal/checks/app` | dns_lookup, tcp_connect, tcp_template, udp_probe, tls_check, http_check |
| `internal/checks/diagnose` | diagnose, built from the other checks through `Env.Run` |
| `internal/probe` | probe runtime: config, enrolment, state file, the link to the hub, job dispatch, limits |
| `internal/hubapi` | the boundary inside the hub: `Router`, `ProbeStatus`, `Client` |
| `internal/hub` | hub probe side: store (SQLite), enrolment, probe link, router, revocation, admin commands, config |
| `internal/mcpserver` | hub agent side: MCP tools, client auth and scopes, fan-out, path_test orchestration, audit log |

## Rules every part follows

- **The probe's policy is the authority.** The hub and the agent can ask for less, never more. A probe refuses to start
  without `targets.mode` set to `open` or `closed`.
- **Targets are reached only through `policy`.** Names are resolved there, each address is checked, and connections go to
  the checked address. Checks never use a proxy (`HTTPS_PROXY` applies to the probe's link to the hub only). Raw-socket
  checks send to an address `policy.Resolve` returned. A DNS server given to `dns_lookup` is a target too.
- **Fixed checks only.** No shell, no free payloads, no range scans, no relaying or tunnelling, nothing that changes a
  target. Every check is read-only, so every MCP tool sets `readOnlyHint: true`.
- **Results are structured.** Every hub tool returns one `protocol.ProbeResult` per probe, stamped with probe and site.
  Text the target controls goes in `protocol.Untrusted`. Response bodies are never returned.
- **No queueing.** An offline probe answers `probe_offline` at once.
- **Time budgets.** A hub tool call finishes within 50 s (callers may allow 60). One job on a probe takes at most 40 s;
  checks honour their context and return partial results where they have them.
- **Identity.** Enrolment tokens are single use and fix the probe's name and site. The hub stores hashes of tokens and
  secrets, never the values. The probe's state file is mode 0600. Admin is by local command only.
- **Logs.** JSON lines on stdout. Every tool call (hub) and job (probe) is logged. Secrets, tokens and URLs with
  credentials are never logged.

## Probe link

1. A new probe posts `EnrollRequest` to `/v1/enroll` with its enrolment token and gets `EnrollResponse`; it saves
   `{hub_url, probe_id, name, site, secret}` to `<state_dir>/identity.json` (0600). With a saved identity it skips this.
2. It opens a WebSocket to `/v1/connect` with subprotocol `probe.v1` and `Authorization: Bearer <probe_id>.<secret>`.
3. It sends `hello`; the hub answers `welcome`. Then the hub sends `job` and `cancel`, the probe sends `result`.
4. The hub pings every 20 s and drops a probe that misses two. The probe reconnects with backoff from 1 s to 60 s, with
   jitter.
5. Close codes: `4401` unknown, wrong or revoked credential (the probe retries only every 10 minutes and logs that it
   needs re-enrolling); `4409` replaced by a newer session of the same probe (the old one waits 10 minutes before trying
   again); `4400` protocol error, including a `hello` whose fields fail the hub's checks (charsets, lengths, addresses
   that don't parse). Before the upgrade the credential is always checked: a valid one is accepted however many
   failures came from its address (probes can share a NAT or proxy address); a bad one gets HTTP 401, or the same 429
   for any failure once its address has too many failed authentications.
6. Frames are at most 1 MiB.
7. Enrolment is limited per client address (IPv6 per /64), in concurrency and in time: the body must arrive within
   10 s and be at most 4 KiB. Every refused token gets the same 401; too many attempts or too many at once get 429 or
   503 before any token is checked.
8. Every request on the probe listener must send its body within 10 s, and every refusal closes the connection, so an
   unauthenticated client cannot hold a connection open; `/v1/connect` lifts the deadline just before the upgrade.

## path_test

The hub picks a random nonce, asks probe B to `listen_start` (TCP or UDP, a port from B's `listen_ports`), asks probe A
to `path_send` to B's address, then asks B to `listen_collect`. A sends exactly `probe-path-test <nonce>`; the probe
builds that line itself and the nonce is limited to `[A-Za-z0-9_-]{22,43}`, so a hub cannot use path_send to deliver a
payload of its choosing. B matches arrivals on the nonce, not the source address, so a NAT shows up as an unexpected
source rather than as "nothing arrived". "Port could not be opened" and "denied by A's policy" are reported as such,
never as a blocked path.

B's address: the caller may give `to_address`, but only one of B's reported addresses unless the client may also call
`tcp_connect`. Otherwise the hub picks a B address on the same /24 (IPv6 /64) as one of A's addresses, else B's first
address, and says so in any verdict other than reached.

## Agent side

- A client sees and may call only the tools in its `tools` list. A probe it may not use and a probe that doesn't exist
  get the same answer, `probe_unknown`, so a client can't map probes outside its scope.
- The probe's rate limit applies per resolved address, once per job, so different spellings of one address share a
  limit. `policy.Resolve` returns (and charges) at most 8 addresses per call. The limiter's table is bounded; when it
  is full it drops refilled buckets, then the least recently used one, and never refuses a new address for lack of room.
