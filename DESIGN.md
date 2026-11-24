# Design

A hub and remote probes for network troubleshooting by AI agents. The hub is an MCP server; probes run checks from
where they are installed. Probes always connect out to the hub. The only inbound traffic a probe accepts is a path_test arrival, on a port from its own `listen_ports`, while that test runs.

```
agent (any MCP client) --MCP over HTTP, bearer token--> hub <--WebSocket, opened by the probe-- probe (site A)
                                                          ^------------------------------------- probe (site B)
```

This is the design reference. How to deploy, operate and use it is in [README.md](README.md) and [docs/](docs/).

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
  target. No check changes a target's configuration or state, so every MCP tool sets `readOnlyHint: true`; they still
  connect and send (path_test opens a listener on the receiving probe for up to 20 s; device_show logs in, and on EdgeOS
  and PAN-OS sends one session-only paging setting first). The one check that takes a command line
  is `device_show`, and only commands that pass its floor and its per-platform list run (see "Device commands over
  SSH").
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

## Device commands over SSH

`device_show` runs one read-only command on a network device from the probe that can reach it; `device_commands` lists
what is allowed. Supported platforms: `ios` (IOS and IOS-XE), `nxos`, `junos`, `eos`, `panos`, `fortios`, `edgeos`
(Ubiquiti EdgeRouter), `routeros` (MikroTik).

| Path | What |
|---|---|
| `internal/devcmd` | the command lists: built-in per-platform patterns, a probe's local additions and removals, and the floor |
| `internal/sshcfg` | the probe's local SSH store: profiles, jump hosts, secrets and known host keys under `<state_dir>/ssh/` |
| `internal/checks/devssh` | the `device_show` and `device_commands` checks: profile choice, SSH, jump hosts, per-platform drivers |

**Which device, which credentials.** There is no list of devices. A device is given as an address or name of letters,
digits and `. : _ -`; an IPv6 zone (`%...`) is refused everywhere. A device is any address the probe's target policy
allows; the no-touch list is `targets.deny_cidrs` plus `targets.deny_hosts`, and applies to every check. The probe
chooses the credentials and platform from its local **profiles**: each covers CIDRs, names a platform, a user name,
password or key, and optionally a jump host. A profile matches on the device's *resolved address*, never its name, so DNS
cannot steer a password to another host; the first matching profile wins; no profile means the device is refused. A
profile may not cover a catch-all range (shorter than /8 for IPv4, /16 for IPv6). The agent never chooses the platform.

**Secrets stay on the probe.** Profiles, jump hosts and their secrets are entered on the probe host with
`probe ssh ...` commands: a hidden password prompt, or a key file copied into the store, never a flag or environment
variable (`--password-stdin` is for automation and refused on a terminal). The command runs as the probe's own user
(`sudo -u probe probe ssh ...` on a systemd install; as root it refuses a state directory owned by another user). The
store refuses symbolic links and checks that every directory is the user's own with mode 0700 and every file the user's
own with mode 0600. Changes apply to the next command; no restart. Keys are recommended over passwords.

**Host keys.** Recorded per jump, address and port; a later different key is refused (`host_key_changed`). A key
profile trusts a device's key on first use, since a public-key login gives a fake server nothing it can reuse. A
password profile never logs in to a device whose key isn't recorded: it answers `host_key_unknown` with the fingerprint
and records nothing, and the operator confirms the key with `probe ssh hostkey learn` (or opts the profile into trust
on first use with `--trust-on-first-use`). A jump host's key is confirmed when the jump is added.

**Jump hosts.** The probe resolves and policy-checks the device, then asks the jump to connect to that IP address
(`direct-tcpip`), so the jump never resolves a name.

**Commands.** A command is allowed when it passes the floor, matches an allow pattern for the platform, and matches no
deny pattern. Patterns are Go regular expressions anchored over the whole normalised command. The built-in lists cover
physical and operational state (interfaces, routes, neighbours, counters, hardware) and leave out configuration, keys,
users, communities and tech-support. A probe's local file (`ssh.commands_file`) may add or remove patterns per
platform, or with `builtin: false` replace a platform's list with only its own allow patterns, so sites can be stricter
or more permissive than each other. Every list is an allow list: a command no allow pattern matches is refused. The floor applies to every list, built-in or
local: one line using only letters, digits, space and `. _ : / , = @ + -` (so no pipes, separators, redirection, quotes
or shell characters, which matters because EdgeOS and a Junos root login reach a POSIX shell), and the platform's read
verb first (`show` on most platforms; on FortiOS `get`, or one of a fixed set of read-only `diagnose` commands built
into the floor, which no local file can add to; on RouterOS a `/menu` path written with spaces, then `print` with only
fixed output arguments, or `monitor <item> once`; `/log` takes only `print`). The floor also refuses, anywhere after the
first word, words that configure, write, change state, send, start a shell, stream or start a long job (`configure`,
`write`, `copy`, `delete`, `reload`, `clear`, `add`, `remove`, `debug`, `run`, `ping`, `ssh`, `monitor`, `top`,
`tech-support`, `delta`, `discover`, `wol` and many more, plus a few per platform), and any word that abbreviates one of
them (three letters by default, with per-word minimums), since device CLIs accept abbreviations. On EdgeOS, whose
operational mode expands prefixes, two letters are enough for the streaming words (`capture`, `tail`, `follow`,
`monitor`, `top`: `show log ta` is refused). One-letter abbreviations are not refused on any platform, a known limit. So
an argument that happens to be such a word or its prefix is refused too. `internal/devcmd/floor.go` has the full rules. Allow patterns match the command as
written; deny patterns ignore case and must cover every spelling of an argument (`Gi1/0/1` and `GigabitEthernet1/0/1`)
or deny the whole command. The built-in lists show VRRP and HSRP in brief or summary form only, since the detailed forms
may show authentication text.

**Store layout.** `<state_dir>/ssh/` holds `profiles.json` (profiles and jumps, no secrets), `secrets.json`,
`keys/profile-<name>` and `keys/jump-<name>`, `known_hosts` (devices reached directly, and jump hosts under their
configured address), `known_hosts.via-<jump>` (devices reached through that jump) and `.lock`. Writes take the lock and
are atomic, so first-use records from parallel jobs and edits from the CLI don't lose each other.

**Per-platform transport.** Sources are in `internal/checks/devssh/drivers.go`. Only `edgeos` has been run on a real
device (an EdgeRouter Lite 3-Port on EdgeOS v2.0.3); the others are from vendor documentation and public reports.

| Platform | Transport | Sent before the command |
|---|---|---|
| ios, nxos, eos, junos, fortios | SSH exec | nothing (a pager prompt, if one appears, is answered with a space) |
| panos | interactive shell | `set cli pager off` (a session setting) |
| edgeos | interactive shell | `terminal length 0` |
| routeros | SSH exec | nothing; the user name gets `+cet512w` for plain, wide output |

**Running a command.** One session per device at a time (a second request gets `busy`), opened for the command and
closed after it. A failed login is reported as `auth_failed` and never retried. When the password was sent (by password
or keyboard-interactive) and refused, that device address is not tried again with the profile for
`ssh.auth_failure_cooldown_s` (default 10 minutes, cleared by changing the profile's secret), so repeated calls cannot
lock the AAA account; the profile's other devices are still tried. Once its password has failed at 3 different addresses
within the cool-down, the pattern of an account being locked out, the profile is not tried at any address until the
cool-down from the third failure ends. A jump host is one host: a password refused there stops it for every profile
that uses it. A refused key, or a login that stopped at a question other than the password, sent no password and
starts no cool-down, so a host squatting on one address in a profile's range cannot block the others. Keyboard-interactive login answers only a prompt that asks for the password. Output is capped (`ssh.max_output_bytes`, and cut further so the result fits one message) and returned as untrusted
text. A result's `detail` uses fixed phrases only; text the device sent appears only in `output`.

**Agents.** `device_show` runs on exactly one probe (sites reuse private ranges, so the same address may be a
different device elsewhere). A client's `tools: ["*"]` does not include the device tools; they must be named.
