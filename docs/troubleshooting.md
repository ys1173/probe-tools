# Troubleshooting

Fixes for the common failures, for operators. Commands assume Docker in `deploy/central/` (hub) or
`deploy/remote-docker/` (probe); for systemd probes use `journalctl -u probe` and `sudo -u probe probe ...`. Every
error code an agent can see, with what to do, is in [agent-guide.md](agent-guide.md#errors-and-outcomes).

## A probe is missing from list_probes, or shows online: false

1. **Scope.** Is the probe's name or site covered by the client's `probes` in `hub.yaml`? A probe outside the scope is
   invisible. Did the agent pass a `site` filter?
2. **Hub's view.** `docker compose exec hub probe-hub probes list`. Not listed: it never enrolled (go on to 3). Listed
   with `REVOKED`: re-enrol it ([operations.md](operations.md#re-enrolling-a-probe)). Listed with an old `LAST SEEN`:
   its link is down (go on to 4).
3. **Probe logs** (`docker compose logs probe` or `journalctl -u probe`):
   - `enrolment failed; will retry` with a network or TLS error: see the next two sections.
   - `hub refused enrolment: HTTP 401`: the token is used, expired, revoked or from another hub. Check
     `probe-hub token list`, then create a new one.
   - `no saved identity ... and the enrolment token variable PROBE_ENROLL_TOKEN is empty`: put the token in
     `probe.env`, then `docker compose up -d --force-recreate probe` (or `sudo systemctl restart probe`).
   - `the identity ... was enrolled with hub X but hub_url is now Y`: re-enrol.
   - `configuration is not valid`: run `check-config`.
4. **Link.** `could not connect to hub` or `link to hub lost`: see the next section.
   `credential refused or revoked; re-enrol with a new token`: the probe was revoked or the hub's database was lost;
   re-enrol.

## The probe cannot reach the hub

- From the probe host: `curl -sS https://hub.example.com:8443/healthz` (with `--cacert ca.crt` for a private CA)
  should print `ok`. This checks name resolution, route, firewall, TLS and the certificate's name together.
- The site must allow **outbound TCP to the hub's 8443**, and the hub host must allow it inbound from the site's
  outbound (NAT or proxy) address.
- **Proxy:** set `HTTPS_PROXY` (and `NO_PROXY` if needed) in `probe.env` or `/etc/probe/probe.env`. It is used for the
  hub link only, never for checks. The proxy must allow `CONNECT` to port 8443. A TLS-inspecting proxy replaces the
  hub's certificate: exempt the hub, or add the proxy's CA to `ca_file`.
- **No inbound mode.** The probe only ever connects out; the hub cannot connect in to a probe. If a site truly cannot
  reach the hub, either move the hub somewhere every site can reach, or carry the traffic over a tunnel or VPN you
  run, with `hub_url` pointing at the hub's address through it.

## TLS errors

| Probe log says | Fix |
|---|---|
| `x509: certificate signed by unknown authority` | Private CA: give the probe its certificate as `ca_file` (Docker: mount it and use the in-container path). Public CA: `tls.crt` on the hub probably lacks the intermediate certificates; put the full chain in it. |
| `x509: certificate is valid for A, not B` | `hub_url` uses a name the certificate does not cover. Use a name in the certificate, or reissue it. |
| `cannot validate certificate for 10.x.x.x because it doesn't contain any IP SANs` | `hub_url` uses an IP: add it to the certificate as an IP SAN, or use a name. |
| `x509: certificate has expired or is not yet valid` | Renew the certificate ([certificates](deploy.md#certificates)) and `docker compose restart hub`, or fix the clock. |
| hub log: permission denied reading `/certs/tls.key` | `chown 65532:65532 certs/tls.key && chmod 0400 certs/tls.key` (again after every renewal). |

## Agent problems

- **HTTP 401:** the bearer token does not match any client token. Check `hub.env`, that the container was recreated
  after editing it (`docker compose up -d --force-recreate hub`), and the hub log line `mcp request refused`.
- **Connection refused from another host:** MCP is bound to `127.0.0.1` by default; see
  [Make MCP reachable](deploy.md#make-mcp-reachable).
- **TLS error from the agent after enabling MCP TLS:** the URL's host name must be in the certificate (an IP needs an
  IP SAN), and a private CA must be trusted by the agent (for Claude Code, `NODE_EXTRA_CA_CERTS`).
- **`http://127.0.0.1:8080/healthz` fails after enabling remote MCP:** expected; MCP now listens on the internal
  address only, with TLS. Use `https://<name in the certificate>:8080/healthz`.
- **`unknown tool`:** the client's `tools` does not grant it (device tools must be named).
- **`busy` on the whole call:** the client already has 8 calls running.

## Checks report unavailable

- **ping, traceroute or path_mtu:** the probe has no raw sockets. Keep `cap_add: [NET_RAW]` (Docker) or
  `AmbientCapabilities=CAP_NET_RAW` (systemd). `path_mtu` also needs Linux.
- **path_test `listen_failed`:** the receiver has no `listen_ports`, the port is outside them, it is in use, or (below
  1024) the probe may not bind it; `listen.error.message` has the exact error. See
  [a test listener on TCP 443](operations.md#a-test-listener-on-tcp-443).
- **dns_lookup:** the probe has no resolvers in `/etc/resolv.conf`; give `server`.

## Device commands

| Symptom | Check |
|---|---|
| `not_found` | `ssh.enabled: true` in `probe.yaml` and the probe restarted. |
| `unavailable: no SSH profile covers ...` | `ssh.enabled: true`, then `probe ssh profile list`; the device's resolved address must be in a profile's ranges. |
| `unavailable: ... SSH profiles cannot be read` | The store's ownership or modes are wrong; run `probe ssh` commands as the probe's own user only. |
| `denied` | The device or jump host must be allowed by `targets` and not on the no-touch list. |
| `command_not_allowed` | `device_commands` for the patterns; write the command in full. |
| `host_key_unknown` | `probe ssh hostkey learn ADDR` after checking the fingerprint. If `detail` starts with `jump host NAME:`, ADDR is the jump host's address exactly as `probe ssh jump list` shows it. |
| `host_key_changed` | Investigate first. Then `probe ssh hostkey forget ADDR [--jump J]` and `learn`. |
| `auth_failed` at once, with "not tried again until" | A cool-down is running. Fix the secret with `profile set NAME --password` (or `jump set`), which ends it. |
| `auth_failed` after connecting | Wrong secret, account locked, the account asked for a one-time code, or AAA unreachable from the device. Do not loop `probe ssh test` against a shared account: it has no cool-down. |
| `refused` / `unreachable` via a jump host | The jump host's sshd may forbid TCP forwarding, or cannot route to the device. |
| `error` with "no common algorithm" | `probe ssh profile set NAME --legacy` (or `jump set NAME --legacy` for the jump host). |
| `timeout` | Raise `timeout_ms`; for `panos` and `edgeos` the prompt may not have been recognised: report it. |
| `probe ssh` says the store is owned by another user | Run it as the probe's user: `docker compose exec` (not `run` as root) or `sudo -u probe`. |
| a new commands file is ignored | Docker: the volume line needs `docker compose up -d --force-recreate probe`; edits after that need `docker compose restart probe`. `check-config` shows `(changed locally)` per platform. |

Device commands end to end: [device-commands.md](device-commands.md).
