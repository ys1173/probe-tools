# Testing and development

What has and has not been tested, how to run the tests, and the build scripts. Deployment is in
[deploy.md](deploy.md).

## Maturity

Early. Everything has run in the automated end-to-end test, which uses Docker networks on one host, never a real WAN.
One short trial ran on real hosts with one real network device. Treat the device platforms other than EdgeOS, the
native systemd install on amd64, IPv6 and multi-hop WAN paths as unproven.

## What has been tested

- **Unit tests** (`scripts/go test ./...`) for the probe, hub, MCP server, policy, protocol, checks, SSH store and
  command lists, including raw ICMP tests when run privileged. `internal/check`, `internal/hubapi`, `internal/deps`
  and `cmd/probe-hub` have no tests of their own.
- **The end-to-end test** (`test/e2e/run.sh`) runs everything in Docker on one host: a hub with TLS, three probes on
  separate Docker networks, a NAT router, real targets, fake IOS-like and PAN-OS-like SSH devices, a real OpenSSH jump
  host, and an MCP client container. It covers enrolment, scopes, every check, `path_test` verdicts including NAT,
  device commands (profiles entered with the real CLI, key and password profiles, unknown and changed host keys, a
  wrong password and its cool-down, refusals before connecting, one session per device), the audit log, and that no
  token or secret appears in any log. It also checks the probe image refuses to run without `NET_RAW`.
- **One trial on real hosts:** a hub in Docker Desktop on macOS, and a probe as a Docker image on a Debian 12
  **amd64** host, running `device_show` against an Ubiquiti EdgeRouter Lite
  3-Port on EdgeOS v2.0.3. On that device `show version`, `show interfaces`, `show ip route`, `show vrrp summary` and
  the OSPF and BGP summaries ran cleanly, refused commands never opened a connection, a second concurrent request got
  `busy`, and no credentials appeared in the logs. The probe recorded the device's RSA host key although the device
  also offered ED25519; this works, and a change to prefer ED25519 is planned.
- **The systemd unit** has run under real systemd in a Debian 12 container on arm64.

## Not yet tested

- The other seven device platforms (`ios`, `nxos`, `junos`, `eos`, `panos`, `fortios`, `routeros`) on real hardware.
  Their command lists and the way each takes a command (exec or shell, paging, error text, prompts) come from vendor
  documentation and public reports. Expect to correct a list or a driver on first use; run `probe ssh test` against a
  device where a failed login does not matter before relying on it (and see the
  [warning about shared accounts](device-commands.md#worked-example)). That `set cli pager off` lasts only for the
  session on PAN-OS rests on community reports.
- `--legacy` algorithms and keyboard-interactive prompts other than a plain password: tested against an in-process
  test SSH server only.
- IPv6: tested on loopback only.
- Real WAN and multi-hop paths: the end-to-end test uses Docker networks.
- Host networking on Docker Desktop (macOS, Windows): not supported.
- The native amd64 binary and the systemd unit on amd64: the amd64 binary has run only inside the Docker image; the
  unit has not run on a VM, bare metal or amd64.
- The systemd drop-in for `CAP_NET_BIND_SERVICE` in [operations.md](operations.md#a-test-listener-on-tcp-443).
- Remote MCP over TLS with a real agent: the hub's TLS listener and `https` health check were checked by hand with
  `curl`; Claude Code against it with a private CA was not.
- There is no native installer for the hub; `scripts/build.sh` produces a `probe-hub` binary, but you would write the
  unit yourself.

## Development

Go runs in a container, so Docker is the only requirement:

```
scripts/go test ./...                      # unit tests
GO_PRIVILEGED=1 scripts/go test ./...      # adds NET_RAW and NET_ADMIN for the raw ICMP tests
scripts/go vet ./...
```

| Script | What |
|---|---|
| `scripts/go` | Runs `go ...` in a `golang:1.26` container with cached modules. |
| `scripts/build.sh` | Cross-compiles `probe` and `probe-hub` for linux `amd64` and `arm64` into `dist/`, and packs the probe tarballs and `SHA256SUMS`. Honours `VERSION` and `ARCHES`. |
| `scripts/build-images.sh` | Builds `probetools/hub` and `probetools/probe` with `docker buildx`, tagged with the version and `latest`, loaded into the local daemon. `--multi-arch` builds both platforms and pushes (or use `--output`). `REGISTRY`, `VERSION`, `PLATFORMS` change names and platforms. |
| `scripts/dev-certs.sh` | Throwaway test certificates. Testing only. |

## End-to-end test

`test/e2e/run.sh` builds the images, starts the stack described above, runs the cases, prints PASS/FAIL and tears
down. It needs Docker with Compose v2, `jq`, `openssl` and `ssh-keygen`; evidence is saved under `test/e2e/.work/`
(results in `out/<id>.json`, container logs in `logs/`).

| Option | What |
|---|---|
| `--keep` | Leave the stack up afterwards (tokens in `test/e2e/.work/env`). |
| `--reuse --keep` | Run against a stack left up by `--keep` (no rebuild, no re-enrol). |
| `--only "3 5"` | Run only these cases (ids 1-13; `x` is the image and config checks; 13 is device commands over SSH). |
| `--with-build` | Also run `scripts/build.sh` and check `dist/` (writes `dist/` at the repository root). |
| `--down` | Just tear the stack down. |

[DESIGN.md](../DESIGN.md) has the design rules and the wire protocol.
