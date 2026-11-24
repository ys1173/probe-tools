# Operations

Running probe-tools after it is deployed: every configuration key, how to apply changes, admin commands, revoking and
re-enrolling probes, upgrades, backups, logs, and a temporary listener on a low port. Installation is in
[deploy.md](deploy.md); fixes for common failures in [troubleshooting.md](troubleshooting.md).

## Configuration reference

Unknown keys are refused, so a misspelt setting fails at start-up. Check a file without starting anything with
`probe-hub check-config` or `probe check-config` (Docker: `docker compose exec hub probe-hub check-config`,
`docker compose run --rm probe check-config`; systemd: `sudo -u probe probe check-config`).

### hub.yaml

The file is `--config FILE`, else `$HUB_CONFIG`, else `/etc/probe-hub/hub.yaml`.

| Key | Default | Notes |
|---|---|---|
| `data_dir` | `/data` | Holds the SQLite database `hub.db`. Back it up: losing it means every probe must re-enrol. |
| `probe_listener.address` | `:8443` | Must differ from `mcp.address`. |
| `probe_listener.tls_cert_file`, `tls_key_file` | none | Required unless `insecure_plaintext` is true. The certificate file holds the full chain. Read once at start-up. |
| `probe_listener.insecure_plaintext` | `false` | Plain HTTP, only behind a TLS-terminating proxy you trust. Cannot be combined with the TLS files. |
| `probe_listener.public_url` | none | `wss://host:port` probes use. Only printed by `token create`. |
| `mcp.address` | `:8080` | |
| `mcp.path` | `/mcp` | Must start with `/` and not be `/healthz`. |
| `mcp.tls_cert_file`, `tls_key_file` | none | Both or neither. Without them MCP is plain HTTP. See [remote MCP over TLS](deploy.md#remote-mcp-over-tls). |
| `clients` | none | Agent clients, below. With none, every MCP request is refused. |
| `log_level` | `info` | `debug`, `info`, `warn`, `error`. |

Each client:

| Key | Notes |
|---|---|
| `name` | Unique. Appears in the audit log. |
| `token_env` | The environment variable (in `hub.env`) that holds this client's client token: at least 24 characters, different for every client. The token is never in `hub.yaml`. |
| `probes` | Probes the client may use: exact names, globs (`syd-*`), `site:<site>`, or `*`. Empty allows none. A probe outside the scope looks the same as one that does not exist. |
| `tools` | Tool names, or `*`. Empty allows none. `*` does not include `device_show` and `device_commands`; name them to grant them. A misspelt tool name stops the hub from starting. |

### probe.yaml

The file is `--config FILE`, else `$PROBE_CONFIG`, else `/etc/probe/probe.yaml`.

| Key | Default | Notes |
|---|---|---|
| `hub_url` | none (required) | `wss://host[:port]`; `ws://` only with `insecure_plaintext`. No credentials, query or fragment. Env override `PROBE_HUB_URL`. |
| `enroll_token_env` | `PROBE_ENROLL_TOKEN` | The environment variable that holds the enrolment token. |
| `state_dir` | `/var/lib/probe` | Holds `identity.json` and the SSH store `ssh/`. Env override `PROBE_STATE_DIR`. |
| `ca_file` | none | PEM CA certificates to trust for the hub, added to the system roots. |
| `insecure_plaintext` | `false` | Allows `ws://`. Testing only. |
| `targets.mode` | none (required) | `open` or `closed`. |
| `targets.allow_cidrs` | none | CIDRs or addresses. `closed` mode. On a DNS64 network it must hold the IPv4 ranges or the NAT64 prefix. |
| `targets.allow_hosts` | none | Exact names, or `*.example.com` for any name below it. `closed` mode. Never admits an address that carries an IPv4 address (NAT64). |
| `targets.deny_cidrs` | none | Refused in both modes. |
| `targets.deny_hosts` | none | Names refused in both modes; matches requests made by name only. |
| `listen_ports` | none (off) | One port or one range, for example `"40000-40100"`, within 1-65535. |
| `limits.max_concurrent` | `4` | 1 to 64 jobs at once; more answer `busy`. |
| `limits.per_target_per_minute` | `30` | 1 to 600 jobs per minute that may contact one resolved address; more answer `busy`. |
| `ssh.enabled` | `false` | Turns on `device_show` and `device_commands`. Needs a restart. Linux only. |
| `ssh.commands_file` | none | Local changes to the command lists ([device-commands.md](device-commands.md#local-commands-file)). With SSH on, a file that does not load stops the probe; with SSH off, `check-config` still reports it (exit status 1). |
| `ssh.max_output_bytes` | `262144` | 4096 to 4194304. |
| `ssh.connect_timeout_ms` | `10000` | 1000 to 30000, per TCP connection (device or jump host). |
| `ssh.auth_failure_cooldown_s` | `600` | 0 to 86400; `0` turns it off ([cool-downs](device-commands.md#logins-cool-downs-and-sessions)). |
| `log_level` | `info` | Env override `PROBE_LOG_LEVEL`. |

`closed` mode with both allow lists empty is refused at start-up.

## Applying changes

Both programs read their configuration only at start-up. Run `check-config` first.

| Changed | Docker | systemd |
|---|---|---|
| `hub.yaml`, or the hub's certificate files | `docker compose restart hub` | |
| `hub.env` or the hub's `compose.yaml` | `docker compose up -d --force-recreate hub` | |
| `probe.yaml`, or a file it names (`ca_file`, `commands_file`) | `docker compose restart probe` | `sudo systemctl restart probe` |
| `probe.env` or the probe's `compose.yaml` | `docker compose up -d --force-recreate probe` | `sudo systemctl restart probe` |
| SSH profiles, jump hosts, host keys | nothing: they apply to the next command | nothing |

Probes reconnect to a restarted hub on their own. A probe restart clears the SSH login cool-downs.

## Hub admin commands

They run on the hub (Docker: `docker compose exec hub probe-hub ...`) and work on its database directly. There is no
remote admin interface.

| Command | What |
|---|---|
| `probe-hub token create --name N --site S [--ttl 24h] [--replace]` | New enrolment token. `--replace` revokes the active probe of that name when the new one enrols. |
| `probe-hub token list` | Tokens and their state: `valid`, `used`, `expired`, `revoked`. |
| `probe-hub token revoke <id>` | Cancels an unused token. |
| `probe-hub probes list` | Probes with enrolment time, last seen and revocation. |
| `probe-hub probes revoke <name>` | Revokes a probe. A running hub drops its link within seconds. |
| `probe-hub check-config` | Validates the config and notes client token variables not set in this environment. |
| `probe-hub version` | |

The probe has `probe check-config`, `probe version` and `probe ssh ...` ([device-commands.md](device-commands.md)).

## Revoking a probe

`probe-hub probes revoke <name>`. It disappears from `list_probes`. If it is still running it logs that it needs
re-enrolling and retries only every 10 minutes; stop or uninstall it.

## Re-enrolling a probe

After revocation, or moving to a new hub. A probe with a saved identity ignores the enrolment token, and refuses to
start if the identity was enrolled with a different `hub_url`, so the identity must go.

1. On the hub: `probe-hub token create --name <same name> --site <site> --replace`.
2. On the probe host, delete only `identity.json`, which keeps the SSH store (profiles, secrets, host keys).
   - **Docker.** The volume name is the compose project name, from the `name: probe` line at the top of
     `deploy/remote-docker/compose.yaml`, plus `_probe-state`; confirm it with
     `docker volume ls --filter name=probe-state`. The probe image is distroless (no shell, no `rm`), so use a
     one-off container from any image that has `rm`:

     ```
     docker compose stop probe
     docker image ls busybox; docker image ls alpine      # an image already on the host avoids a pull
     docker run --rm --user 65532:65532 -v probe_probe-state:/s busybox rm /s/identity.json
     ```

     With no such image and no registry access, on a Linux host with Docker Engine, delete the file on the host:
     `sudo rm "$(docker volume inspect -f '{{ .Mountpoint }}' probe_probe-state)/identity.json"`.
   - **systemd:** `sudo systemctl stop probe && sudo rm /var/lib/probe/identity.json`
3. Put the new enrolment token in `probe.env` (Docker) or `/etc/probe/probe.env` (systemd), then start:
   `docker compose up -d --force-recreate probe` or `sudo systemctl start probe`.

Do not use `docker compose down -v` for this: it deletes the whole `probe-state` volume, including the SSH profiles,
their secrets and the recorded host keys.

## Backups

Hub: the `probe-hub_hub-data` volume (the database). Probe: the `probe_probe-state` volume or `/var/lib/probe`
(identity and SSH store, which holds secrets in plain files: protect the backup accordingly).

## Upgrading

Docker: pull the new code, `docker compose build` and `docker compose up -d`; state is in volumes. Probes reconnect to
a restarted hub on their own. systemd: build a new tarball and run its `install.sh`; it replaces the binary and unit,
keeps the config, and restarts the service.

## Hosts without a checkout

Build the images once with `scripts/build-images.sh` (tags `probetools/<name>:<version>` and `:latest` for the local
architecture) and move them with `docker save` and `docker load`, or use `--multi-arch` to push both architectures to
a registry. On the target, delete the `build:` block from the compose file and, for a tag other than `latest`, set
`HUB_IMAGE` or `PROBE_IMAGE` in the shell or a `.env` file next to `compose.yaml`. Step by step:
[deploy.md](deploy.md#docker-without-a-checkout).

## Logs and audit

JSON lines on stdout. Docker: `docker compose logs -f hub` (the compose files keep 5 files of 10 MB); systemd:
`journalctl -u probe`. The hub writes one audit line per tool call (client, tool, probes, target, outcome per probe,
duration, and for `path_test` the verdict; for `device_show` the command, never the output):

```
{"time":"...","level":"INFO","msg":"tool_call","event":"tool_call","client":"agents","tool":"ping","probes":["syd-1"],"target":"example.com","outcomes":{"syd-1":"ok"},"duration_ms":2310}
```

Failed calls are logged at `WARN` with an `error`. Each probe logs every job (`"msg":"job"`). Tokens, secrets and URL
credentials are never logged; query strings are removed from logged URLs.

## Monitoring

`GET /healthz` returns `ok` on both listeners: `https://<hub>:8443/healthz`, and MCP at
`http://127.0.0.1:8080/healthz` (or `https://<name in the certificate>:8080/healthz` once MCP is re-bound with TLS).
The images have no shell, so there is no in-container health check. Watch probes with `probe-hub probes list` (`LAST
SEEN`) or the container's restart count.

## A test listener on TCP 443

`path_test` tests only ports inside the receiving probe's `listen_ports`, and with the shipped deployments a probe
cannot open a port below 1024. To answer "is TCP 443 allowed from site A to site B" when nothing at B listens on 443,
give B a temporary listener, then have the agent run `tcp_connect` from A (or `path_test` to the probe). Firewalls
match the destination address too, so put the listener on the address whose rules you want to test.

- **A temporary real listener on a host at B.** For example `sudo nc -l 443` (netcat; flags vary by variant) or
  `sudo python3 -m http.server 443`, stopped when the test is done. The agent then uses `tcp_connect` with that host
  as `target` and `ports: [443]`. Simplest, and touches nothing in the probe.
- **The Docker probe in bridge mode.** Inside a container's own network namespace Docker sets
  `net.ipv4.ip_unprivileged_port_start=0`, so a uid 65532 process can bind 443 (verified with a uid 65532 test
  process on Docker 29; a full `path_test` this way has not been run). Switch B's
  probe to the bridge-mode alternative described in `compose.yaml`, publish `"443:443/tcp"`, and set
  `listen_ports: "443"` (one port or one range, so this replaces the usual range). The probe then reports container
  addresses, so the agent must give `path_test` the host's address as `to_address` (which needs `tcp_connect` too).
  Switch back afterwards.
- **The shipped Docker probe (host networking) cannot do it.** It uses the host's network namespace, where
  `ip_unprivileged_port_start` is normally 1024; the bind fails with permission denied (verified). `cap_add:
  NET_BIND_SERVICE` does not help: for a non-root container user Docker puts the capability only in the bounding set,
  and the probe binary's file capability grants `cap_net_raw` alone, so the process never holds it (verified: empty
  effective set). `sysctls:` cannot be set with host networking. Lowering the sysctl **on the host**
  (`sudo sysctl -w net.ipv4.ip_unprivileged_port_start=443`) does let it bind (verified in a shared network namespace),
  but it lets every process on the host bind ports from 443 up; restore `1024` after the test.
- **systemd.** The native binary carries no file capability, so ambient capabilities apply. Add a drop-in with
  `sudo systemctl edit probe`:

  ```
  [Service]
  AmbientCapabilities=
  AmbientCapabilities=CAP_NET_RAW CAP_NET_BIND_SERVICE
  CapabilityBoundingSet=
  CapabilityBoundingSet=CAP_NET_RAW CAP_NET_BIND_SERVICE
  ```

  set `listen_ports: "443"`, and `sudo systemctl restart probe`. Remove it afterwards with
  `sudo systemctl revert probe` and restore `listen_ports`. Not yet tested on a real systemd host.

If the bind still fails, `path_test` returns `listen_failed` and the exact error is in `listen.error.message`.
