# Deploying probe-tools

How to install the hub, install probes, and connect an AI agent. For the prerequisites and the port list, see the
[README](../README.md#prerequisites); for every configuration key, [operations.md](operations.md#configuration-reference);
when something fails, [troubleshooting.md](troubleshooting.md).

## How it fits together

- The hub has two listeners: the **probe listener** (`:8443`, TLS) for probes, and **MCP** (`:8080`, path `/mcp`) for
  agents. Both answer `GET /healthz` with `ok`.
- Probes connect out to the hub over a WebSocket and keep the link open; they reconnect on their own (backoff 1 s to
  60 s). The hub never connects to a probe.
- Each probe enforces its own **target policy** (`targets` in `probe.yaml`). That policy is the main guard.

Three secrets are involved. Keep their names straight:

| Name | What it is | Where it lives | Lifetime |
|---|---|---|---|
| **enrolment token** | lets one probe join the hub; fixes the probe's name and site | printed once by `probe-hub token create`; you put it in the probe's `probe.env` as `PROBE_ENROLL_TOKEN` | single use, valid 24 h by default |
| **probe secret** | the probe's lasting credential, issued when it enrols | the probe's `<state_dir>/identity.json` (mode 0600); the hub keeps only a hash | until the probe is revoked |
| **client token** | an agent's bearer token for MCP | `hub.env` on the hub, in the variable named by that client's `token_env`; the agent sends `Authorization: Bearer <client token>` | until you change it |

Enrolment, step by step:

1. On the hub, `probe-hub token create --name syd-1 --site syd` prints an enrolment token.
2. The probe starts with `hub_url` in `probe.yaml` and the token in its environment. It posts the token to the hub and
   receives a probe id and a probe secret, which it saves in `identity.json`. The token is now spent.
3. The probe opens a WebSocket to the hub and reports its version, addresses, checks, policy and listen ports.

## Deploy the hub

Work in `deploy/central/` of a checkout. The compose project is `name: probe-hub`, so the data volume is
`probe-hub_hub-data`.

### Certificates

Put the probe listener's certificate and key in `deploy/central/certs/` as `tls.crt` and `tls.key`.

- **`tls.crt` holds the full chain:** the server certificate first, then any intermediate certificates, all PEM. The
  hub sends what is in the file; a missing intermediate gives probes `certificate signed by unknown authority`.
- **The key must be readable by uid 65532** (the container's user), and no one else:
  `chown 65532:65532 certs/tls.key && chmod 0400 certs/tls.key`.
- **The name.** The certificate must cover, as a subject alternative name, the host name or IP in the hub's
  `public_url`, which is what probes put in `hub_url`. Use the IP as an IP SAN if probes connect by IP.
- **Renewal.** The hub reads the files once at start-up. Replace `tls.crt` and `tls.key`, run the `chown` and `chmod`
  above again on the new key, then `docker compose restart hub`. Connected probes drop and reconnect on their own.
- **Testing only:** `scripts/dev-certs.sh hub.example.com 10.1.2.3` (from the repository root) makes a throwaway CA
  and a certificate for the names and IPs given, and writes `ca.crt` for the probes' `ca_file`. It keeps the CA key
  next to the server key and makes `tls.key` world-readable; never use it for a real deployment.

**A private CA for an internal hub.** If the hub is only reachable inside your network, use your organisation's
internal CA, or make a small one on an admin machine (not the hub). Tested with OpenSSL 3:

```
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.crt -days 3650 \
  -subj "/CN=probe-tools internal CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout tls.key -out tls.csr -subj "/CN=hub.example.com"
printf "subjectAltName=DNS:hub.example.com,IP:10.1.2.3\nextendedKeyUsage=serverAuth\n" > san.ext
openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 397 -out tls.crt -extfile san.ext
openssl verify -CAfile ca.crt tls.crt        # prints "tls.crt: OK"
```

Copy `tls.crt` and `tls.key` to the hub's `certs/`, keep `ca.key` offline, and give every probe `ca.crt` as `ca_file`
(the probe adds it to the system roots). Agents that use MCP over TLS with this certificate need `ca.crt` too.

### hub.yaml

A complete minimal file. Paths are inside the container: the compose file mounts `./certs` at `/certs` and the
`hub-data` volume at `/data`.

```yaml
data_dir: /data

probe_listener:
  address: ":8443"
  tls_cert_file: /certs/tls.crt
  tls_key_file: /certs/tls.key
  public_url: wss://hub.example.com:8443   # CHANGE: the name or IP probes use; must be in the certificate

mcp:
  address: ":8080"
  path: /mcp

clients:
  - name: agents                  # one entry per agent, see "Connect an agent"
    token_env: HUB_TOKEN_AGENTS   # the variable in hub.env that holds this client's token
    probes: ["*"]                 # which probes it may use
    tools: ["*"]                  # which tools; "*" excludes the device tools (device_show, device_commands)

log_level: info
```

`public_url` is only printed by `token create`, as the `hub_url` to give probes. What matters is that probes can reach
that address and that the certificate covers its host name or IP.

### hub.env

One client token per client, in the variable its `token_env` names. Make the file mode 0600:

```
HUB_TOKEN_AGENTS=CHANGE-ME
```

Replace `CHANGE-ME` with the output of `openssl rand -hex 32`. Tokens must be at least 24 characters and all
different; the hub will not start otherwise (so it refuses the placeholder).

### Start and check

```
docker compose up -d
docker compose exec hub probe-hub check-config
curl -fsS http://127.0.0.1:8080/healthz        # MCP on its default loopback binding
```

The first `up` builds the image from the checkout (the build context is the repository root). After a change to
`hub.yaml`, run `docker compose restart hub`; after a change to `hub.env` or `compose.yaml`, run
`docker compose up -d --force-recreate hub` (the container must be recreated to see new environment values).

### Enrolment tokens

One per probe:

```
docker compose exec hub probe-hub token create --name syd-1 --site syd
```

Names and sites are `a-z`, `0-9` and `-`, 1 to 63 characters. The token is shown once and works once. `--ttl 72h`
changes the 24-hour validity. `token create` refuses a name an active probe already has unless you add `--replace`.

### A reverse proxy in front of 8443

Let the hub terminate TLS itself, as above. A TLS-terminating reverse proxy in front of 8443 also works (set
`probe_listener.insecure_plaintext: true`, keep the proxy-to-hub hop on a trusted network, and pass WebSocket
upgrades), but then every probe shares the proxy's address for the hub's per-address enrolment and failed-login
limits, so a burst of bad requests can delay new probes' enrolment. Connected probes are not affected. A proxy in
front of MCP (8080) has no such cost.

## Deploy a probe

### probe.yaml and the target policy

The same file serves Docker and systemd. A complete minimal file:

```yaml
hub_url: wss://hub.example.com:8443   # CHANGE: the hub's public_url
# ca_file: /etc/probe/ca.crt          # only for a hub certificate from a private CA

targets:
  mode: closed                        # required: closed or open
  allow_cidrs:
    - 10.20.0.0/16                    # CHANGE: the networks this probe may test
  allow_hosts:
    - "*.corp.example"                # CHANGE or remove: names it may test
  deny_cidrs: []                      # never touched, in either mode
  deny_hosts: []

listen_ports: "40000-40100"           # for path_test; "" turns listening off
```

Choose the policy deliberately:

- `targets.mode` is required; there is no default.
- `closed`: the probe reaches only `allow_cidrs` and names matching `allow_hosts`. Use this unless the site is meant to
  be open. `closed` with both allow lists empty is refused at start-up.
- `open`: the probe reaches anything except `deny_cidrs`, `deny_hosts` and the always-refused addresses (loopback,
  link-local and cloud metadata, multicast, the probe's own addresses; the full list is in
  [security.md](security.md#always-refused-addresses)).
- `deny_cidrs` and `deny_hosts` are the no-touch list. They apply in both modes to everything a check connects to: the
  target, every `http_check` redirect, a `dns_lookup` `server`, the `path_test` destination, and a device and its jump
  host for `device_show`. They do not apply to the name `dns_lookup` looks up, nor to the probe's own resolvers that
  `dns_lookup` uses when no `server` is given. `deny_hosts` matches requests made by name only, so list the addresses
  in `deny_cidrs` too.
- `listen_ports` is one port or one range. The receiving probe of a `path_test` opens a port from it for the test.
  Allow the range inbound in the probe host's firewall from the other probe sites.

Unknown keys are refused. Every key: [operations.md](operations.md#probeyaml).

### Docker

Work in `deploy/remote-docker/` of a checkout (or a copy of that directory with a loaded image, see
[Docker without a checkout](#docker-without-a-checkout)). The compose project is `name: probe`, so the state volume is
`probe_probe-state`.

1. Edit `probe.yaml` as above. For a private CA, copy its `ca.crt` here, uncomment the
   `- ./ca.crt:/etc/probe/ca.crt:ro` line in `compose.yaml`, and set `ca_file: /etc/probe/ca.crt`.
2. Create `probe.env`, mode 0600:

   ```
   PROBE_ENROLL_TOKEN=CHANGE-ME-enrolment-token-from-token-create
   # HTTPS_PROXY=http://proxy.corp.example:3128   # only if this site reaches the hub through a proxy
   ```

3. Check and start:

   ```
   docker compose run --rm probe check-config
   docker compose up -d
   docker compose logs -f probe        # look for "enrolled" then "connected to hub"
   ```

Once enrolled the identity lives in the `probe-state` volume and the token is no longer used; you may empty the line.

**After a change:** to `probe.yaml` (or a file it names, such as a commands file), run `docker compose restart probe`;
the probe reads its configuration only at start-up. To `probe.env` or `compose.yaml` (a new volume line, say), run
`docker compose up -d --force-recreate probe`, because the environment and mounts are fixed when the container is
created. Run `docker compose run --rm probe check-config` first.

The compose file uses **host networking**: checks see the site's real interfaces, routes, DNS and source addresses,
and `listen_ports` are opened on the host's own addresses (allow them in the host firewall). The container shares the
host's network, so the target policy is the real guard. Host networking is Linux only. The container runs as uid 65532
with `cap_drop: [ALL]`, `cap_add: [NET_RAW]`, a read-only root filesystem and `no-new-privileges`; keep those lines
(without `NET_RAW` the binary does not start). The image is distroless: there is no shell in it. A bridge-mode
alternative is described in comments in `compose.yaml`.

### Docker without a checkout

A probe site needs only the `deploy/remote-docker/` directory and the image. On a machine with a checkout and the same
CPU architecture as the site (`uname -m`: `x86_64` is amd64, `aarch64` is arm64):

```
scripts/build-images.sh probe                                   # tags probetools/probe:<version> and :latest
docker save probetools/probe:latest | gzip > probe-image.tar.gz
```

Copy `probe-image.tar.gz` and `deploy/remote-docker/` to the site, then there: `docker load -i probe-image.tar.gz`,
delete the `build:` block from `compose.yaml`, and continue with [Docker](#docker). The compose file uses
`probetools/probe:latest` unless you set `PROBE_IMAGE` (in the shell or a `.env` file next to `compose.yaml`; not in
`probe.env`, which only feeds the container). Use `docker save` and `docker load`, or a registry: the binary's
`NET_RAW` file capability lives in an extended attribute, which plain tar or directory exports can drop. For other
architectures, `scripts/build-images.sh --multi-arch` builds amd64 and arm64 and pushes them to a registry
(`REGISTRY=registry.example.com/netops`). The hub works the same way with `scripts/build-images.sh hub` and `HUB_IMAGE`.

### Linux server with systemd

Build the release tarballs on any machine with Docker (no Go needed):

```
scripts/build.sh                  # or: VERSION=v1.2.3 ARCHES="amd64" scripts/build.sh
```

This writes `dist/probe-<version>-linux-<arch>.tar.gz` for `amd64` and `arm64`, and `dist/SHA256SUMS`. Copy the one
that matches the server (`uname -m`: `x86_64` is `amd64`, `aarch64` is `arm64`) and, as root:

```
tar xzf probe-<version>-linux-<arch>.tar.gz
cd probe-<version>-linux-<arch>
sudo ./install.sh                 # asks for the enrolment token, input hidden
```

`install.sh` needs no network. It installs `/usr/local/bin/probe`, a `probe` system user, `/etc/probe/probe.yaml`
(an example, 0640 root:probe; an existing file is kept), `/etc/probe/probe.env` (the token, 0600 root),
`/var/lib/probe` (state, 0700 probe) and the `probe.service` unit, enabled at boot. It runs `check-config` as the
`probe` user and does not start the service while `hub_url` is still `hub.example.com` or there is neither a token nor
a saved identity. Then:

```
sudoedit /etc/probe/probe.yaml     # hub_url, targets, listen_ports, ca_file
sudo systemctl start probe         # restart after later config changes: sudo systemctl restart probe
journalctl -u probe -f             # look for "enrolled" then "connected to hub"
```

For a proxy, add `HTTPS_PROXY=http://proxy.corp.example:3128` to `/etc/probe/probe.env`. For a private CA, put the CA
certificate where user `probe` can read it (for example `/etc/probe/ca.crt`, `chgrp probe`, mode 0640) and set
`ca_file`. The unit grants only `CAP_NET_RAW` and applies systemd sandboxing. Remove with
`sudo ./install.sh --uninstall` (keeps config and state) or `--uninstall --purge` (deletes them and the user).

## Connect an agent

Any MCP client that supports streamable HTTP works. Each agent gets its own client entry, so it has its own token,
scope and audit name.

### Add a client

Add the client to `hub.yaml` and its client token to `hub.env`:

```yaml
clients:
  - name: claude-netops
    token_env: HUB_TOKEN_CLAUDE_NETOPS
    probes: ["*"]                  # or ["site:syd", "mel-*"]
    tools: ["*"]                   # add "device_show", "device_commands" to grant device commands
```

```
HUB_TOKEN_CLAUDE_NETOPS=CHANGE-ME          # openssl rand -hex 32
```

Apply both with `docker compose up -d --force-recreate hub`.

### Make MCP reachable

The compose file publishes MCP as `127.0.0.1:8080`, so only the hub host itself can reach it. A URL such as
`http://hub.example.com:8080/mcp` will not work from another host until you choose one of these:

- **Agent on the hub host:** use `http://127.0.0.1:8080/mcp`.
- **SSH tunnel** from the agent's host, no hub change (needs SSH to the hub host):
  `ssh -N -L 8080:127.0.0.1:8080 admin@hub.example.com`, then use `http://127.0.0.1:8080/mcp`.
- **Bind to an internal address with TLS**, below. The client token then crosses the network, so do not do this
  without TLS (or a TLS reverse proxy in front), and never publish MCP on the internet.

### Remote MCP over TLS

The example: hub internal IP `10.1.2.3`, name `hub.example.com` resolving to it for the agents, certificate covering
that name (or the IP as an IP SAN). The probe listener's certificate can serve both if it covers the name agents use.

1. In `deploy/central/compose.yaml`, change the MCP port line from `"127.0.0.1:8080:8080"` to:

   ```yaml
         - "10.1.2.3:8080:8080"
   ```

2. In `hub.yaml`, add the TLS files (paths inside the container):

   ```yaml
   mcp:
     address: ":8080"
     path: /mcp
     tls_cert_file: /certs/tls.crt
     tls_key_file: /certs/tls.key
   ```

3. Apply and check, on the hub host or an agent host:

   ```
   docker compose up -d --force-recreate hub
   curl -fsS https://hub.example.com:8080/healthz                # prints ok; add --cacert ca.crt for a private CA
   curl -fsS --resolve hub.example.com:8080:10.1.2.3 https://hub.example.com:8080/healthz   # if the name resolves elsewhere
   ```

   The name you use must be in the certificate: `https://10.1.2.3:8080/` fails unless the IP is an IP SAN.
   `http://127.0.0.1:8080/healthz` no longer works after this change: nothing listens on loopback port 8080, and the
   port now speaks TLS (plain HTTP gets `Client sent an HTTP request to an HTTPS server`). Monitor the https URL
   instead. Allow TCP 8080 on the hub host from agent hosts only.

4. Add it to Claude Code on the agent's host. `--scope user` makes it available in every project. Keep `--scope`, the
   name and the URL before `--header`, which takes the rest of the line:

   ```
   read -rs PROBES_TOKEN            # paste the client token; not echoed, not in shell history
   claude mcp add --scope user --transport http probes https://hub.example.com:8080/mcp \
     --header "Authorization: Bearer $PROBES_TOKEN"
   unset PROBES_TOKEN
   claude mcp list                  # probes should show as connected
   claude mcp get probes            # details; a failure shows on an "Issue:" line
   ```

   The token is stored in plain text in Claude Code's local configuration (`~/.claude.json` for user and local
   scope); protect that file. Typing the token on the command line instead of using `read` also leaves it in your shell
   history. Do not use `--scope project`: it writes `.mcp.json` into the project, which is meant to be committed. For a
   private CA, start Claude Code with `NODE_EXTRA_CA_CERTS=/path/to/ca.crt` (documented by Claude Code for custom CAs;
   not tested here against this hub).

### Configure the agent

Claude Code with the hub on the same host:

```
claude mcp add --transport http probes http://127.0.0.1:8080/mcp --header "Authorization: Bearer CHANGE-ME-client-token"
```

Other clients take the same three things (URL, transport, header); a typical JSON configuration:

```json
{
  "mcpServers": {
    "probes": {
      "type": "http",
      "url": "http://127.0.0.1:8080/mcp",
      "headers": { "Authorization": "Bearer CHANGE-ME-client-token" }
    }
  }
}
```

### Confirm

Ask the agent to call `list_probes`; your probes should be listed with `"online": true`. Without an agent:

```
curl -s http://127.0.0.1:8080/mcp \
  -H "Authorization: Bearer CHANGE-ME-client-token" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_probes","arguments":{}}}'
```

With remote MCP over TLS, use the https URL (and `--cacert ca.crt` for a private CA). A wrong or missing token gives
HTTP 401. Then point the agent at [agent-guide.md](agent-guide.md).
