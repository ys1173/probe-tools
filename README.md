# probe-tools

Network troubleshooting for AI agents, run from the sites where the problem is. A hub is an MCP server; small probes
installed at each site connect out to it and run fixed network checks (ping, traceroute, DNS, TCP, TLS, HTTP,
probe-to-probe path tests) when an agent asks. Optionally, a probe can also run allowed read-only commands on network
devices over SSH.

**Each file is self-contained and short enough to read in full; read the one for your task.** This README is the
summary and the index; the details are in [docs/](docs/) and the design in [DESIGN.md](DESIGN.md).

**Maturity: early.** The end-to-end test runs the hub, three probes, targets and fake SSH devices in Docker on one host
(Docker networks, no real WAN). One short trial ran across real hosts: a probe image on an amd64 Debian 12 host against
a real Ubiquiti EdgeRouter (EdgeOS). The other seven device platforms have not met real hardware, and the native amd64
binary and the systemd unit have not run on a real amd64 host. Details: [docs/testing.md](docs/testing.md).

```
agent (any MCP client) --MCP over HTTP(S), client token--> hub <--WebSocket over TLS, opened by the probe-- probe (site A)
                                                            ^----------------------------------------------- probe (site B)
```

The hub sends each job to the probes named in the call and returns one result per probe. Each probe enforces its own
target policy; the hub and the agent can ask for less than it allows, never more. Probes never accept connections from
the hub. An offline probe answers `probe_offline` at once; jobs are never queued.

## Start here

| You are | Read, in order |
|---|---|
| **Deploying it (operator)** | [Prerequisites](#prerequisites) and [Ports](#ports) below, then [docs/deploy.md](docs/deploy.md), then [Verify it works](#verify-it-works). Keep [docs/operations.md](docs/operations.md) and [docs/troubleshooting.md](docs/troubleshooting.md) for later. |
| **Using it (AI agent)** | [docs/agent-guide.md](docs/agent-guide.md). It has everything an agent needs: conventions, every tool, recipes and every error code. |
| **Running device commands over SSH (network engineer, optional)** | [docs/device-commands.md](docs/device-commands.md), starting with its worked example. |

## Prerequisites

- **Hub host:** Docker Engine with Compose v2 (`docker compose version`), reachable from every probe site on TCP 8443.
- **Each probe site:** a Linux host with Docker and Compose v2 (the probe uses host networking, which needs Linux), or
  a Linux server with systemd (amd64 or arm64; see the maturity note above for what has run where).
- **The images or binaries.** No images are published. Either clone the repository
  (`git clone https://github.com/ys1173/probe-tools.git`) where you deploy, and the compose files build the images, or
  build once and copy them: `docker save` / `docker load` for images, `scripts/build.sh` tarballs for systemd
  ([docs/deploy.md](docs/deploy.md#docker-without-a-checkout)). Device commands over SSH need a build that includes
  them: `probe ssh help` must work.
- **A TLS certificate for the hub** whose name or IP (subject alternative name) matches the host in the hub's
  `public_url`, trusted by the probes: from a public CA, or from a private CA whose certificate each probe gets as
  `ca_file` ([certificates](docs/deploy.md#certificates)).
- **Outbound TCP from each site to the hub's port 8443**, directly or through an HTTP proxy (`HTTPS_PROXY`). Sites need
  no inbound rule for the hub.

## Ports

| From | To | Port | For |
|---|---|---|---|
| each probe | hub | TCP 8443 (TLS) | Enrolment and the probe's link to the hub, opened by the probe. The hub's compose file publishes 8443 on **all** interfaces of the hub host. |
| agent hosts | hub | TCP 8080, path `/mcp` | MCP. The hub's compose file binds it to `127.0.0.1` only; see [Connect an agent](docs/deploy.md#connect-an-agent). |
| probe | targets | whatever the check uses (ICMP, DNS 53, the TCP/UDP ports asked for) | the checks |
| probe | devices and jump hosts | TCP 22 by default | device commands over SSH, when turned on |
| sending probe | receiving probe | the receiver's `listen_ports` (TCP or UDP) | `path_test` only, while a test runs |

Firewall rules **on the hub host** (inbound):

| Allow | From | When |
|---|---|---|
| TCP 8443 | the probe sites' outbound addresses (their NAT or proxy addresses) | always |
| TCP 8080 | agent hosts only | only if you publish MCP beyond loopback ([remote MCP](docs/deploy.md#remote-mcp-over-tls)); never from the internet |
| TCP 22 (SSH) | agent hosts | only if agents reach MCP through an SSH tunnel |

## Verify it works

1. **Configs are valid.** On the hub: `docker compose exec hub probe-hub check-config`. On a Docker probe:
   `docker compose run --rm probe check-config`. On a systemd probe: `sudo -u probe probe check-config`.
2. **The hub answers.** From a probe site: `curl -fsS https://hub.example.com:8443/healthz` prints `ok` (add
   `--cacert ca.crt` for a private CA); this proves the route, the firewall, the certificate and its name in one go.
   MCP: on the hub host, `curl -fsS http://127.0.0.1:8080/healthz` prints `ok` while MCP is on its default loopback
   binding. After you re-bind MCP to an internal address with TLS, loopback no longer answers; use
   `curl -fsS https://<name in the certificate>:8080/healthz` instead
   ([remote MCP](docs/deploy.md#remote-mcp-over-tls)).
3. **The probe is online.** Your agent calls `list_probes` and sees the probe with `"online": true`. Without an agent,
   `docker compose exec hub probe-hub probes list` shows it with a recent `LAST SEEN`.

## Tools

The hub offers 15 tools. A client sees only the tools its configuration grants; `tools: ["*"]` grants all but the two
device tools, which must be named. Inputs, defaults, sample results and errors: [docs/agent-guide.md](docs/agent-guide.md).

| Tool | What it does |
|---|---|
| `list_probes` | The probes this client may use: site, online, addresses, policy summary, `listen_ports`, SSH profiles. |
| `diagnose` | DNS, ping, TCP, TLS and HTTP to one target in one call; names the first layer that failed. |
| `ping`, `traceroute`, `path_mtu` | ICMP echo; hop-by-hop path (ICMP, UDP or TCP); largest unfragmented packet. |
| `dns_lookup` | One DNS query, from the probe's resolvers or a given server. |
| `tcp_connect` | Whether 1 to 10 TCP ports accept connections; optional TLS handshake and banner. |
| `tcp_template`, `udp_probe` | Fixed, harmless requests that make a service identify itself (HTTP HEAD, SMTP EHLO, DNS, NTP, SNMPv3 discovery, ...). |
| `tls_check`, `http_check` | Certificate chain and handshake; one HTTP(S) request with timings (the body is never returned). |
| `probe_info` | The probe's interfaces, routes, resolvers, capabilities and policy. |
| `path_test` | Whether TCP or UDP gets from probe A to probe B on a port in B's `listen_ports`. |
| `device_show`, `device_commands` | Run one allowed read-only command on a network device over SSH; list what is allowed. |

Every tool is marked `readOnlyHint: true`: none changes a target's configuration or state. They do make real
connections, and three do a little more: `path_test` opens a listening port on the receiving probe for up to 20 s,
`device_show` logs in to the device (it appears in the device's login and AAA records) and on EdgeOS and PAN-OS sends
one session-only paging setting first, and `http_check` sends a real `GET` or `HEAD`. See
[docs/security.md](docs/security.md#what-read-only-means).

## Documentation

| File | Answers |
|---|---|
| [docs/deploy.md](docs/deploy.md) | How do I install the hub and a probe (Docker or systemd), get certificates, enrol probes, and connect an agent, including remote MCP over TLS? |
| [docs/agent-guide.md](docs/agent-guide.md) | For AI agents: how do I call each tool, what do results look like, how do I answer common questions, and what does each error mean? |
| [docs/device-commands.md](docs/device-commands.md) | How do I let a probe run read-only commands on switches, routers and firewalls over SSH, safely? |
| [docs/operations.md](docs/operations.md) | Every `hub.yaml` and `probe.yaml` key; admin commands; applying changes; revoke, re-enrol, upgrade, back up; logs and audit; a test listener on port 443. |
| [docs/troubleshooting.md](docs/troubleshooting.md) | A probe is offline, cannot reach the hub, TLS fails, the agent gets 401, a device command fails: what now? |
| [docs/security.md](docs/security.md) | What protects what, which addresses are always refused, what "read-only" covers, and the known limits. |
| [docs/testing.md](docs/testing.md) | What has and has not been tested, how to run the unit and end-to-end tests, and the build scripts. |
| [DESIGN.md](DESIGN.md) | The design rules, the probe link protocol and how device commands are built. |

## Licence

MIT. See [LICENSE](LICENSE).
