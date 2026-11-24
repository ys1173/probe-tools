# Device commands over SSH

Off by default. With it on, a probe logs in to a switch, router or firewall it can reach and runs one allowed
read-only command, so an agent can see what the device itself reports. Device passwords and keys are entered on the
probe and never pass through the hub or the agent. The probe, not the agent, picks the credentials and the platform,
by the device's address. The probe must run on Linux (the credential store relies on Unix file protections). Device
commands need a build that includes them: `probe ssh help` must work.

For the deployment itself see [deploy.md](deploy.md); for how agents call the tools, [agent-guide.md](agent-guide.md);
for failures, [troubleshooting.md](troubleshooting.md#device-commands).

## Platforms

| Platform | Devices | Tested on hardware |
|---|---|---|
| `ios` | Cisco IOS and IOS-XE | no |
| `nxos` | Cisco NX-OS | no |
| `junos` | Juniper Junos | no |
| `eos` | Arista EOS | no |
| `panos` | Palo Alto PAN-OS | no |
| `fortios` | Fortinet FortiOS | no |
| `edgeos` | Ubiquiti EdgeRouter (EdgeOS) | yes, see [testing.md](testing.md#what-has-been-tested) |
| `routeros` | MikroTik RouterOS | no |

The untested platforms' command lists and drivers come from vendor documentation and public reports. Expect to correct
a list or a driver on first use.

## What it sends to a device

`device_show` is the only tool that takes a command line from the agent. Before any connection, the command must pass
the floor and the probe's list for the device's platform ([Which commands are allowed](#which-commands-are-allowed)).
Then the probe opens one SSH session, sends the command, reads the output and closes the session. It sends nothing
else, with two exceptions, both operational-mode CLI settings (paging off) that change no configuration and last only
for that SSH session (for PAN-OS, that it is session-only rests on community reports):

| Platform | Transport | Sent before the command |
|---|---|---|
| `ios`, `nxos`, `eos`, `junos`, `fortios` | SSH exec channel | nothing (a pager prompt, if one appears, is answered with a space) |
| `panos` | interactive shell | `set cli pager off` |
| `edgeos` | interactive shell | `terminal length 0` |
| `routeros` | SSH exec channel | nothing; the login name gets `+cet512w` (console options for plain, wide output) |

The login itself shows in the device's logs and AAA accounting. The probe never sends `enable` (the floor refuses
it), so the device account must land directly at a privilege level that can run the show commands you need. The
device's own authorisation is the second guard: give the probe an account that can only read.

## Worked example

Site `syd`, probe `syd-1`. Ten Cisco IOS switches (10.30.1.11 to 10.30.1.20) share one TACACS+ account,
`svc-netprobe`. One Juniper router (10.30.1.1, in the same management subnet) has its own local account, `probe-ro`.
All of them are reachable only through a jump host, `bastion` (10.20.0.5), where the probe logs in as `probe` with an
SSH key.

**Before you start.**
- The TACACS+ account must land at a privilege level that can run show commands without `enable` (on IOS, have
  TACACS+ authorisation set the privilege level). On Junos, use a login class whose shell is the CLI, not `root`.
- The jump host's sshd must allow TCP forwarding for user `probe` (`AllowTcpForwarding`), because the probe asks it to
  open a connection to the device.

**1. Turn it on.** In `probe.yaml`, allow the jump host and the device subnet (the devices are checked against the
policy even when reached through the jump host) and enable SSH:

```yaml
targets:
  mode: closed
  allow_cidrs:
    - 10.20.0.5/32     # jump host
    - 10.30.1.0/24     # switch and router management
ssh:
  enabled: true
```

Make the jump host's private key readable by the probe, then restart:

| | Docker (in `deploy/remote-docker/`) | systemd |
|---|---|---|
| key | `sudo chown 65532 probe_ed25519 && sudo chmod 0400 probe_ed25519`, and add `- ./probe_ed25519:/etc/probe/import.key:ro` under `volumes:` in `compose.yaml` | `sudo install -m 0400 -o probe probe_ed25519 /var/lib/probe/import.key` |
| restart | `docker compose up -d --force-recreate probe` (a new volume line needs a new container) | `sudo systemctl restart probe` |
| key path below | `/etc/probe/import.key` | `/var/lib/probe/import.key` |

Every `probe ssh` command runs as the probe's own user, which owns the store. Set an alias for the rest of this
example:

```
alias pssh='docker compose exec -it probe probe ssh'   # Docker, in deploy/remote-docker/
alias pssh='sudo -u probe probe ssh'                   # systemd (never plain sudo: root is refused)
```

**2. Add the jump host.**

```
pssh jump add --name bastion --address 10.20.0.5 --username probe --auth key --key-file /etc/probe/import.key
```

It connects, prints the jump host's key type and `SHA256:` fingerprint, and asks
`Record this key and add the jump host? [y/N]`. Compare it with the jump host's own key, of the same type, before
answering `y`; on the jump host: `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` (or `..._rsa_key.pub` if the
probe printed `ssh-rsa`). The key file is copied into the store. Now remove the key: Docker, delete the volume line
and run `docker compose up -d --force-recreate probe`, then delete the file; systemd,
`sudo rm /var/lib/probe/import.key`.

**3. Add the profiles.** Each password is asked for twice, without echo.

```
pssh profile add --name switches --cidr 10.30.1.0/24 --platform ios --username svc-netprobe --auth password --jump bastion
pssh profile add --name edge-rtr --cidr 10.30.1.1/32 --platform junos --username probe-ro --auth password --jump bastion
```

The second prints `note: profile switches comes first and covers some of these addresses; the first matching profile
wins`. Without a fix the router would be treated as an IOS switch with the TACACS+ account. Put the specific profile
first:

```
pssh profile move edge-rtr --before switches
pssh profile list            # edge-rtr is now above switches
```

**4. Record the devices' host keys.** Password profiles never send a password to a device whose key is not recorded.

```
pssh hostkey learn 10.30.1.1 10.30.1.{11..20}
```

For each address it connects through `bastion` without logging in, prints the key type and fingerprint and the
profile that covers it, and asks `Record ...? [y/N]`. Check each against a record you trust: an admin host that
already knows the device (`ssh-keygen -lF 10.30.1.11` reads its `known_hosts`), your inventory, or the device console.
Compare the same key type the probe printed. Use `--yes` only for addresses you have already checked: `learn` records
whatever key answers.

**5. Test from the probe.**

```
pssh test --device 10.30.1.11 --command "show version"
pssh test --device 10.30.1.1 --command "show interfaces terse"
```

This runs the command exactly as `device_show` would (policy, profile, floor, list, host key) and prints the outcome,
profile, host key and output. It exits with status 1 for any outcome other than `ok`.

> **Careful with a shared account.** `probe ssh test` runs in its own process: it neither sees nor sets the running
> probe's login cool-down, and starts with a fresh one each time. Every run with a wrong password is a real failed
> login. With a TACACS+ or RADIUS account shared by many devices, a few repeated tests can lock the account
> everywhere. After an `auth_failed`, fix the password (`pssh profile set switches --password`) before testing again.

**6. Grant the tools to a client.** On the hub, add a client to `hub.yaml`, its client token to `hub.env`
(`HUB_TOKEN_NETOPS=` and the output of `openssl rand -hex 32`), and run `docker compose up -d --force-recreate hub`.
To grant an existing client instead, add the two tool names to its `tools` and run `docker compose restart hub`.

```yaml
clients:
  - name: netops
    token_env: HUB_TOKEN_NETOPS
    probes: ["site:syd"]                          # the probes this client may run device commands on
    tools: ["*", "device_show", "device_commands"]
```

`tools: ["*"]` does not include the device tools; they must be named. Only a client with a device tool sees the
probes' SSH profiles in `list_probes`.

**7. Use it.** Profile changes apply to the next command with no restart. `device_commands` shows the profiles at once;
`list_probes` shows them after the probe next connects to the hub (`docker compose restart probe` or
`sudo systemctl restart probe` to hurry it). Then, from the agent:
`device_show` with `probe: "syd-1"`, `device: "10.30.1.11"`, `command: "show interfaces status"`.

**Without a terminal** (a script, or an agent doing the setup), the prompts cannot be answered. Use
`docker compose exec -T probe probe ssh ...` (no `-it`) or `sudo -u probe probe ssh ...` with:
`--password-stdin` and the secret on stdin (`... --password-stdin < secret-file`), for `profile add`, `profile set`,
`jump add` and `jump set`; `jump add --accept-host-key SHA256:...` with a fingerprint you checked; and
`hostkey learn --yes` only for addresses whose keys you checked. `probe ssh profile list` and `probe ssh jump list`
(which also shows the profiles using each jump host) show the result.

## Profiles and their order

A profile names the device ranges it covers (`--cidr`, repeatable, up to 16), the platform, the user name, password or
key, the port (`--port`, default 22) and optionally a jump host (`--jump`). Profile and jump host names are `a-z`,
`0-9` and `-`, 1 to 32 characters.

- **A profile matches on the device's resolved address, never its name,** so DNS cannot steer a password to another
  host. No profile means the device is refused (`unavailable`).
- **The first matching profile wins.** `profile add` appends at the end and warns when an earlier profile overlaps.
  Put specific ranges (a /32) before broad ones with `probe ssh profile move NAME --before OTHER`, or send one to the
  end with `probe ssh profile move NAME --last`.
- A range wider than /8 (IPv4) or /16 (IPv6) is refused: a profile must name the networks it is for.
- `--legacy` also offers old SSH algorithms (SHA-1 key exchange, CBC ciphers, `ssh-rsa`); use it only for a device
  that offers nothing newer.
- Keys are recommended over passwords. With `--auth key`, the key file is copied into the store and a passphrase is
  asked for if it has one. A password or passphrase is never taken from a flag or environment variable; for
  automation, `--password-stdin` reads one line from stdin (`docker compose exec -T ... < file`) and is refused on a
  terminal.

## Host keys

Keys are recorded per address and port, and per jump host (the same private address behind two jump hosts is two
devices). A key that differs from the recorded one is always refused (`host_key_changed`) before any credential is
sent. When no key is recorded:

- **A key profile always records the key on first use** and logs in (`host_key_first_use: true`). A public-key login
  gives a fake server nothing it can reuse: it sees a signature, not a secret.
- **A password profile refuses by default** (`host_key_unknown`), because a fake server at that address would receive
  the password. Record the key first with `hostkey learn` (or `hostkey add`), or opt the profile in with
  `--trust-on-first-use`, which sends the password to whoever answers first (`profile add` warns).
- **A jump host's key** is confirmed when the jump host is added and is never trusted on first use. If it is later
  missing (after `hostkey forget`, say), `device_show` answers `host_key_unknown` with `detail` starting
  `jump host NAME:`. Fix it with `probe ssh hostkey learn ADDR`, where ADDR is the jump host's address exactly as
  `probe ssh jump list` shows it (`10.20.0.5` in the worked example), without `--jump`: `learn` recognises a
  configured jump host by that address and records the key for it. A changed jump host key: `hostkey forget ADDR`,
  then `hostkey learn ADDR`, after checking why it changed.

```
probe ssh hostkey list
probe ssh hostkey learn 10.1.0.1 10.1.0.2 [--jump J] [--legacy] [--yes]   # connect without logging in, show, ask
probe ssh hostkey add 10.1.0.1 SHA256:...              # the probe connects and checks the key matches
probe ssh hostkey add 10.1.0.1 "ssh-ed25519 AAAA..."   # or give the public key; no connection
probe ssh hostkey forget 10.1.0.1 [--jump J]           # after a device was replaced or re-keyed
```

`learn` takes the port, jump host and algorithms from the profile that covers the address (override with `--jump`,
`ADDR:PORT` or `--legacy`). `probe ssh profile list` shows in its `FIRST-USE` column what each profile does with an
unknown key: `refuse`, `trust` (key profile) or `trust (opted in)`.

## Changing credentials and profiles

| Change | Command | Notes |
|---|---|---|
| Rotate a profile's password | `probe ssh profile set NAME --password` | Asked for twice (or `--password-stdin` for automation). Keeps the profile's place in the order and its settings. Ends any login cool-down for it. |
| Rotate a profile's key | `probe ssh profile set NAME --key-file PATH` | The key must be readable by the probe's user, as in the [worked example](#worked-example). Asks for the passphrase if the key has one. |
| Rotate a jump host's password or key | `probe ssh jump set NAME --password` or `--key-file PATH` | Ends the jump host's cool-down. |
| Old algorithms on or off | `probe ssh profile set NAME --legacy` or `--no-legacy`; `probe ssh jump set NAME --legacy` or `--no-legacy` | |
| Trust on first use on or off | `probe ssh profile set NAME --trust-on-first-use` or `--no-trust-on-first-use` | Applies to password profiles; key profiles always trust on first use. |
| Change a profile's ranges, platform, user name, port, jump host or auth type | `probe ssh profile remove NAME`, `probe ssh profile add ...`, then `probe ssh profile move NAME --before OTHER` | `add` puts it last, so move it back. Recorded host keys are kept (they belong to addresses, not profiles). |
| Change a jump host's address, port, user name or auth type | remove the profiles that use it, `probe ssh jump remove NAME`, `probe ssh jump add ...`, add the profiles again | `jump remove` refuses while a profile uses it, and forgets the device keys learnt through it: learn them again. |
| A device was replaced or re-keyed | `probe ssh hostkey forget ADDR [--jump J]`, then `probe ssh hostkey learn ADDR` | |
| Remove a profile | `probe ssh profile remove NAME` | Removes its secret and key too. |
| Remove a jump host | `probe ssh jump remove NAME` | Only when no profile uses it. |

Changes apply to the next command; no restart. Back up the store with the rest of the probe's state
([operations.md](operations.md#backups)), or you will have to enter everything again. Never use
`docker compose down -v` on a probe: it deletes the state volume and the store with it.

## Which commands are allowed

A command runs only if it passes, in order: **the floor** (no list can override it), **no deny pattern** of this probe
matches, and **an allow pattern** for the profile's platform matches. Patterns are regular expressions over the whole
command after spaces are collapsed. Commands are written out in full: the probe does not expand abbreviations
(`show interfaces`, not `sh int`).

**Built-in lists.** Per platform, covering physical and operational state: interfaces, routes, neighbours, counters,
hardware. They leave out configuration, keys, users, SNMP communities and tech-support; VRRP and HSRP appear in brief
or summary form only, since the detailed forms may show authentication text. You can read them in
`internal/devcmd/lists/<platform>.yaml`, with their sources; `device_commands` shows the effective list on each probe.

### Local commands file

A local file (`ssh.commands_file` in `probe.yaml`) adds to or removes from the lists per platform, or replaces one:

```yaml
platforms:
  ios:
    allow:
      - '^show ip ospf database(?: router| network| summary)?$'   # added to the built-in list
    deny:
      - '^show ip route vrf .*$'                                  # removes matches; deny always wins
  fortios:
    builtin: false                                                # drop the built-in list: only these run
    allow:
      - '^get system status$'
      - '^get router info routing-table all$'
```

- Keys are `platforms:`, a platform name, then `allow:`, `deny:` and `builtin:`. `builtin: false` drops only the
  platform's built-in allow list, making the file's `allow` patterns the whole list (none means nothing runs on it).
  The file's `deny` patterns for that platform still apply, and so does the floor. Left out, the built-in list is used.
- A pattern starts with `^`, ends with `$`, is at most 512 characters, and is written out (the `<IF>`-style placeholders
  of the built-in lists are not available). Deny patterns ignore case, but nothing else is canonicalised: a deny meant
  to keep one interface out must cover every spelling (`Gi1/0/1` and `GigabitEthernet1/0/1`), or deny the whole
  command.
- An unknown key or platform, a second YAML document, or a pattern that is unanchored or does not compile stops the
  probe from starting. `probe check-config` reports it, and shows how many commands each platform allows and which
  this probe changed.

**Example: only two IOS commands on this probe.**

```yaml
platforms:
  ios:
    builtin: false
    allow:
      - '^show version$'
      - '^show ip interface brief$'
```

`check-config` then shows `allowed: ios 2 (changed locally), nxos 39, ...`.

**Installing it with Docker** (in `deploy/remote-docker/`):

1. Save the file as `commands.yaml` next to `compose.yaml`, readable by uid 65532. It holds no secrets, so
   `chmod 0644 commands.yaml` is enough (or `sudo chown 65532 commands.yaml && chmod 0400 commands.yaml`).
2. In `compose.yaml`, uncomment the volume line under `volumes:`:
   `- ./commands.yaml:/etc/probe/commands.yaml:ro`
3. In `probe.yaml`, under `ssh:`, set `commands_file: /etc/probe/commands.yaml` (the path inside the container).
4. `docker compose run --rm probe check-config`, then `docker compose up -d --force-recreate probe` (the new volume
   needs a new container). After later edits of `commands.yaml`, `docker compose restart probe` is enough.

**With systemd:** put the file in `/etc/probe/commands.yaml` (`sudo chgrp probe` it, mode 0640), set
`commands_file: /etc/probe/commands.yaml`, run `sudo -u probe probe check-config`, then `sudo systemctl restart probe`.

### The floor

The floor keeps every command to one read-only line. A command must:

- be 1 to 256 characters on one line, using only letters, digits, space and `. _ : / , = @ + -` (no pipes, `;`, `&`,
  redirection, quotes, `$`, backticks, wildcards, `?`, `!` or `#`; on EdgeOS and for a Junos root login the command
  reaches a POSIX shell);
- start with the platform's read verb: `show`; on FortiOS `get`, or one of a fixed set of read-only `diagnose` commands
  (`diagnose sys session stat`, `diagnose ip arp list`, `diagnose ip route list`, `diagnose sys ha status`,
  `diagnose hardware deviceinfo nic <name>`, `diagnose netlink aggregate list` and `name <name>`,
  `diagnose hardware sysinfo memory` and `conserve`), which a local file can remove but not add to; on RouterOS a menu
  path written with spaces (`/ip route print`), then `print` with only output-shaping arguments and an optional
  `where`, or `monitor <item> once`, with `/log` taking only `print`;
- contain no refused word, anywhere, in any case: words that configure, write or move files (`configure`, `set`,
  `copy`, `delete`, `commit`, ...), reload or clear state (`reload`, `clear`, `reset`, `enable`, `disable`, ...), add
  or remove entries, send, debug, test or run a shell (`debug`, `test`, `run`, `bash`, ...), leave the box (`ping`,
  `traceroute`, `ssh`, `telnet`), stream or start a long job (`monitor`, `follow`, `tail`, `top`, `capture`,
  `tech-support`), plus `delta`, `discover`, `wol` and a few per platform;
- contain no abbreviation of a refused word, since device CLIs accept them (IOS `show tec` is `show tech-support`): a
  prefix of three letters or more is refused, with per-word minimums; on EdgeOS two letters suffice for the streaming
  words. One-letter abbreviations are not refused. So an argument that happens to be a refused word or its prefix is
  refused too.

The floor is a refusal list, not a parser of each CLI. The built-in lists are exact; a broad local allow such as
`^show .*$` trusts the platform's command tree and only loses the known-bad words. Keep local patterns as narrow as the
built-in ones. `internal/devcmd/floor.go` has the full rules.

## Logins, cool-downs and sessions

- **One session per device** at a time; a second request gets `busy`. Each session is opened for one command and
  closed after it.
- **A login is never retried.** Within one request the password is offered at most once. Keyboard-interactive login
  answers only a prompt that asks for the password; a one-time code or any other question ends it as `auth_failed`
  with nothing sent.
- **Cool-down.** When a password was sent and refused, that device address is not tried again with that profile for
  `ssh.auth_failure_cooldown_s` (default 600 s); calls answer `auth_failed` at once. The profile's other devices are
  still tried. If the password fails at 3 different addresses within the window, the pattern of a locked-out account,
  the whole profile waits one cool-down. A refused password at a jump host stops that jump host for every profile.
  A refused key sends no password and starts no cool-down. The cool-down is in memory: a probe restart clears it, and
  changing the secret ends it. `0` turns it off. `probe ssh test` runs in its own process and neither sees nor sets it
  (see the warning in the [worked example](#worked-example)).
- **Output** is capped at `ssh.max_output_bytes` (cut further to fit one message; `truncated` is then true) and
  returned as untrusted text. `detail` uses the probe's own wording only.
- **Logs.** The probe logs one `device_show` line per request: device address, profile, jump host, platform, command
  and outcome, never a user name, secret or output. The hub's audit line records the command and outcome.
