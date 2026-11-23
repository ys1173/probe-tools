#!/usr/bin/env bash
# Installs the probe as a systemd service on a Linux server. Run as root on the target server.
#
#   sudo ./install.sh [--binary PATH] [--no-start]
#   sudo ./install.sh --uninstall [--purge]
#
# Needs no network access: it installs files that sit next to this script (the release tarball layout) or that you
# point it at.
#
#   --binary PATH   the probe binary to install (default: ./probe next to this script)
#   --no-start      install and enable, but do not start (or restart) the service
#   --uninstall     stop and remove the service and the binary; keeps /etc/probe and /var/lib/probe
#   --purge         with --uninstall: also delete /etc/probe, /var/lib/probe and the probe user
#
# The enrolment token (issued on the hub, single use) is taken from PROBE_ENROLL_TOKEN in the environment, or asked
# for on a terminal. It is stored in /etc/probe/probe.env (0600, root). Re-running this script is safe: it replaces
# the binary and unit, and leaves an existing /etc/probe/probe.yaml alone.
set -euo pipefail

readonly BIN_DST=/usr/local/bin/probe
readonly UNIT_DST=/etc/systemd/system/probe.service
readonly CONF_DIR=/etc/probe
readonly CONF_FILE=$CONF_DIR/probe.yaml
readonly ENV_FILE=$CONF_DIR/probe.env
readonly STATE_DIR=/var/lib/probe
readonly SVC_USER=probe
readonly SVC=probe.service

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
binary="$here/probe"
start=1
uninstall=0
purge=0

log() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

usage() {
  sed -n '2,/^set -euo/{/^set -euo/!p;}' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)
      [[ $# -ge 2 ]] || die "--binary needs a path"
      binary="$2"
      shift 2
      ;;
    --no-start)
      start=0
      shift
      ;;
    --uninstall)
      uninstall=1
      shift
      ;;
    --purge)
      purge=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || die "run as root (sudo $0 ...)"
[[ "$(uname -s)" == Linux ]] || die "this installer is for Linux"
[[ "$purge" -eq 0 || "$uninstall" -eq 1 ]] || die "--purge only makes sense with --uninstall"
command -v systemctl >/dev/null 2>&1 || die "systemctl not found: this installer needs systemd"

do_uninstall() {
  if systemctl cat "$SVC" >/dev/null 2>&1; then
    systemctl disable --now "$SVC" >/dev/null 2>&1 || true
  fi
  rm -f "$UNIT_DST" "$BIN_DST"
  systemctl daemon-reload
  log "removed $UNIT_DST and $BIN_DST"
  if [[ "$purge" -eq 1 ]]; then
    rm -rf "$CONF_DIR" "$STATE_DIR"
    if getent passwd "$SVC_USER" >/dev/null; then
      userdel "$SVC_USER" 2>/dev/null || warn "could not remove user $SVC_USER"
    fi
    if getent group "$SVC_USER" >/dev/null; then
      groupdel "$SVC_USER" 2>/dev/null || true
    fi
    log "purged $CONF_DIR, $STATE_DIR and the $SVC_USER user"
  else
    log "kept $CONF_DIR and $STATE_DIR (use --uninstall --purge to delete them)"
  fi
}

if [[ "$uninstall" -eq 1 ]]; then
  do_uninstall
  exit 0
fi

# ---- install ---------------------------------------------------------------------------------------------------

[[ -f "$binary" ]] || die "probe binary not found at $binary (use --binary PATH)"
[[ -f "$here/probe.service" ]] || die "probe.service not found next to this script"
[[ -f "$here/probe.yaml" || -f "$CONF_FILE" ]] || die "probe.yaml example not found next to this script"

# A wrong-architecture binary fails here, before anything on the system is touched.
version="$("$binary" version 2>&1)" || die "$binary does not run on this machine: $version"
log "installing probe: $version"

# Service user: no login, no home directory.
if ! getent passwd "$SVC_USER" >/dev/null; then
  nologin=/usr/sbin/nologin
  [[ -x "$nologin" ]] || nologin=/sbin/nologin
  [[ -x "$nologin" ]] || nologin=/bin/false
  command -v useradd >/dev/null 2>&1 || die "useradd not found; create a system user named $SVC_USER and re-run"
  useradd --system --user-group --no-create-home --home-dir "$STATE_DIR" --shell "$nologin" "$SVC_USER"
  log "created system user $SVC_USER"
fi

# Binary: write beside the target and rename, so a running service never sees a half-written file.
install -d -m 0755 -o root -g root "$(dirname "$BIN_DST")"
install -m 0755 -o root -g root "$binary" "$BIN_DST.new"
mv -f "$BIN_DST.new" "$BIN_DST"

# Config directory and example config. An existing config is never overwritten.
install -d -m 0750 -o root -g "$SVC_USER" "$CONF_DIR"
if [[ -e "$CONF_FILE" ]]; then
  log "keeping existing $CONF_FILE"
  # The service reads it as the probe user: make sure it can, without widening it beyond root and that group.
  chown root:"$SVC_USER" "$CONF_FILE"
  chmod 0640 "$CONF_FILE"
else
  install -m 0640 -o root -g "$SVC_USER" "$here/probe.yaml" "$CONF_FILE"
  log "wrote example $CONF_FILE: edit hub_url and targets before the probe can run"
fi

# State directory (systemd's StateDirectory= also creates it; this lets check-config run as the probe user first).
install -d -m 0700 -o "$SVC_USER" -g "$SVC_USER" "$STATE_DIR"

# Enrolment token. The file is created with the token already in it, under a restrictive umask, so the secret is
# never readable by other users.
token="${PROBE_ENROLL_TOKEN:-}"
if [[ -z "$token" && ! -e "$ENV_FILE" && ! -e "$STATE_DIR/identity.json" && -t 0 ]]; then
  read -rsp "Enrolment token from the hub (input hidden, Enter to skip): " token
  printf '\n'
fi
if [[ -n "$token" ]]; then
  if [[ "$token" == *[[:space:]]* || "$token" == *\"* || "$token" == *\'* ]]; then
    die "the enrolment token contains whitespace or quotes; copy it again"
  fi
  (
    umask 077
    printf 'PROBE_ENROLL_TOKEN=%s\n' "$token" >"$ENV_FILE.new"
  )
  chown root:root "$ENV_FILE.new"
  mv -f "$ENV_FILE.new" "$ENV_FILE"
  log "wrote $ENV_FILE (0600)"
elif [[ ! -e "$ENV_FILE" ]]; then
  (
    umask 077
    printf 'PROBE_ENROLL_TOKEN=\n' >"$ENV_FILE"
  )
  chown root:root "$ENV_FILE"
  log "created an empty $ENV_FILE"
fi
chmod 0600 "$ENV_FILE"
unset token

# Unit.
install -m 0644 -o root -g root "$here/probe.service" "$UNIT_DST"
systemctl daemon-reload
systemctl enable "$SVC" >/dev/null 2>&1
log "installed and enabled $SVC"

# Validate the configuration as the service user before starting anything. check-config reads only the config file,
# so the enrolment token is not passed to it: any way of handing it over would put it on a command line (env's
# arguments), where other users can read it in the process list.
if command -v runuser >/dev/null 2>&1; then
  runas=(runuser -u "$SVC_USER" --)
elif command -v setpriv >/dev/null 2>&1; then
  runas=(setpriv --reuid "$SVC_USER" --regid "$SVC_USER" --init-groups --)
else
  die "neither runuser nor setpriv found; cannot validate the config as $SVC_USER"
fi
if ! "${runas[@]}" "$BIN_DST" check-config --config "$CONF_FILE"; then
  die "check-config failed: fix $CONF_FILE and run: systemctl start $SVC"
fi

# The token is single use and worthless once the probe has enrolled, but it is still a secret on disk. Removing it is
# left to the operator: the script cannot tell whether they mean to re-enrol.
token_note() {
  if [[ -e "$STATE_DIR/identity.json" ]] && grep -Eq '^PROBE_ENROLL_TOKEN=.+' "$ENV_FILE"; then
    log "the probe has enrolled ($STATE_DIR/identity.json exists); the enrolment token is no longer needed and you may remove the PROBE_ENROLL_TOKEN line from $ENV_FILE"
  fi
}

if [[ "$start" -eq 0 ]]; then
  log "not starting (--no-start). Start it with: systemctl start $SVC"
  token_note
  exit 0
fi

# Do not start a probe that cannot work yet; tell the operator what is missing instead.
if grep -Eq '^[[:space:]]*hub_url:[[:space:]]*"?[a-z]+://hub\.example\.com' "$CONF_FILE"; then
  warn "$CONF_FILE still has the example hub_url. Edit it, then: systemctl start $SVC"
  exit 0
fi
if [[ ! -e "$STATE_DIR/identity.json" ]] && ! grep -Eq '^PROBE_ENROLL_TOKEN=.+' "$ENV_FILE"; then
  warn "no saved identity and no enrolment token. Put the token in $ENV_FILE, then: systemctl start $SVC"
  exit 0
fi

systemctl restart "$SVC"
log "started $SVC. Follow it with: journalctl -u $SVC -f"

# Enrolment happens in the service after it starts, so give it a few seconds to write its identity.
for _ in 1 2 3 4 5 6 7 8 9 10; do
  [[ -e "$STATE_DIR/identity.json" ]] && break
  sleep 1
done
if [[ -e "$STATE_DIR/identity.json" ]]; then
  token_note
else
  log "the probe has not enrolled yet; once $STATE_DIR/identity.json exists you may remove the PROBE_ENROLL_TOKEN line from $ENV_FILE"
fi
