# Jump host for the e2e device cases: stock OpenSSH on alpine. One ed25519 host key (so the fingerprint the suite
# confirms with `probe ssh jump add --accept-host-key` is the one presented), key login for user "jump", TCP
# forwarding on (direct-tcpip is how the probe reaches devices behind it), DEBUG1 logging to stderr so the suite can
# see each direct-tcpip request and its target.
FROM alpine:3.20
RUN apk add --no-cache openssh-server \
 && adduser -D -s /bin/sh jump \
 && sed -i 's/^jump:!:/jump:*:/' /etc/shadow \
 && mkdir -p /home/jump/.ssh && chmod 700 /home/jump/.ssh && chown jump:jump /home/jump/.ssh \
 && printf '%s\n' \
    'HostKey /etc/ssh/ssh_host_ed25519_key' \
    'PermitRootLogin no' \
    'PasswordAuthentication no' \
    'KbdInteractiveAuthentication no' \
    'PubkeyAuthentication yes' \
    'AuthorizedKeysFile /etc/ssh/authorized_keys/%u' \
    'AllowTcpForwarding yes' \
    'PermitOpen any' \
    'AllowUsers jump' \
    'LogLevel DEBUG1' \
    > /etc/ssh/sshd_config \
 && mkdir -p /etc/ssh/authorized_keys
# The suite mounts the jump user's public key at /e2e/jump_key.pub; the host key is made at start.
CMD ["sh", "-euc", "[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key; install -m 0644 /e2e/jump_key.pub /etc/ssh/authorized_keys/jump; exec /usr/sbin/sshd -D -e"]
