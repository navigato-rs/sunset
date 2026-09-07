#!/usr/bin/env bash
# Four disposable loopback sshds and a private agent. No user keys or config.
set -euo pipefail
root=$(mktemp -d /tmp/sunset-client.XXXXXX)
chmod 700 "$root"
cleanup() {
    for file in "$root"/sshd*.pid; do
        if test -f "$file"; then sudo kill "$(cat "$file")" 2>/dev/null || true; fi
    done
    if test -n "${SSH_AGENT_PID:-}"; then ssh-agent -k >/dev/null 2>&1 || true; fi
    if test "${failed:-1}" = 1; then cat "$root"/sshd*.log 2>/dev/null || true; fi
    rm -rf "$root"
}
# Never terminate an inherited agent on an early failure.
unset SSH_AGENT_PID SSH_AUTH_SOCK
trap cleanup EXIT
sshd=$(command -v sshd)
python3 - "$root" <<'PY'
import pathlib, socket, sys
sockets = [socket.socket() for _ in range(4)]
for sock in sockets:
    sock.bind(('127.0.0.1', 0))
pathlib.Path(sys.argv[1], 'ports').write_text(','.join(str(sock.getsockname()[1]) for sock in sockets))
PY
IFS=, read -r -a ports < <(cat "$root/ports"; echo)
user=$(id -un)
sudo mkdir -p /run/sshd
for i in 0 1 2 3; do
    ssh-keygen -q -t ed25519 -N '' -f "$root/host$i"
    ssh-keygen -q -t ed25519 -N '' -f "$root/identity$i"
    forwarding=yes
    if test "$i" = 3; then forwarding=no; fi
    cat > "$root/sshd$i.conf" <<EOF
Port ${ports[$i]}
ListenAddress 127.0.0.1
HostKey $root/host$i
PidFile $root/sshd$i.pid
AuthorizedKeysFile $root/identity$i.pub
AllowUsers $user
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
UsePAM yes
UseDNS no
GSSAPIAuthentication no
StrictModes no
PrintMotd no
LogLevel ERROR
AllowTcpForwarding $forwarding
Subsystem sftp internal-sftp
EOF
    sudo "$sshd" -f "$root/sshd$i.conf" -E "$root/sshd$i.log"
    read -r kind key _ < "$root/host$i.pub"
    printf '[127.0.0.1]:%s %s %s\n' "${ports[$i]}" "$kind" "$key" >> "$root/known_hosts"
done
read -r kind key _ < "$root/identity0.pub"
for port in "${ports[@]}"; do
    printf '[127.0.0.1]:%s %s %s\n' "$port" "$kind" "$key" >> "$root/wrong_hosts"
done
: > "$root/unknown_hosts"
eval "$(ssh-agent -s)" >/dev/null
ssh-add "$root/identity0" "$root/identity2" >/dev/null 2>&1
export SUNSET_TEST_ROOT="$root" SUNSET_TEST_PORTS="$(cat "$root/ports")" SUNSET_TEST_USER="$user"
export SUNSET_AGENT_TEST_PUBKEY="$root/identity2.pub"
cargo test --locked -p sunset-client --test localhost -- --ignored --test-threads=1
cargo test --locked -p sunset-client --lib signs_with_isolated_openssh_agent -- --ignored
failed=0
