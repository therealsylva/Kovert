#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh must run as root" >&2
    exit 1
fi

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
daemon_binary="$project_dir/target/release/kovert-daemon"
cli_binary="$project_dir/target/release/kovert"

if [ ! -x "$daemon_binary" ] || [ ! -x "$cli_binary" ]; then
    echo "release binaries are missing; run cargo build --release --workspace" >&2
    exit 1
fi

if ! getent group kovert >/dev/null 2>&1; then
    groupadd --system kovert
fi

install -d -m 0750 -o root -g root /etc/kovert
install -d -m 0700 -o root -g root /var/lib/kovert
install -m 0755 "$daemon_binary" /usr/local/sbin/kovert-daemon
install -m 0755 "$cli_binary" /usr/local/bin/kovert
install -m 0644 "$project_dir/packaging/kovert.service" /etc/systemd/system/kovert.service

if [ ! -e /etc/kovert/kovert.toml ]; then
    install -m 0600 "$project_dir/examples/minimal.toml" /etc/kovert/kovert.toml
fi

systemctl daemon-reload
systemctl enable --now kovert.service
echo "Kovert installed. Review /etc/kovert/kovert.toml; it starts in dry-run mode."

