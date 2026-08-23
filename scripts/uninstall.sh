#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "uninstall.sh must run as root" >&2
    exit 1
fi

systemctl disable --now kovert.service 2>/dev/null || true
rm -f -- /etc/systemd/system/kovert.service
rm -f -- /usr/local/sbin/kovert-daemon
rm -f -- /usr/local/bin/kovert
systemctl daemon-reload

if [ "${1:-}" = "--purge" ]; then
    rm -r -- /etc/kovert 2>/dev/null || true
    rm -r -- /var/lib/kovert 2>/dev/null || true
    groupdel kovert 2>/dev/null || true
    echo "Kovert binaries, configuration, state, audit records, and group removed."
else
    echo "Kovert binaries removed. Configuration and state were preserved."
fi

