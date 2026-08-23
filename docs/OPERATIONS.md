# Operations

## Deployment sequence

1. Build or verify release checksums.
2. Install the binaries and systemd unit.
3. Create `/etc/kovert/kovert.toml` as root with mode `0600`.
4. Keep `dry_run = true`.
5. Run `kovert validate`, start the daemon, inspect `kovert status` and exercise
   manual events.
6. Simulate representative events and inspect `kovert audit`.
7. Test `kovert recovery on` from a separate root session.
8. Configure and test vault adapters manually.
9. Set `dry_run = false`, reload, and test one reversible rule at a time.

## Recovery

Recovery mode is persisted and suspends all automatic rule actions while
keeping sensors, audit and the control socket active:

```bash
sudo kovert recovery on
sudo kovert status
```

If the socket is unavailable, stop the service and start the daemon with a
known-safe configuration:

```bash
sudo systemctl stop kovert
sudo install -m 0600 examples/minimal.toml /etc/kovert/kovert.toml
sudo systemctl start kovert
```

Do not remove the SQLite database during ordinary recovery; it contains the
recovery flag, action ledger and audit chain.

## Configuration reload

`kovert reload` parses and validates a complete replacement before changing the
running configuration. Sensors are started for the new policy before old
providers are stopped. A failure leaves the current configuration active.

## systemd sandbox

The supplied service grants only the capabilities required by supported
actions and makes the host filesystem read-only outside the daemon state and
runtime directories. Policies that mount vaults or write metadata evidence to
another path need an explicit drop-in:

```ini
[Service]
ReadWritePaths=/home/sylva/.local/share/kovert-vaults /var/lib/kovert/evidence
```

Run `systemctl daemon-reload` and restart Kovert after editing the drop-in.

## Audit checks

```bash
kovert verify-audit
kovert audit --limit 100 --json
journalctl -u kovert --since today
```

Retention advances a stored chain anchor. A successful verification covers the
retained suffix, not records already removed by configured retention.

## Vault adapters

Install and initialize `fscrypt` or `gocryptfs` independently before adding the
vault to Kovert. Confirm manual lock and unlock first. For automatic unlock,
place the passphrase in the user keyring under the exact configured description:

```bash
keyctl padd user kovert:operations @u
```

The command reads the secret from standard input. Keyring entries disappear
according to kernel keyring lifetime and session policy.

