# Kovert

Kovert is a programmable host-security daemon for Linux. It observes local
events, evaluates typed event-condition-action policies, and performs a small
set of controlled defensive operations.

Kovert is designed for one machine. It has no account system, cloud control
plane, telemetry, or remote policy service.

## Capabilities

- Time windows, cooldowns, sustained conditions, ordered sequences and modes
- Filesystem create, modify, rename, delete, access and metadata events
- Wi-Fi SSID/BSSID and network-interface state
- USB, mount, process, systemd service and listening-port changes
- Session, lock state, suspend-adjacent power state and battery conditions
- Configured emergency key sequences through Linux `evdev`
- Configuration and binary integrity events
- `fscrypt` and `gocryptfs` vault adapters; no custom encryption algorithm
- Typed actions with no shell evaluation
- Dry-run planning, priority conflict resolution and action idempotency
- Root-owned SQLite state with a hash-chained audit trail
- Recovery mode that suspends automatic rule execution
- CLI, JSON output and an interactive control shell

## Architecture

Kovert installs two binaries:

| Binary | Role |
|---|---|
| `kovert-daemon` | Root daemon that owns sensors, policy state, actions and audit records |
| `kovert` | Unprivileged client for validation, inspection, simulation and recovery |

The client communicates through `/run/kovert/kovert.sock`. The socket is mode
`0660` and belongs to the `kovert` group. Policies are loaded from
`/etc/kovert/kovert.toml`, which must be root-owned and not writable by group or
others.

See [the architecture](docs/ARCHITECTURE.md) and
[threat model](docs/THREAT_MODEL.md) before enabling non-dry-run policies.

## Build

Kovert requires Rust 1.85 or newer and Linux kernel 5.15 or newer.

```bash
cargo build --release --workspace
cargo test --workspace --all-features
```

The release binaries are written to `target/release/kovert` and
`target/release/kovert-daemon`.

## Install

Review `examples/kovert.toml`, build the release binaries, then run:

```bash
sudo ./scripts/install.sh
sudo install -m 0600 examples/kovert.toml /etc/kovert/kovert.toml
sudo systemctl restart kovert
```

The example configuration has `dry_run = true`. Keep dry-run enabled until
`kovert rules`, `kovert status`, and simulations show the intended actions.

Grant a user control access explicitly:

```bash
sudo usermod -aG kovert "$USER"
```

Start a new login session after changing group membership.

## Basic use

```bash
kovert validate /etc/kovert/kovert.toml
kovert status
kovert rules
kovert audit --limit 25
kovert trigger panic
kovert recovery on
kovert verify-audit
kovert repl
```

All daemon-facing commands support `--json`.

## Example policy

```toml
[[rules]]
id = "operations-after-hours"
description = "Lock the operations vault outside the approved window"
priority = 100
cooldown = "5m"

[rules.trigger]
type = "tick"

[rules.when]
type = "time_window"
start = "09:00"
end = "17:00"
outside = true
weekdays = ["mon", "tue", "wed", "thu", "fri"]

[[rules.actions]]
type = "lock_vault"
vault = "operations"
```

The full schema is documented in [Policy reference](docs/POLICY_REFERENCE.md).

## Vault safety

Kovert never stores a vault password in its configuration. Locking delegates to
`fscrypt` or `gocryptfs`. Automatic unlock is disabled unless a vault names a
key already present in the Linux user keyring. Key material is sent to the
adapter over standard input and is zeroed from Kovert's buffer afterward.

Unattended unlocking weakens the protection provided by an encrypted vault.
Prefer automatic locking and manual unlocking unless the operational need is
clear.

## Security status

Kovert is security-sensitive software and has not received an independent
audit. Use dry-run mode first, maintain tested recovery access, and do not treat
the audit chain as protection from an attacker who already controls the kernel
or root account.

## License

Kovert is available under either the MIT License or Apache License 2.0, at your
option.

