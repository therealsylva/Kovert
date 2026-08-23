# Architecture

## Trust boundaries

`kovert-daemon` runs as root because mount control, network isolation, process
signals and global input devices cannot be implemented reliably from an
ordinary user process. The daemon exposes only a versioned JSON protocol over a
mode `0660` Unix socket. Filesystem permissions provide local authorization;
the daemon also records peer credentials for each request.

The `kovert` client performs local policy validation without privilege. It
cannot edit policy files. Operators manage `/etc/kovert/kovert.toml` with normal
root-controlled deployment tools and request an atomic reload through the
socket.

## Processing path

1. Sensor providers normalize Linux state into a bounded `Event` type.
2. The daemon appends the event to the audit chain.
3. The policy engine updates its latest host snapshot.
4. Enabled rules are evaluated by priority.
5. Sequence, sustained-condition, cooldown and once-per-boot state is applied.
6. Mutually exclusive actions are resolved using typed conflict keys.
7. Each action is entered in the idempotency ledger before execution.
8. The action executor performs a dry run or invokes a typed implementation.
9. Outcomes and state transitions are committed to the audit store.

The event channel is bounded. Polling uses skip-on-delay intervals instead of
building an unbounded backlog.

## Policy engine

Rules contain one event trigger, an optional persistent-state condition, and
one or more typed actions. Composite triggers and conditions are recursive but
validation limits nesting to 16 levels. Ordered sequences have an explicit time
window. Sustained conditions arm a rule and fire only after the condition has
remained true for the requested duration.

Rules are sorted by descending priority. Actions that target the same vault,
service, interface, mount, process or global mode share a conflict key; only the
highest-priority action for a key survives one evaluation cycle. Notifications,
evidence records and approved executions do not conflict.

## Sensors

Kovert derives required sensors from active rules. Filesystem events use
`inotify` through the `notify` crate. Emergency sequences read Linux input
events through `evdev`; only configured key codes and the small in-memory match
window are retained. Other providers poll bounded kernel or systemd surfaces:

- `/sys/class/net` and NetworkManager for network and Wi-Fi state
- `/sys/bus/usb/devices` for USB inventory
- `/proc/self/mountinfo` for mounts
- `/proc` for named processes and local listening ports
- `systemctl is-active` for explicitly named services
- `loginctl` for session state
- `/sys/class/power_supply` and ACPI lid state for power

A provider failure emits a normalized sensor-failure event only on transition
into the failed state. Policies default to alerting without executing their
normal actions. A rule may explicitly request fail-closed behaviour; Kovert then
permits only vault-lock, network-isolation, and security-mode actions.

## Actions

Actions never use a shell. External programs receive an absolute executable
path and argument array in a scrubbed environment. Approved custom programs
must appear in `daemon.allowed_executables` and may pin a SHA-256 digest.
Captured output is bounded to 64 KiB per stream and every child has a timeout.

Metadata evidence records describe existence, type, length, permissions and
modification time. Kovert does not silently copy protected file contents.

## Vault adapters

`fscrypt` and `gocryptfs` remain responsible for encryption, formats and key
derivation. The adapter checks required absolute paths and uses fixed binary
locations. Lock operations do not require a stored secret. Automatic unlock
looks up a configured user-keyring description through `keyctl` and supplies
the result over standard input. Secrets never appear in arguments, environment
variables, configuration or logs.

## Durable state

SQLite runs in WAL mode with full synchronization. Audit records contain the
hash of the preceding record and a length-delimited BLAKE3 digest over every
field. Retention advances a stored anchor before deleting old rows, preserving
verification for the retained suffix.

The action ledger is keyed by event ID, rule ID and serialized-action hash. A
successfully completed action will not be repeated if the same event is
processed again. Current mode and recovery state survive daemon restarts.

