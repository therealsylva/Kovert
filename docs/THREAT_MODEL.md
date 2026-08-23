# Threat model

## Protected assets

- Availability and confidentiality of adapter-managed vaults
- Integrity of root-owned Kovert configuration
- Predictable execution of defensive actions
- Local audit history and recovery state
- Control-socket authorization

## Assumptions

Kovert trusts the Linux kernel, boot chain, root account, systemd, configured
adapter binaries and the cryptographic implementation of `fscrypt` or
`gocryptfs`. An attacker with arbitrary kernel or root execution is outside the
security boundary.

## Considered threats

### Unprivileged local user

Socket mode and group ownership prevent unauthorized control requests. Policy
and state files are root-owned. The daemon rejects symlink configuration files,
group/world-writable configuration, relative privileged paths, unapproved
executables, unapproved process targets, malformed interface names and malformed
systemd units.

### Malicious policy input

Serde rejects unknown fields. Validation limits recursion, verifies references,
requires typed actions, and does not support shell command strings. Custom
execution uses a scrubbed environment, fixed timeout, bounded output, safe
root-only file ownership and mandatory digest pinning.

### Event storms and feedback loops

The event queue is bounded, polling skips missed ticks, rule cooldowns and
once-per-boot controls limit repeats, and conflicting actions are collapsed by
priority. Operators should avoid watching the evidence destination with a rule
that captures evidence.

### Adapter failure

Adapter exit status, bounded output and timeout are audited. Kovert does not
claim success when an adapter fails. Where a reversible inverse exists, the
operator can issue it through a separate policy or recovery procedure; Kovert
does not invent rollback steps that may be unsafe.

### Audit modification

Hash chaining detects modification, insertion, removal or reordering within the
retained chain. It does not stop an active root attacker from replacing both the
database and the daemon. Export important records to independently protected
storage using an operator-controlled process if stronger guarantees are needed.

### Key exposure

Secrets are not accepted in TOML, CLI arguments or environment variables.
Automatic unlock necessarily places key bytes in daemon memory and adapter
standard input. Buffers are zeroed after use, but unattended unlock remains less
secure than manual unlock.

## Explicit non-goals

- Protection after kernel or unrestricted root compromise
- Antivirus signature scanning
- Network intrusion detection
- Remote administration or cloud policy delivery
- Covert file collection, secure wipe or self-destruct behaviour
- Replacement for full-disk encryption, backups or measured boot
