# Security policy

Kovert is a privileged host-security daemon. Treat configuration changes and
adapter binaries with the same care as root access.

## Supported versions

Security fixes are provided for the latest release. Until version 1.0, breaking
configuration changes may occur between minor releases and will be documented
in the changelog.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose secrets,
bypass policy authorization, or permit privilege escalation. Use GitHub's
private vulnerability-reporting flow for this repository. Include the affected
version, operating system, configuration, reproduction steps, and expected
impact. Reports are acknowledged as soon as practical.

## Security boundaries

Kovert assumes the kernel and root account are trusted. Hash-chained audit
records make accidental or post-event modification detectable; they cannot
protect against an active attacker with unrestricted root access. Vault
cryptography is delegated to `fscrypt` or `gocryptfs`; Kovert does not implement
its own encryption algorithm.

