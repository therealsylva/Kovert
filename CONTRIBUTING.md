# Contributing

1. Create a focused branch from `main`.
2. Add tests for behavioural changes.
3. Run `make check`.
4. Update documentation when the policy schema or security model changes.
5. Open a pull request describing security implications and recovery behaviour.

Kovert forbids unsafe Rust. New privileged actions must use typed arguments,
must not invoke a shell, and must define dry-run and rollback behaviour.

