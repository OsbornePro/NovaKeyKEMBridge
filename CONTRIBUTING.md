# Contributing to NovaKey

Thank you for your interest in contributing to **NovaKey**.

NovaKey is a security-critical system. Contributions are welcome, but they must
preserve strict correctness, clarity, and security guarantees.

This document describes how to contribute safely and productively.

---

## Project Philosophy

NovaKey is built on a few non-negotiable principles:

- **Explicit over implicit**
- **Typed protocols over magic behavior**
- **No legacy compatibility paths**
- **Security > convenience**
- **Code is the source of truth**

If a behavior is not reachable in code, it must not appear in documentation.
If a behavior weakens security assumptions, it will not be merged.

---

## Scope of Contributions

### Welcome contributions

- Bug fixes
- Security hardening
- Documentation corrections
- Test coverage
- Platform-specific fixes (macOS / Linux / Windows / iOS)
- Performance improvements that do not weaken safety checks

### Out-of-scope contributions

- Legacy protocol support
- Backward compatibility for removed protocol versions
- Untyped or implicit control messages
- “Magic string” behavior
- Silent fallbacks or undocumented behavior

If you are unsure whether a change fits, open an issue first.

---

## Protocol & Documentation Rules

NovaKey enforces **Docs ↔ Protocol invariants**.

Before submitting a PR, ensure:

- The change matches `PROTOCOL.md`
- Security-relevant behavior is documented
- No legacy terminology is introduced
- No undocumented fallback behavior is added

See: `DOCS_INVARIANTS.md`

PRs that introduce protocol drift will be rejected.

---

## Coding Standards

### Go (NovaKey-Daemon)

- Go 1.22+
- Clear error paths
- No silent failures
- Crypto code must be constant-time where applicable
- Avoid global mutable state unless explicitly synchronized

### Swift (NovaKey iOS App)

- Swift concurrency preferred
- No hard-coded secrets
- No reliance on obscurity
- All cryptographic behavior must remain auditable
- UI code must not weaken security guarantees

---

## Security Issues

**Do not** open public issues for security vulnerabilities.

Instead, email:

- `security@novakey.app`
- or `rosborne@osbornepro.com`

Include:
- affected component
- OS / version
- reproduction steps
- impact assessment

PGP is available on request.

---

## Licensing

By contributing, you agree that your contributions will be licensed under the
project’s existing license.

You also agree that the **NovaKey** name and branding are trademarks and may not
be reused without permission.

---

## Final Note

This project values **correctness and trust** over velocity.

Clean, boring, explicit code wins.

Thank you for helping keep NovaKey secure.

