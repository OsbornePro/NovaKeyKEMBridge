# NovaKeyKEMBridge - Security Policy

**NovaKeyKEMBridge** is security-critical bridging software: it enables the **NovaKey** iOS app to securely transmit secrets and approval messages to the NovaKey-Daemon running on a desktop computer using post-quantum cryptography. We take security very seriously and welcome responsible review and disclosure.

NovaKeyKEMBridge v3 uses **ML-KEM-768 + HKDF-SHA-256 + XChaCha20-Poly1305**, plus timestamp freshness checks, replay protection (nonce-based), and strong per-message forward secrecy. The protocol is designed to protect against passive eavesdropping and active tampering on local networks.

> Reviewer note: Please test only on systems and networks you own/operate. This project is intended for LAN/local use and normal desktop pairing workflows. Do **not** expose test servers or daemons to the public Internet.

---
## Supported Versions
Security updates are provided for the **latest stable release only**.

| Version          | Supported          | Notes                              |
|------------------|--------------------|------------------------------------|
| Latest release   | Supported          | Receives security fixes promptly   |
| All others       | Not supported      | Upgrade recommended                |

---
## Reporting a Vulnerability
Please **do not** open public GitHub issues for security problems.

Email:
* `security@novakey.app`
* or `robert@osbornepro.com` if needed

My PGP key can be obtained from [HERE](https://downloads.osbornepro.com/publickey.asc)

If you need encrypted communication, include “PGP” in your email subject and we’ll coordinate.

### What to include
- Steps to reproduce
- Affected version(s) of NovaKeyKEMBridge and Go toolchain
- iOS version / Xcode version (if relevant)
- Impact
- Proof-of-concept (if available and safe to share)
- Relevant logs or hex dumps (with secrets redacted)

### What to expect
- Acknowledgment within 24 hours
- Triage response within ~3 business days
- Fix shipped as soon as practical (faster for critical issues)

---
## Security Features

### Per-device identity and authentication
- Each paired iOS device has a unique device ID and a **32-byte secret** (device key).
- The device secret is never transmitted in plaintext.
- Pairing material (JSON blob / QR code) must be protected like a high-value password.

### Post-quantum key encapsulation (ML-KEM-768)
- Every message includes a fresh ML-KEM-768 encapsulation against the daemon’s static public key.
- Provides per-message forward secrecy and resistance to store-now-decrypt-later attacks.

### Session key derivation (HKDF-SHA-256)
Each message derives a fresh AEAD key using:
- IKM = per-message ML-KEM shared secret
- salt = per-device 32-byte secret (PSK)
- info = `"NovaKey v3 AEAD key"`

Keys are single-use and never stored.

### Authenticated encryption (XChaCha20-Poly1305)
- All sensitive content is encrypted and authenticated with XChaCha20-Poly1305.
- The outer header (device ID + KEM ciphertext) is included as AAD, preventing header tampering.

### Typed message framing
Messages use a typed inner frame:
- inner msgType `1` = Inject (carries the secret payload)
- inner msgType `2` = Approve (empty payload, signals confirmation)

No legacy or magic-string fallback exists in v3.

### Freshness & replay protection
- Plaintext includes a Unix timestamp (big-endian u64).
- Each message carries a fresh 24-byte XChaCha nonce.
- Replays of `(deviceID, nonce)` are rejected.

### Protocol hardening
- Strict length checks on all variable-length fields
- Versioned outer and inner frames
- No fallback to weaker cryptography
- Ephemeral keys used only once per message

---
## Threat Model (High Level)

### In scope
- Passive eavesdropping on local networks
- Active man-in-the-middle on local networks
- Replay attempts
- Malicious clients without valid device secrets
- Tampering with pairing material in transit (QR/JSON)

### Out of scope (assumed)
- Compromise of the desktop host OS, daemon process, or same-user malware
- Physical access to the paired iOS device
- Compromise of the iOS device itself (keychain, app sandbox)
- Supply-chain attacks on Go dependencies or XCFramework build pipeline
- Public Internet exposure (this is a LAN/local protocol)

### Pairing material compromise
If an attacker obtains the pairing JSON/QR (containing device ID + device secret + server Kyber public key):
- They can generate valid frames for that device.
- Daemon-side **arming** and **two-man** controls (if enabled in NovaKey-Daemon) can still prevent unauthorized injection.
- Does **not** protect against full host compromise.

---
Thank you for helping keep NovaKey and NovaKeyKEMBridge secure.

— Robert H. Osborne (OsbornePro)  
Maintainer, NovaKey & NovaKeyKEMBridge
```
