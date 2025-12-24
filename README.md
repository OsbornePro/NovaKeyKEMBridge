# NovaKeyKEMBridge

## Overview

**NovaKeyKEMBridge** is a Go module and bridging project designed to enable secure communication between the **NovaKey** iOS application and a companion daemon running on a desktop computer (typically macOS).

The core functionality is provided by the `novakeykem` Go package, which implements a custom post-quantum secure protocol using **ML-KEM-768** (formerly known as Kyber-768, standardized in NIST FIPS 203). This allows the iOS app to securely "inject" secrets or send approval messages to the daemon over TCP, with forward-secure, quantum-resistant encryption.

The project includes an **XCFramework** (`NovaKeyKEM.xcframework`) built from the Go code using `golang.org/x/mobile/bind`, allowing the Go implementation to be called directly from Swift/Objective-C in the NovaKey iOS app.

## Features

- Post-quantum key encapsulation using **ML-KEM-768** via `golang.org/x/crypto/mlkem`
- Authenticated encryption with **XChaCha20-Poly1305**
- Key derivation via **HKDF-SHA256**
- Custom framed TCP messages with versioning and typed inner payloads
- Two message types:
  - **Inject**: Sends a secret payload (e.g., a password or authentication token) to the daemon
  - **Approve**: Sends a confirmation/approval without payload
- Secure pairing via a JSON blob containing device ID, device key, server address, and server Kyber public key

## Directory Contents

- `NovaKeyKEM.xcframework/` – Pre-built framework for integration into Xcode projects
- `novakeykem/` – Main Go package implementing the protocol
  - `kem.go` – Core functions: `BuildInjectFrame` and `BuildApproveFrame`
- `go.mod`, `go.sum` – Go module dependencies
- `tools.go` – Tool imports for Go mobile binding

## Dependencies

- Go 1.24
- `golang.org/x/crypto` (v0.46.0) – Provides ML-KEM, ChaCha20-Poly1305, HKDF, etc.
- `golang.org/x/mobile` – For generating the iOS XCFramework

## Building the XCFramework

To regenerate or update the framework:

```bash
gomobile bind -target=ios -o NovaKeyKEM.xcframework novakeykem
```

(Note: Requires `gomobile` installed via `go install golang.org/x/mobile/cmd/gomobile@latest` and initialized with `gomobile init`.)

## Usage in iOS (Swift)

After adding the XCFramework to your Xcode project:

```swift
import NovaKeyKEM

// Example: Build an inject frame
let pairingJSON = "{...}" // Your pairing blob as JSON string
let secret = "my-secret-password"

if let frame = try? NovakeykemBuildInjectFrame(pairingJSON, secret) {
    // Send `frame` (Data) over TCP to the daemon
}
```

Similar for `NovakeykemBuildApproveFrame(pairingJSON)`.

## Protocol Notes

- Uses ephemeral ML-KEM encapsulation against the server's static Kyber-768 public key
- Derives AEAD key from shared secret + static device key (acting as salt/authentication)
- Includes timestamp in plaintext to prevent replay
- Framed with 16-bit length prefix for TCP streaming

This provides strong post-quantum confidentiality and authentication for short messages/secrets from iOS to the desktop daemon.

## License

(Not specified in source – add your preferred license here if publishing.)

## Author

Developed for the NovaKey iOS app by Robert H. Osborne.
