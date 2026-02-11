# tink-ffi

Safe Rust bindings to [Google Tink](https://github.com/tink-crypto/tink-cc)
cryptography library via FFI, built against
[tink-cc v2.5.0](https://github.com/tink-crypto/tink-cc/releases/tag/v2.5.0).

Tink is a multi-language, cross-platform cryptographic library that provides
secure, easy-to-use APIs for common cryptographic operations. This crate wraps
the C++ implementation through a thin C shim, giving Rust programs access to
the full set of Tink primitives.

## Supported Primitives

- **AEAD** (AES-GCM, AES-EAX, AES-GCM-SIV, XChaCha20-Poly1305, AES-CTR-HMAC)
- **Deterministic AEAD** (AES-SIV)
- **Streaming AEAD** (AES-GCM-HKDF, AES-CTR-HMAC)
- **MAC** (HMAC, AES-CMAC)
- **Digital Signatures** (ECDSA, RSA-SSA-PKCS1, RSA-SSA-PSS, Ed25519)
- **Hybrid Encryption** (ECIES, HPKE)
- **JWT** (HMAC, ECDSA, RSA-SSA-PKCS1, RSA-SSA-PSS)
- **PRF** (HKDF, HMAC, AES-CMAC)
- **Key Derivation** (PRF-based keyset derivation)

## Prerequisites

- Rust toolchain (stable)
- CMake 3.22+
- C++17 compiler (Clang or GCC)
- A checkout of [tink-cc](https://github.com/tink-crypto/tink-cc)

## Building

```bash
# Point to your tink-cc source checkout
export TINK_CC_DIR=/path/to/tink-cc

# Build all crates
cargo build

# Run tests
cargo test -p testing-server
```

## Quick Example

```rust
use tink_ffi::{register_all, Aead, AeadPrimitive, KeyTemplate, KeysetHandle, Primitive};

fn main() -> tink_ffi::Result<()> {
    register_all()?;

    // Generate a new keyset
    let handle = KeysetHandle::generate_new(KeyTemplate::Aes256Gcm)?;

    // Get an AEAD primitive from the keyset
    let aead: AeadPrimitive = handle.primitive()?;

    // Encrypt
    let ciphertext = aead.encrypt(b"hello world", b"associated data")?;

    // Decrypt
    let plaintext = aead.decrypt(&ciphertext, b"associated data")?;
    assert_eq!(plaintext, b"hello world");

    Ok(())
}
```

## Crate Structure

```
tink-ffi/
  tink-ffi-sys/       Raw FFI bindings and C++ shim
    ffi/              C++ shim wrapping tink-cc
    src/lib.rs        extern "C" declarations
  tink-ffi/           Safe Rust API
    src/              Typed primitives, keyset management, error handling
  testing-server/     gRPC testing server for cross-language compatibility tests
```

### tink-ffi-sys

Low-level crate that builds the C++ shim via CMake and exposes raw `extern "C"`
function bindings. Handles linking against tink-cc and all its dependencies
(abseil, protobuf, boringssl).

### tink-ffi

Safe, idiomatic Rust wrapper. Provides typed primitives (`AeadPrimitive`,
`MacPrimitive`, etc.) behind trait interfaces, `KeysetHandle` for key
management, and `KeyTemplate` enum for key generation.

### testing-server

A gRPC server implementing the
[Tink cross-language testing protocol](https://github.com/tink-crypto/tink-cross-lang-tests).
Used to verify interoperability with other Tink implementations (C++, Java, Go,
Python).

## Cross-Language Testing

The testing server can be registered with the
[tink-cross-lang-tests](https://github.com/tink-crypto/tink-cross-lang-tests)
framework. See `testing-server/` for details on building and running the server.

## License

[Apache License 2.0](https://github.com/winstanley-industries/tink-ffi/blob/main/LICENSE)
