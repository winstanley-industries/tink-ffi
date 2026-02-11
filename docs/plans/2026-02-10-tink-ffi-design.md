# tink-ffi Design

## Overview

Rust FFI bindings to Google's tink-cc C++ cryptography library. Provides safe, idiomatic Rust access to all Tink primitives via a C shim layer.

## Architecture

**Workspace with two crates:**

- `tink-ffi-sys` — C shim + raw FFI bindings + CMake build
- `tink-ffi` — Safe Rust API with traits mirroring Tink's primitive interfaces

**Build pipeline:** `build.rs` → CMake → builds tink-cc + C shim → static library → Rust links against it.

## Workspace Layout

```
tink-ffi/
├── Cargo.toml                    # workspace root
├── tink-ffi-sys/
│   ├── Cargo.toml                # links = "tink"
│   ├── build.rs                  # cmake build orchestration
│   ├── ffi/                      # C shim (compiled by cmake)
│   │   ├── CMakeLists.txt        # builds shim + links tink-cc
│   │   ├── include/tink_ffi.h    # public C API header
│   │   └── src/
│   │       ├── aead.cc
│   │       ├── mac.cc
│   │       ├── signature.cc
│   │       ├── hybrid.cc
│   │       ├── streaming_aead.cc
│   │       ├── deterministic_aead.cc
│   │       ├── jwt.cc
│   │       ├── prf.cc
│   │       ├── key_derivation.cc
│   │       ├── keyset.cc
│   │       └── config.cc
│   └── src/lib.rs                # raw extern "C" bindings
├── tink-ffi/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── error.rs
│       ├── keyset.rs
│       ├── aead.rs
│       ├── mac.rs
│       ├── signature.rs
│       ├── hybrid.rs
│       ├── streaming_aead.rs
│       ├── deterministic_aead.rs
│       ├── jwt.rs
│       ├── prf.rs
│       └── key_derivation.rs
```

## C Shim Conventions

Every FFI function follows this pattern:

- Returns `int` (0 = success, non-zero = failure)
- Results written to out-pointers
- `tink_error_message()` returns last error string (thread-local)
- Opaque handle types: `TinkKeysetHandle`, `TinkAead`, `TinkMac`, etc.
- Caller frees output buffers with `tink_free_bytes(ptr, len)`
- Handles freed with `tink_*_free()` functions

```c
typedef struct TinkKeysetHandle TinkKeysetHandle;
typedef struct TinkAead TinkAead;

int tink_aead_encrypt(
    const TinkAead *aead,
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t **ciphertext_out, size_t *ciphertext_len_out
);

void tink_free_bytes(uint8_t *ptr, size_t len);
void tink_aead_free(TinkAead *aead);
int tink_register_all();
```

## Safe Rust API

### Error Handling

```rust
pub struct TinkError { message: String, code: i32 }
pub type Result<T> = std::result::Result<T, TinkError>;
```

### KeysetHandle

Central type owning an opaque pointer, implements `Drop`:

```rust
impl KeysetHandle {
    pub fn generate_new(template: KeyTemplate) -> Result<Self>;
    pub fn from_json(json: &str) -> Result<Self>;
    pub fn to_json(&self) -> Result<String>;
    pub fn from_binary(data: &[u8]) -> Result<Self>;
    pub fn to_binary(&self) -> Result<Vec<u8>>;
    pub fn public_handle(&self) -> Result<KeysetHandle>;
    pub fn primitive<P: Primitive>(&self) -> Result<P>;
}
```

### Primitive Traits

```rust
pub trait Aead: Send + Sync {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
}

pub trait Mac: Send + Sync {
    fn compute_mac(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn verify_mac(&self, mac: &[u8], data: &[u8]) -> Result<()>;
}

pub trait Signer: Send + Sync {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
}

pub trait Verifier: Send + Sync {
    fn verify(&self, signature: &[u8], data: &[u8]) -> Result<()>;
}

pub trait HybridEncrypt: Send + Sync {
    fn encrypt(&self, plaintext: &[u8], context_info: &[u8]) -> Result<Vec<u8>>;
}

pub trait HybridDecrypt: Send + Sync {
    fn decrypt(&self, ciphertext: &[u8], context_info: &[u8]) -> Result<Vec<u8>>;
}

pub trait DeterministicAead: Send + Sync {
    fn encrypt_deterministically(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
    fn decrypt_deterministically(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
}

pub trait StreamingAead: Send + Sync {
    fn new_encrypting_writer(&self, dest: Box<dyn Write>, aad: &[u8]) -> Result<Box<dyn Write>>;
    fn new_decrypting_reader(&self, source: Box<dyn Read>, aad: &[u8]) -> Result<Box<dyn Read>>;
}

pub trait JwtMac: Send + Sync {
    fn compute_mac_and_encode(&self, raw_jwt: &RawJwt) -> Result<String>;
    fn verify_mac_and_decode(&self, token: &str, validator: &JwtValidator) -> Result<VerifiedJwt>;
}

pub trait PrfSet: Send + Sync {
    fn primary_id(&self) -> u32;
    fn compute_primary(&self, input: &[u8], output_len: usize) -> Result<Vec<u8>>;
}

pub trait KeysetDeriver: Send + Sync {
    fn derive_keyset(&self, salt: &[u8]) -> Result<KeysetHandle>;
}
```

### KeyTemplate

Enum with variants for every supported algorithm:

```rust
pub enum KeyTemplate {
    // AEAD
    Aes128Gcm, Aes256Gcm, Aes128Eax, Aes256Eax,
    Aes128CtrHmacSha256, Aes256CtrHmacSha256,
    XChaCha20Poly1305, Aes128GcmSiv, Aes256GcmSiv,
    // DeterministicAead
    Aes256Siv,
    // MAC
    HmacSha256, HmacSha256HalfDigest, HmacSha512, HmacSha512HalfDigest, AesCmac,
    // Signatures
    EcdsaP256, EcdsaP384Sha384, EcdsaP384Sha512, EcdsaP521,
    Ed25519,
    RsaSsaPkcs13072Sha256, RsaSsaPkcs14096Sha512,
    RsaSsaPss3072Sha256, RsaSsaPss4096Sha512,
    // Hybrid
    EciesP256HkdfHmacSha256Aes128Gcm,
    EciesP256HkdfHmacSha256Aes128CtrHmacSha256,
    HpkeX25519HkdfSha256Aes128Gcm,
    HpkeX25519HkdfSha256Aes256Gcm,
    HpkeX25519HkdfSha256ChaCha20Poly1305,
    // StreamingAead
    Aes128GcmHkdf4kb, Aes256GcmHkdf4kb,
    Aes128CtrHmacSha256Streaming4kb, Aes256CtrHmacSha256Streaming4kb,
    // JWT
    JwtHs256, JwtHs384, JwtHs512,
    JwtEs256, JwtEs384, JwtEs512,
    JwtRs256_2048, JwtRs256_3072,
    JwtPs256_2048, JwtPs256_3072,
    // PRF
    HmacPrfSha256, HkdfPrfSha256, AesCmacPrf,
}
```

### Primitive Trait (sealed)

```rust
pub trait Primitive: sealed::Sealed {
    fn from_keyset_handle(handle: &KeysetHandle) -> Result<Self> where Self: Sized;
}
```

Implemented for `AeadPrimitive`, `MacPrimitive`, `SignerPrimitive`, `VerifierPrimitive`, etc. Each concrete type owns its opaque FFI pointer and implements `Drop`.

## StreamingAead Detail

The C shim exposes chunked operations rather than wrapping C++ streams:

```c
int tink_streaming_aead_encrypt_start(handle, aad, aad_len, TinkEncryptingStream **stream_out);
int tink_encrypting_stream_write(stream, data, data_len, bytes_written_out);
int tink_encrypting_stream_finalize(stream, **out, *out_len);
void tink_encrypting_stream_free(stream);
```

Rust wraps these in `Write`/`Read` implementations.

## JWT Detail

`RawJwt` and `JwtValidator` are builder-pattern structs serialized to JSON at the FFI boundary. The C shim parses JSON back into tink-cc's JWT objects.

```rust
pub struct RawJwt { claims: serde_json::Value }
pub struct JwtValidator { /* validation params */ }
pub struct VerifiedJwt { claims: serde_json::Value }
```

## Thread Safety

All primitive structs are `Send + Sync`. tink-cc primitives are thread-safe. Opaque pointers are never mutated after construction.

## Memory Management

- All handle types implement `Drop` calling the corresponding `tink_*_free()`
- Output byte buffers from FFI are copied into `Vec<u8>` then freed with `tink_free_bytes()`
- No raw pointer escapes the safe API boundary

## Supported Primitives (Full Port)

| Primitive | C Shim File | Rust Module |
|-----------|-------------|-------------|
| AEAD | aead.cc | aead.rs |
| DeterministicAead | deterministic_aead.cc | deterministic_aead.rs |
| MAC | mac.cc | mac.rs |
| Signatures | signature.cc | signature.rs |
| Hybrid Encryption | hybrid.cc | hybrid.rs |
| StreamingAead | streaming_aead.cc | streaming_aead.rs |
| JWT | jwt.cc | jwt.rs |
| PRF | prf.cc | prf.rs |
| Key Derivation | key_derivation.cc | key_derivation.rs |
| Keyset Management | keyset.cc | keyset.rs |
| Configuration | config.cc | lib.rs |
