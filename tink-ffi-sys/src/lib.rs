#![doc = "Raw FFI bindings to [Google Tink](https://github.com/tink-crypto/tink-cc) via a C shim.

This crate provides low-level `extern \"C\"` functions that map directly to the
C shim built on top of tink-cc. **Most users should prefer the safe
[`tink_ffi`] crate**, which wraps these bindings in idiomatic Rust with
automatic memory management.

# Conventions

- All functions return `c_int` where `0` means success and non-zero means error.
- On error, a thread-local message is set and can be retrieved with
  [`tink_error_message`].
- Pointers returned by these functions are allocated on the C++ side. The caller
  **must** free them with [`tink_free_bytes`] (for `*mut u8` + length) or
  [`tink_free_string`] (for `*mut c_char`).
- Opaque handle types (e.g. [`TinkAead`]) must be freed with their corresponding
  `_free` function.

# Build

This crate builds tink-cc from source via CMake. You need CMake 3.13+ and a
C++17 compiler."]

// Copyright 2026 Adam Winstanley
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_int};

// ---------------------------------------------------------------------------
// Opaque handle types
// ---------------------------------------------------------------------------

/// Opaque handle to a Tink keyset. See [`tink_ffi::KeysetHandle`] for the safe wrapper.
#[repr(C)]
pub struct TinkKeysetHandle {
    _private: [u8; 0],
}

/// Opaque handle to a Tink AEAD primitive. See [`tink_ffi::Aead`] for the safe wrapper.
#[repr(C)]
pub struct TinkAead {
    _private: [u8; 0],
}

/// Opaque handle to a Tink deterministic AEAD primitive. See [`tink_ffi::DeterministicAead`] for the safe wrapper.
#[repr(C)]
pub struct TinkDeterministicAead {
    _private: [u8; 0],
}

/// Opaque handle to a Tink MAC primitive. See [`tink_ffi::Mac`] for the safe wrapper.
#[repr(C)]
pub struct TinkMac {
    _private: [u8; 0],
}

/// Opaque handle to a Tink public-key signer. See [`tink_ffi::Signer`] for the safe wrapper.
#[repr(C)]
pub struct TinkSigner {
    _private: [u8; 0],
}

/// Opaque handle to a Tink public-key verifier. See [`tink_ffi::Verifier`] for the safe wrapper.
#[repr(C)]
pub struct TinkVerifier {
    _private: [u8; 0],
}

/// Opaque handle to a Tink hybrid encryption primitive. See [`tink_ffi::HybridEncrypt`] for the safe wrapper.
#[repr(C)]
pub struct TinkHybridEncrypt {
    _private: [u8; 0],
}

/// Opaque handle to a Tink hybrid decryption primitive. See [`tink_ffi::HybridDecrypt`] for the safe wrapper.
#[repr(C)]
pub struct TinkHybridDecrypt {
    _private: [u8; 0],
}

/// Opaque handle to a Tink streaming AEAD primitive. See [`tink_ffi::StreamingAead`] for the safe wrapper.
#[repr(C)]
pub struct TinkStreamingAead {
    _private: [u8; 0],
}

/// Opaque handle to an in-progress encrypting stream.
#[repr(C)]
pub struct TinkEncryptingStream {
    _private: [u8; 0],
}

/// Opaque handle to an in-progress decrypting stream.
#[repr(C)]
pub struct TinkDecryptingStream {
    _private: [u8; 0],
}

/// Opaque handle to a Tink JWT MAC primitive. See [`tink_ffi::JwtMac`] for the safe wrapper.
#[repr(C)]
pub struct TinkJwtMac {
    _private: [u8; 0],
}

/// Opaque handle to a Tink JWT signer. See [`tink_ffi::JwtSigner`] for the safe wrapper.
#[repr(C)]
pub struct TinkJwtSigner {
    _private: [u8; 0],
}

/// Opaque handle to a Tink JWT verifier. See [`tink_ffi::JwtVerifier`] for the safe wrapper.
#[repr(C)]
pub struct TinkJwtVerifier {
    _private: [u8; 0],
}

/// Opaque handle to a Tink PRF set. See [`tink_ffi::PrfSet`] for the safe wrapper.
#[repr(C)]
pub struct TinkPrfSet {
    _private: [u8; 0],
}

/// Opaque handle to a Tink keyset deriver. See [`tink_ffi::KeysetDeriver`] for the safe wrapper.
#[repr(C)]
pub struct TinkKeysetDeriver {
    _private: [u8; 0],
}

extern "C" {
    // -----------------------------------------------------------------------
    // Error handling
    // -----------------------------------------------------------------------

    /// Return the thread-local error message from the last failed operation, or null if none.
    pub fn tink_error_message() -> *const c_char;

    // -----------------------------------------------------------------------
    // Memory management
    // -----------------------------------------------------------------------

    /// Free a byte buffer allocated by the C shim.
    pub fn tink_free_bytes(ptr: *mut u8, len: usize);

    /// Free a C string allocated by the C shim.
    pub fn tink_free_string(ptr: *mut c_char);

    // -----------------------------------------------------------------------
    // Configuration & Registration
    // -----------------------------------------------------------------------

    /// Register all Tink primitive factories (AEAD, MAC, signatures, hybrid, JWT, PRF, etc.).
    pub fn tink_register_all() -> c_int;

    // -----------------------------------------------------------------------
    // KeysetHandle
    // -----------------------------------------------------------------------

    /// Generate a new keyset for the named key template.
    pub fn tink_keyset_handle_generate_new(
        template_name: *const c_char,
        handle_out: *mut *mut TinkKeysetHandle,
    ) -> c_int;

    /// Serialize a keyset handle to JSON. Caller must free the string with [`tink_free_string`].
    pub fn tink_keyset_handle_to_json(
        handle: *const TinkKeysetHandle,
        json_out: *mut *mut c_char,
    ) -> c_int;

    /// Deserialize a keyset handle from a JSON string.
    pub fn tink_keyset_handle_from_json(
        json: *const c_char,
        handle_out: *mut *mut TinkKeysetHandle,
    ) -> c_int;

    /// Serialize a keyset handle to binary. Caller must free with [`tink_free_bytes`].
    pub fn tink_keyset_handle_to_binary(
        handle: *const TinkKeysetHandle,
        data_out: *mut *mut u8,
        data_len_out: *mut usize,
    ) -> c_int;

    /// Deserialize a keyset handle from binary.
    pub fn tink_keyset_handle_from_binary(
        data: *const u8,
        data_len: usize,
        handle_out: *mut *mut TinkKeysetHandle,
    ) -> c_int;

    /// Extract the public key portion of an asymmetric keyset.
    pub fn tink_keyset_handle_public(
        handle: *const TinkKeysetHandle,
        public_out: *mut *mut TinkKeysetHandle,
    ) -> c_int;

    /// Return keyset metadata as a JSON string. Caller must free with [`tink_free_string`].
    pub fn tink_keyset_handle_info(
        handle: *const TinkKeysetHandle,
        info_out: *mut *mut c_char,
    ) -> c_int;

    /// Serialize a named key template to its protobuf bytes. Caller must free with [`tink_free_bytes`].
    pub fn tink_key_template_serialize(
        template_name: *const c_char,
        bytes_out: *mut *mut u8,
        len_out: *mut usize,
    ) -> c_int;

    /// Generate a new keyset from raw serialized key-template bytes.
    pub fn tink_keyset_handle_generate_from_template_bytes(
        template_bytes: *const u8,
        template_len: usize,
        handle_out: *mut *mut TinkKeysetHandle,
    ) -> c_int;

    /// Decrypt and deserialize an encrypted keyset. The master keyset provides the AEAD key used for decryption.
    pub fn tink_keyset_handle_read_encrypted(
        encrypted: *const u8,
        encrypted_len: usize,
        master_keyset: *const u8,
        master_len: usize,
        associated_data: *const u8,
        ad_len: usize,
        handle_out: *mut *mut TinkKeysetHandle,
    ) -> c_int;

    /// Serialize and encrypt a keyset. Caller must free the output with [`tink_free_bytes`].
    pub fn tink_keyset_handle_write_encrypted(
        handle: *const TinkKeysetHandle,
        master_keyset: *const u8,
        master_len: usize,
        associated_data: *const u8,
        ad_len: usize,
        out: *mut *mut u8,
        out_len: *mut usize,
    ) -> c_int;

    /// Free a keyset handle.
    pub fn tink_keyset_handle_free(handle: *mut TinkKeysetHandle);

    // -----------------------------------------------------------------------
    // AEAD
    // -----------------------------------------------------------------------

    /// Create a new AEAD primitive from a keyset handle.
    pub fn tink_aead_new(handle: *const TinkKeysetHandle, aead_out: *mut *mut TinkAead) -> c_int;

    /// Encrypt plaintext with associated data. Caller must free ciphertext with [`tink_free_bytes`].
    pub fn tink_aead_encrypt(
        aead: *const TinkAead,
        plaintext: *const u8,
        plaintext_len: usize,
        aad: *const u8,
        aad_len: usize,
        ciphertext_out: *mut *mut u8,
        ciphertext_len_out: *mut usize,
    ) -> c_int;

    /// Decrypt ciphertext with associated data. Caller must free plaintext with [`tink_free_bytes`].
    pub fn tink_aead_decrypt(
        aead: *const TinkAead,
        ciphertext: *const u8,
        ciphertext_len: usize,
        aad: *const u8,
        aad_len: usize,
        plaintext_out: *mut *mut u8,
        plaintext_len_out: *mut usize,
    ) -> c_int;

    /// Free an AEAD handle.
    pub fn tink_aead_free(aead: *mut TinkAead);

    // -----------------------------------------------------------------------
    // Deterministic AEAD
    // -----------------------------------------------------------------------

    /// Create a new deterministic AEAD primitive from a keyset handle.
    pub fn tink_deterministic_aead_new(
        handle: *const TinkKeysetHandle,
        daead_out: *mut *mut TinkDeterministicAead,
    ) -> c_int;

    /// Deterministically encrypt plaintext with associated data. Caller must free ciphertext with [`tink_free_bytes`].
    pub fn tink_deterministic_aead_encrypt(
        daead: *const TinkDeterministicAead,
        plaintext: *const u8,
        plaintext_len: usize,
        aad: *const u8,
        aad_len: usize,
        ciphertext_out: *mut *mut u8,
        ciphertext_len_out: *mut usize,
    ) -> c_int;

    /// Decrypt deterministically-encrypted ciphertext. Caller must free plaintext with [`tink_free_bytes`].
    pub fn tink_deterministic_aead_decrypt(
        daead: *const TinkDeterministicAead,
        ciphertext: *const u8,
        ciphertext_len: usize,
        aad: *const u8,
        aad_len: usize,
        plaintext_out: *mut *mut u8,
        plaintext_len_out: *mut usize,
    ) -> c_int;

    /// Free a deterministic AEAD handle.
    pub fn tink_deterministic_aead_free(daead: *mut TinkDeterministicAead);

    // -----------------------------------------------------------------------
    // MAC
    // -----------------------------------------------------------------------

    /// Create a new MAC primitive from a keyset handle.
    pub fn tink_mac_new(handle: *const TinkKeysetHandle, mac_out: *mut *mut TinkMac) -> c_int;

    /// Compute a MAC tag over data. Caller must free the tag with [`tink_free_bytes`].
    pub fn tink_mac_compute(
        mac: *const TinkMac,
        data: *const u8,
        data_len: usize,
        mac_out: *mut *mut u8,
        mac_len_out: *mut usize,
    ) -> c_int;

    /// Verify a MAC tag against data.
    pub fn tink_mac_verify(
        mac: *const TinkMac,
        mac_value: *const u8,
        mac_value_len: usize,
        data: *const u8,
        data_len: usize,
    ) -> c_int;

    /// Free a MAC handle.
    pub fn tink_mac_free(mac: *mut TinkMac);

    // -----------------------------------------------------------------------
    // Digital Signatures
    // -----------------------------------------------------------------------

    /// Create a new public-key signer from a keyset handle containing a private key.
    pub fn tink_signer_new(
        handle: *const TinkKeysetHandle,
        signer_out: *mut *mut TinkSigner,
    ) -> c_int;

    /// Sign data. Caller must free the signature with [`tink_free_bytes`].
    pub fn tink_signer_sign(
        signer: *const TinkSigner,
        data: *const u8,
        data_len: usize,
        signature_out: *mut *mut u8,
        signature_len_out: *mut usize,
    ) -> c_int;

    /// Free a signer handle.
    pub fn tink_signer_free(signer: *mut TinkSigner);

    /// Create a new public-key verifier from a keyset handle containing a public key.
    pub fn tink_verifier_new(
        handle: *const TinkKeysetHandle,
        verifier_out: *mut *mut TinkVerifier,
    ) -> c_int;

    /// Verify a signature over data.
    pub fn tink_verifier_verify(
        verifier: *const TinkVerifier,
        signature: *const u8,
        signature_len: usize,
        data: *const u8,
        data_len: usize,
    ) -> c_int;

    /// Free a verifier handle.
    pub fn tink_verifier_free(verifier: *mut TinkVerifier);

    // -----------------------------------------------------------------------
    // Hybrid Encryption
    // -----------------------------------------------------------------------

    /// Create a new hybrid encryption primitive from a keyset handle containing a public key.
    pub fn tink_hybrid_encrypt_new(
        handle: *const TinkKeysetHandle,
        enc_out: *mut *mut TinkHybridEncrypt,
    ) -> c_int;

    /// Hybrid-encrypt plaintext with context info. Caller must free ciphertext with [`tink_free_bytes`].
    pub fn tink_hybrid_encrypt(
        enc: *const TinkHybridEncrypt,
        plaintext: *const u8,
        plaintext_len: usize,
        context_info: *const u8,
        context_info_len: usize,
        ciphertext_out: *mut *mut u8,
        ciphertext_len_out: *mut usize,
    ) -> c_int;

    /// Free a hybrid encrypt handle.
    pub fn tink_hybrid_encrypt_free(enc: *mut TinkHybridEncrypt);

    /// Create a new hybrid decryption primitive from a keyset handle containing a private key.
    pub fn tink_hybrid_decrypt_new(
        handle: *const TinkKeysetHandle,
        dec_out: *mut *mut TinkHybridDecrypt,
    ) -> c_int;

    /// Hybrid-decrypt ciphertext with context info. Caller must free plaintext with [`tink_free_bytes`].
    pub fn tink_hybrid_decrypt(
        dec: *const TinkHybridDecrypt,
        ciphertext: *const u8,
        ciphertext_len: usize,
        context_info: *const u8,
        context_info_len: usize,
        plaintext_out: *mut *mut u8,
        plaintext_len_out: *mut usize,
    ) -> c_int;

    /// Free a hybrid decrypt handle.
    pub fn tink_hybrid_decrypt_free(dec: *mut TinkHybridDecrypt);

    // -----------------------------------------------------------------------
    // Streaming AEAD
    // -----------------------------------------------------------------------

    /// Create a new streaming AEAD primitive from a keyset handle.
    pub fn tink_streaming_aead_new(
        handle: *const TinkKeysetHandle,
        saead_out: *mut *mut TinkStreamingAead,
    ) -> c_int;

    /// Begin a streaming encryption with the given associated data.
    pub fn tink_streaming_aead_encrypt_start(
        saead: *const TinkStreamingAead,
        aad: *const u8,
        aad_len: usize,
        stream_out: *mut *mut TinkEncryptingStream,
    ) -> c_int;

    /// Write plaintext data to an encrypting stream. Returns bytes written.
    pub fn tink_encrypting_stream_write(
        stream: *mut TinkEncryptingStream,
        data: *const u8,
        data_len: usize,
        written_out: *mut usize,
    ) -> c_int;

    /// Finalize an encrypting stream and retrieve the full ciphertext. Caller must free with [`tink_free_bytes`].
    pub fn tink_encrypting_stream_finalize(
        stream: *mut TinkEncryptingStream,
        ciphertext_out: *mut *mut u8,
        ciphertext_len_out: *mut usize,
    ) -> c_int;

    /// Free an encrypting stream handle.
    pub fn tink_encrypting_stream_free(stream: *mut TinkEncryptingStream);

    /// Begin a streaming decryption of the given ciphertext with associated data.
    pub fn tink_streaming_aead_decrypt_start(
        saead: *const TinkStreamingAead,
        ciphertext: *const u8,
        ciphertext_len: usize,
        aad: *const u8,
        aad_len: usize,
        stream_out: *mut *mut TinkDecryptingStream,
    ) -> c_int;

    /// Read decrypted plaintext from a decrypting stream into a buffer. Returns bytes read.
    pub fn tink_decrypting_stream_read(
        stream: *mut TinkDecryptingStream,
        buf: *mut u8,
        buf_len: usize,
        read_out: *mut usize,
    ) -> c_int;

    /// Free a decrypting stream handle.
    pub fn tink_decrypting_stream_free(stream: *mut TinkDecryptingStream);

    /// Free a streaming AEAD handle.
    pub fn tink_streaming_aead_free(saead: *mut TinkStreamingAead);

    // -----------------------------------------------------------------------
    // JWT MAC
    // -----------------------------------------------------------------------

    /// Create a new JWT MAC primitive from a keyset handle.
    pub fn tink_jwt_mac_new(
        handle: *const TinkKeysetHandle,
        jwt_mac_out: *mut *mut TinkJwtMac,
    ) -> c_int;

    /// Compute and encode a JWT MAC. Caller must free the compact token with [`tink_free_string`].
    pub fn tink_jwt_mac_compute_and_encode(
        jwt_mac: *const TinkJwtMac,
        raw_jwt_json: *const c_char,
        compact_out: *mut *mut c_char,
    ) -> c_int;

    /// Verify and decode a compact JWT token. Caller must free the claims JSON with [`tink_free_string`].
    pub fn tink_jwt_mac_verify_and_decode(
        jwt_mac: *const TinkJwtMac,
        compact: *const c_char,
        validator_json: *const c_char,
        claims_json_out: *mut *mut c_char,
    ) -> c_int;

    /// Free a JWT MAC handle.
    pub fn tink_jwt_mac_free(jwt_mac: *mut TinkJwtMac);

    // -----------------------------------------------------------------------
    // JWT Public Key Sign / Verify
    // -----------------------------------------------------------------------

    /// Create a new JWT signer from a keyset handle containing a private key.
    pub fn tink_jwt_signer_new(
        handle: *const TinkKeysetHandle,
        signer_out: *mut *mut TinkJwtSigner,
    ) -> c_int;

    /// Sign and encode a JWT. Caller must free the compact token with [`tink_free_string`].
    pub fn tink_jwt_signer_sign_and_encode(
        signer: *const TinkJwtSigner,
        raw_jwt_json: *const c_char,
        compact_out: *mut *mut c_char,
    ) -> c_int;

    /// Free a JWT signer handle.
    pub fn tink_jwt_signer_free(signer: *mut TinkJwtSigner);

    /// Create a new JWT verifier from a keyset handle containing a public key.
    pub fn tink_jwt_verifier_new(
        handle: *const TinkKeysetHandle,
        verifier_out: *mut *mut TinkJwtVerifier,
    ) -> c_int;

    /// Verify and decode a compact JWT token. Caller must free the claims JSON with [`tink_free_string`].
    pub fn tink_jwt_verifier_verify_and_decode(
        verifier: *const TinkJwtVerifier,
        compact: *const c_char,
        validator_json: *const c_char,
        claims_json_out: *mut *mut c_char,
    ) -> c_int;

    /// Free a JWT verifier handle.
    pub fn tink_jwt_verifier_free(verifier: *mut TinkJwtVerifier);

    // -----------------------------------------------------------------------
    // PRF Set
    // -----------------------------------------------------------------------

    /// Create a new PRF set from a keyset handle.
    pub fn tink_prf_set_new(
        handle: *const TinkKeysetHandle,
        prf_set_out: *mut *mut TinkPrfSet,
    ) -> c_int;

    /// Get the key ID of the primary PRF in the set.
    pub fn tink_prf_set_primary_id(prf_set: *const TinkPrfSet, id_out: *mut u32) -> c_int;

    /// Compute the primary PRF over input. Caller must free output with [`tink_free_bytes`].
    pub fn tink_prf_set_compute_primary(
        prf_set: *const TinkPrfSet,
        input: *const u8,
        input_len: usize,
        output_len: usize,
        output_out: *mut *mut u8,
        output_len_out: *mut usize,
    ) -> c_int;

    /// Get the key IDs of all PRFs in the set. Caller must free with [`tink_free_bytes`].
    pub fn tink_prf_set_key_ids(
        prf_set: *const TinkPrfSet,
        key_ids_out: *mut *mut u32,
        num_keys_out: *mut usize,
    ) -> c_int;

    /// Compute a specific PRF by key ID over input. Caller must free output with [`tink_free_bytes`].
    pub fn tink_prf_set_compute(
        prf_set: *const TinkPrfSet,
        key_id: u32,
        input: *const u8,
        input_len: usize,
        output_len: usize,
        output_out: *mut *mut u8,
        output_len_out: *mut usize,
    ) -> c_int;

    /// Free a PRF set handle.
    pub fn tink_prf_set_free(prf_set: *mut TinkPrfSet);

    // -----------------------------------------------------------------------
    // Keyset Derivation
    // -----------------------------------------------------------------------

    /// Create a new keyset deriver from a keyset handle.
    pub fn tink_keyset_deriver_new(
        handle: *const TinkKeysetHandle,
        deriver_out: *mut *mut TinkKeysetDeriver,
    ) -> c_int;

    /// Derive a new keyset handle from a salt. The caller owns the returned handle.
    pub fn tink_keyset_deriver_derive(
        deriver: *const TinkKeysetDeriver,
        salt: *const u8,
        salt_len: usize,
        derived_handle_out: *mut *mut TinkKeysetHandle,
    ) -> c_int;

    /// Free a keyset deriver handle.
    pub fn tink_keyset_deriver_free(deriver: *mut TinkKeysetDeriver);
}
