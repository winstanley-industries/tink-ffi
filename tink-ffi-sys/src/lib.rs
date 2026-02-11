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

#[repr(C)]
pub struct TinkKeysetHandle {
    _private: [u8; 0],
}

#[repr(C)]
pub struct TinkAead {
    _private: [u8; 0],
}

#[repr(C)]
pub struct TinkDeterministicAead {
    _private: [u8; 0],
}

#[repr(C)]
pub struct TinkMac {
    _private: [u8; 0],
}

#[repr(C)]
pub struct TinkSigner {
    _private: [u8; 0],
}

#[repr(C)]
pub struct TinkVerifier {
    _private: [u8; 0],
}

#[repr(C)]
pub struct TinkHybridEncrypt {
    _private: [u8; 0],
}

#[repr(C)]
pub struct TinkHybridDecrypt {
    _private: [u8; 0],
}

#[repr(C)]
pub struct TinkStreamingAead {
    _private: [u8; 0],
}

#[repr(C)]
pub struct TinkEncryptingStream {
    _private: [u8; 0],
}

#[repr(C)]
pub struct TinkDecryptingStream {
    _private: [u8; 0],
}

#[repr(C)]
pub struct TinkJwtMac {
    _private: [u8; 0],
}

#[repr(C)]
pub struct TinkJwtSigner {
    _private: [u8; 0],
}

#[repr(C)]
pub struct TinkJwtVerifier {
    _private: [u8; 0],
}

#[repr(C)]
pub struct TinkPrfSet {
    _private: [u8; 0],
}

#[repr(C)]
pub struct TinkKeysetDeriver {
    _private: [u8; 0],
}

extern "C" {
    // -----------------------------------------------------------------------
    // Error handling
    // -----------------------------------------------------------------------
    pub fn tink_error_message() -> *const c_char;

    // -----------------------------------------------------------------------
    // Memory management
    // -----------------------------------------------------------------------
    pub fn tink_free_bytes(ptr: *mut u8, len: usize);
    pub fn tink_free_string(ptr: *mut c_char);

    // -----------------------------------------------------------------------
    // Configuration & Registration
    // -----------------------------------------------------------------------
    pub fn tink_register_all() -> c_int;

    // -----------------------------------------------------------------------
    // KeysetHandle
    // -----------------------------------------------------------------------
    pub fn tink_keyset_handle_generate_new(
        template_name: *const c_char,
        handle_out: *mut *mut TinkKeysetHandle,
    ) -> c_int;

    pub fn tink_keyset_handle_to_json(
        handle: *const TinkKeysetHandle,
        json_out: *mut *mut c_char,
    ) -> c_int;

    pub fn tink_keyset_handle_from_json(
        json: *const c_char,
        handle_out: *mut *mut TinkKeysetHandle,
    ) -> c_int;

    pub fn tink_keyset_handle_to_binary(
        handle: *const TinkKeysetHandle,
        data_out: *mut *mut u8,
        data_len_out: *mut usize,
    ) -> c_int;

    pub fn tink_keyset_handle_from_binary(
        data: *const u8,
        data_len: usize,
        handle_out: *mut *mut TinkKeysetHandle,
    ) -> c_int;

    pub fn tink_keyset_handle_public(
        handle: *const TinkKeysetHandle,
        public_out: *mut *mut TinkKeysetHandle,
    ) -> c_int;

    pub fn tink_keyset_handle_info(
        handle: *const TinkKeysetHandle,
        info_out: *mut *mut c_char,
    ) -> c_int;

    pub fn tink_key_template_serialize(
        template_name: *const c_char,
        bytes_out: *mut *mut u8,
        len_out: *mut usize,
    ) -> c_int;

    pub fn tink_keyset_handle_generate_from_template_bytes(
        template_bytes: *const u8,
        template_len: usize,
        handle_out: *mut *mut TinkKeysetHandle,
    ) -> c_int;

    pub fn tink_keyset_handle_read_encrypted(
        encrypted: *const u8,
        encrypted_len: usize,
        master_keyset: *const u8,
        master_len: usize,
        associated_data: *const u8,
        ad_len: usize,
        handle_out: *mut *mut TinkKeysetHandle,
    ) -> c_int;

    pub fn tink_keyset_handle_write_encrypted(
        handle: *const TinkKeysetHandle,
        master_keyset: *const u8,
        master_len: usize,
        associated_data: *const u8,
        ad_len: usize,
        out: *mut *mut u8,
        out_len: *mut usize,
    ) -> c_int;

    pub fn tink_keyset_handle_free(handle: *mut TinkKeysetHandle);

    // -----------------------------------------------------------------------
    // AEAD
    // -----------------------------------------------------------------------
    pub fn tink_aead_new(handle: *const TinkKeysetHandle, aead_out: *mut *mut TinkAead) -> c_int;

    pub fn tink_aead_encrypt(
        aead: *const TinkAead,
        plaintext: *const u8,
        plaintext_len: usize,
        aad: *const u8,
        aad_len: usize,
        ciphertext_out: *mut *mut u8,
        ciphertext_len_out: *mut usize,
    ) -> c_int;

    pub fn tink_aead_decrypt(
        aead: *const TinkAead,
        ciphertext: *const u8,
        ciphertext_len: usize,
        aad: *const u8,
        aad_len: usize,
        plaintext_out: *mut *mut u8,
        plaintext_len_out: *mut usize,
    ) -> c_int;

    pub fn tink_aead_free(aead: *mut TinkAead);

    // -----------------------------------------------------------------------
    // Deterministic AEAD
    // -----------------------------------------------------------------------
    pub fn tink_deterministic_aead_new(
        handle: *const TinkKeysetHandle,
        daead_out: *mut *mut TinkDeterministicAead,
    ) -> c_int;

    pub fn tink_deterministic_aead_encrypt(
        daead: *const TinkDeterministicAead,
        plaintext: *const u8,
        plaintext_len: usize,
        aad: *const u8,
        aad_len: usize,
        ciphertext_out: *mut *mut u8,
        ciphertext_len_out: *mut usize,
    ) -> c_int;

    pub fn tink_deterministic_aead_decrypt(
        daead: *const TinkDeterministicAead,
        ciphertext: *const u8,
        ciphertext_len: usize,
        aad: *const u8,
        aad_len: usize,
        plaintext_out: *mut *mut u8,
        plaintext_len_out: *mut usize,
    ) -> c_int;

    pub fn tink_deterministic_aead_free(daead: *mut TinkDeterministicAead);

    // -----------------------------------------------------------------------
    // MAC
    // -----------------------------------------------------------------------
    pub fn tink_mac_new(handle: *const TinkKeysetHandle, mac_out: *mut *mut TinkMac) -> c_int;

    pub fn tink_mac_compute(
        mac: *const TinkMac,
        data: *const u8,
        data_len: usize,
        mac_out: *mut *mut u8,
        mac_len_out: *mut usize,
    ) -> c_int;

    pub fn tink_mac_verify(
        mac: *const TinkMac,
        mac_value: *const u8,
        mac_value_len: usize,
        data: *const u8,
        data_len: usize,
    ) -> c_int;

    pub fn tink_mac_free(mac: *mut TinkMac);

    // -----------------------------------------------------------------------
    // Digital Signatures
    // -----------------------------------------------------------------------
    pub fn tink_signer_new(
        handle: *const TinkKeysetHandle,
        signer_out: *mut *mut TinkSigner,
    ) -> c_int;

    pub fn tink_signer_sign(
        signer: *const TinkSigner,
        data: *const u8,
        data_len: usize,
        signature_out: *mut *mut u8,
        signature_len_out: *mut usize,
    ) -> c_int;

    pub fn tink_signer_free(signer: *mut TinkSigner);

    pub fn tink_verifier_new(
        handle: *const TinkKeysetHandle,
        verifier_out: *mut *mut TinkVerifier,
    ) -> c_int;

    pub fn tink_verifier_verify(
        verifier: *const TinkVerifier,
        signature: *const u8,
        signature_len: usize,
        data: *const u8,
        data_len: usize,
    ) -> c_int;

    pub fn tink_verifier_free(verifier: *mut TinkVerifier);

    // -----------------------------------------------------------------------
    // Hybrid Encryption
    // -----------------------------------------------------------------------
    pub fn tink_hybrid_encrypt_new(
        handle: *const TinkKeysetHandle,
        enc_out: *mut *mut TinkHybridEncrypt,
    ) -> c_int;

    pub fn tink_hybrid_encrypt(
        enc: *const TinkHybridEncrypt,
        plaintext: *const u8,
        plaintext_len: usize,
        context_info: *const u8,
        context_info_len: usize,
        ciphertext_out: *mut *mut u8,
        ciphertext_len_out: *mut usize,
    ) -> c_int;

    pub fn tink_hybrid_encrypt_free(enc: *mut TinkHybridEncrypt);

    pub fn tink_hybrid_decrypt_new(
        handle: *const TinkKeysetHandle,
        dec_out: *mut *mut TinkHybridDecrypt,
    ) -> c_int;

    pub fn tink_hybrid_decrypt(
        dec: *const TinkHybridDecrypt,
        ciphertext: *const u8,
        ciphertext_len: usize,
        context_info: *const u8,
        context_info_len: usize,
        plaintext_out: *mut *mut u8,
        plaintext_len_out: *mut usize,
    ) -> c_int;

    pub fn tink_hybrid_decrypt_free(dec: *mut TinkHybridDecrypt);

    // -----------------------------------------------------------------------
    // Streaming AEAD
    // -----------------------------------------------------------------------
    pub fn tink_streaming_aead_new(
        handle: *const TinkKeysetHandle,
        saead_out: *mut *mut TinkStreamingAead,
    ) -> c_int;

    pub fn tink_streaming_aead_encrypt_start(
        saead: *const TinkStreamingAead,
        aad: *const u8,
        aad_len: usize,
        stream_out: *mut *mut TinkEncryptingStream,
    ) -> c_int;

    pub fn tink_encrypting_stream_write(
        stream: *mut TinkEncryptingStream,
        data: *const u8,
        data_len: usize,
        written_out: *mut usize,
    ) -> c_int;

    pub fn tink_encrypting_stream_finalize(
        stream: *mut TinkEncryptingStream,
        ciphertext_out: *mut *mut u8,
        ciphertext_len_out: *mut usize,
    ) -> c_int;

    pub fn tink_encrypting_stream_free(stream: *mut TinkEncryptingStream);

    pub fn tink_streaming_aead_decrypt_start(
        saead: *const TinkStreamingAead,
        ciphertext: *const u8,
        ciphertext_len: usize,
        aad: *const u8,
        aad_len: usize,
        stream_out: *mut *mut TinkDecryptingStream,
    ) -> c_int;

    pub fn tink_decrypting_stream_read(
        stream: *mut TinkDecryptingStream,
        buf: *mut u8,
        buf_len: usize,
        read_out: *mut usize,
    ) -> c_int;

    pub fn tink_decrypting_stream_free(stream: *mut TinkDecryptingStream);

    pub fn tink_streaming_aead_free(saead: *mut TinkStreamingAead);

    // -----------------------------------------------------------------------
    // JWT MAC
    // -----------------------------------------------------------------------
    pub fn tink_jwt_mac_new(
        handle: *const TinkKeysetHandle,
        jwt_mac_out: *mut *mut TinkJwtMac,
    ) -> c_int;

    pub fn tink_jwt_mac_compute_and_encode(
        jwt_mac: *const TinkJwtMac,
        raw_jwt_json: *const c_char,
        compact_out: *mut *mut c_char,
    ) -> c_int;

    pub fn tink_jwt_mac_verify_and_decode(
        jwt_mac: *const TinkJwtMac,
        compact: *const c_char,
        validator_json: *const c_char,
        claims_json_out: *mut *mut c_char,
    ) -> c_int;

    pub fn tink_jwt_mac_free(jwt_mac: *mut TinkJwtMac);

    // -----------------------------------------------------------------------
    // JWT Public Key Sign / Verify
    // -----------------------------------------------------------------------
    pub fn tink_jwt_signer_new(
        handle: *const TinkKeysetHandle,
        signer_out: *mut *mut TinkJwtSigner,
    ) -> c_int;

    pub fn tink_jwt_signer_sign_and_encode(
        signer: *const TinkJwtSigner,
        raw_jwt_json: *const c_char,
        compact_out: *mut *mut c_char,
    ) -> c_int;

    pub fn tink_jwt_signer_free(signer: *mut TinkJwtSigner);

    pub fn tink_jwt_verifier_new(
        handle: *const TinkKeysetHandle,
        verifier_out: *mut *mut TinkJwtVerifier,
    ) -> c_int;

    pub fn tink_jwt_verifier_verify_and_decode(
        verifier: *const TinkJwtVerifier,
        compact: *const c_char,
        validator_json: *const c_char,
        claims_json_out: *mut *mut c_char,
    ) -> c_int;

    pub fn tink_jwt_verifier_free(verifier: *mut TinkJwtVerifier);

    // -----------------------------------------------------------------------
    // PRF Set
    // -----------------------------------------------------------------------
    pub fn tink_prf_set_new(
        handle: *const TinkKeysetHandle,
        prf_set_out: *mut *mut TinkPrfSet,
    ) -> c_int;

    pub fn tink_prf_set_primary_id(prf_set: *const TinkPrfSet, id_out: *mut u32) -> c_int;

    pub fn tink_prf_set_compute_primary(
        prf_set: *const TinkPrfSet,
        input: *const u8,
        input_len: usize,
        output_len: usize,
        output_out: *mut *mut u8,
        output_len_out: *mut usize,
    ) -> c_int;

    pub fn tink_prf_set_key_ids(
        prf_set: *const TinkPrfSet,
        key_ids_out: *mut *mut u32,
        num_keys_out: *mut usize,
    ) -> c_int;

    pub fn tink_prf_set_compute(
        prf_set: *const TinkPrfSet,
        key_id: u32,
        input: *const u8,
        input_len: usize,
        output_len: usize,
        output_out: *mut *mut u8,
        output_len_out: *mut usize,
    ) -> c_int;

    pub fn tink_prf_set_free(prf_set: *mut TinkPrfSet);

    // -----------------------------------------------------------------------
    // Keyset Derivation
    // -----------------------------------------------------------------------
    pub fn tink_keyset_deriver_new(
        handle: *const TinkKeysetHandle,
        deriver_out: *mut *mut TinkKeysetDeriver,
    ) -> c_int;

    pub fn tink_keyset_deriver_derive(
        deriver: *const TinkKeysetDeriver,
        salt: *const u8,
        salt_len: usize,
        derived_handle_out: *mut *mut TinkKeysetHandle,
    ) -> c_int;

    pub fn tink_keyset_deriver_free(deriver: *mut TinkKeysetDeriver);
}
