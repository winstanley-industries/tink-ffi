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

#ifndef TINK_FFI_H_
#define TINK_FFI_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Error handling
 *
 * Every function returning int uses 0 = success, non-zero = failure.
 * On failure, call tink_error_message() to retrieve a thread-local
 * human-readable error string (valid until the next tink_* call on that
 * thread).
 * -------------------------------------------------------------------------- */
const char *tink_error_message(void);

/* --------------------------------------------------------------------------
 * Memory management
 *
 * Byte buffers returned via out-pointers must be freed with tink_free_bytes.
 * String buffers (char*) must be freed with tink_free_string.
 * -------------------------------------------------------------------------- */
void tink_free_bytes(uint8_t *ptr, size_t len);
void tink_free_string(char *ptr);

/* --------------------------------------------------------------------------
 * Opaque handle types
 * -------------------------------------------------------------------------- */
typedef struct TinkKeysetHandle TinkKeysetHandle;
typedef struct TinkAead TinkAead;
typedef struct TinkDeterministicAead TinkDeterministicAead;
typedef struct TinkMac TinkMac;
typedef struct TinkSigner TinkSigner;
typedef struct TinkVerifier TinkVerifier;
typedef struct TinkHybridEncrypt TinkHybridEncrypt;
typedef struct TinkHybridDecrypt TinkHybridDecrypt;
typedef struct TinkStreamingAead TinkStreamingAead;
typedef struct TinkEncryptingStream TinkEncryptingStream;
typedef struct TinkDecryptingStream TinkDecryptingStream;
typedef struct TinkJwtMac TinkJwtMac;
typedef struct TinkJwtSigner TinkJwtSigner;
typedef struct TinkJwtVerifier TinkJwtVerifier;
typedef struct TinkPrfSet TinkPrfSet;
typedef struct TinkKeysetDeriver TinkKeysetDeriver;

/* --------------------------------------------------------------------------
 * Configuration & Registration
 * -------------------------------------------------------------------------- */
int tink_register_all(void);

/* --------------------------------------------------------------------------
 * KeysetHandle — creation, serialization, primitive extraction
 * -------------------------------------------------------------------------- */

/* Generate a new keyset from a named template (e.g. "AES256_GCM"). */
int tink_keyset_handle_generate_new(const char *template_name,
                                    TinkKeysetHandle **handle_out);

/* Serialize keyset to JSON (cleartext — for testing / non-secret keys). */
int tink_keyset_handle_to_json(const TinkKeysetHandle *handle,
                               char **json_out);

/* Deserialize keyset from JSON (cleartext). */
int tink_keyset_handle_from_json(const char *json,
                                 TinkKeysetHandle **handle_out);

/* Serialize keyset to binary protobuf (cleartext). */
int tink_keyset_handle_to_binary(const TinkKeysetHandle *handle,
                                 uint8_t **data_out, size_t *data_len_out);

/* Deserialize keyset from binary protobuf (cleartext). */
int tink_keyset_handle_from_binary(const uint8_t *data, size_t data_len,
                                   TinkKeysetHandle **handle_out);

/* Extract public key handle from a private key handle. */
int tink_keyset_handle_public(const TinkKeysetHandle *handle,
                              TinkKeysetHandle **public_out);

/* Get keyset info as JSON string. */
int tink_keyset_handle_info(const TinkKeysetHandle *handle, char **info_out);

/* Serialize a KeyTemplate to binary protobuf by name (e.g. "AES256_GCM"). */
int tink_key_template_serialize(const char *template_name,
                                uint8_t **bytes_out, size_t *len_out);

/* Generate a new keyset from a serialized KeyTemplate (binary protobuf). */
int tink_keyset_handle_generate_from_template_bytes(
    const uint8_t *template_bytes, size_t template_len,
    TinkKeysetHandle **handle_out);

/* Decrypt and load an encrypted keyset using a master keyset's AEAD.
 * If associated_data is NULL, no associated data is used. */
int tink_keyset_handle_read_encrypted(
    const uint8_t *encrypted, size_t encrypted_len,
    const uint8_t *master_keyset, size_t master_len,
    const uint8_t *associated_data, size_t ad_len,
    TinkKeysetHandle **handle_out);

/* Encrypt and serialize a keyset using a master keyset's AEAD.
 * If associated_data is NULL, no associated data is used. */
int tink_keyset_handle_write_encrypted(
    const TinkKeysetHandle *handle,
    const uint8_t *master_keyset, size_t master_len,
    const uint8_t *associated_data, size_t ad_len,
    uint8_t **out, size_t *out_len);

void tink_keyset_handle_free(TinkKeysetHandle *handle);

/* --------------------------------------------------------------------------
 * AEAD
 * -------------------------------------------------------------------------- */
int tink_aead_new(const TinkKeysetHandle *handle, TinkAead **aead_out);

int tink_aead_encrypt(const TinkAead *aead,
                      const uint8_t *plaintext, size_t plaintext_len,
                      const uint8_t *aad, size_t aad_len,
                      uint8_t **ciphertext_out, size_t *ciphertext_len_out);

int tink_aead_decrypt(const TinkAead *aead,
                      const uint8_t *ciphertext, size_t ciphertext_len,
                      const uint8_t *aad, size_t aad_len,
                      uint8_t **plaintext_out, size_t *plaintext_len_out);

void tink_aead_free(TinkAead *aead);

/* --------------------------------------------------------------------------
 * Deterministic AEAD
 * -------------------------------------------------------------------------- */
int tink_deterministic_aead_new(const TinkKeysetHandle *handle,
                                TinkDeterministicAead **daead_out);

int tink_deterministic_aead_encrypt(const TinkDeterministicAead *daead,
                                    const uint8_t *plaintext,
                                    size_t plaintext_len,
                                    const uint8_t *aad, size_t aad_len,
                                    uint8_t **ciphertext_out,
                                    size_t *ciphertext_len_out);

int tink_deterministic_aead_decrypt(const TinkDeterministicAead *daead,
                                    const uint8_t *ciphertext,
                                    size_t ciphertext_len,
                                    const uint8_t *aad, size_t aad_len,
                                    uint8_t **plaintext_out,
                                    size_t *plaintext_len_out);

void tink_deterministic_aead_free(TinkDeterministicAead *daead);

/* --------------------------------------------------------------------------
 * MAC
 * -------------------------------------------------------------------------- */
int tink_mac_new(const TinkKeysetHandle *handle, TinkMac **mac_out);

int tink_mac_compute(const TinkMac *mac,
                     const uint8_t *data, size_t data_len,
                     uint8_t **mac_out, size_t *mac_len_out);

int tink_mac_verify(const TinkMac *mac,
                    const uint8_t *mac_value, size_t mac_value_len,
                    const uint8_t *data, size_t data_len);

void tink_mac_free(TinkMac *mac);

/* --------------------------------------------------------------------------
 * Digital Signatures
 * -------------------------------------------------------------------------- */
int tink_signer_new(const TinkKeysetHandle *handle, TinkSigner **signer_out);

int tink_signer_sign(const TinkSigner *signer,
                     const uint8_t *data, size_t data_len,
                     uint8_t **signature_out, size_t *signature_len_out);

void tink_signer_free(TinkSigner *signer);

int tink_verifier_new(const TinkKeysetHandle *handle,
                      TinkVerifier **verifier_out);

int tink_verifier_verify(const TinkVerifier *verifier,
                         const uint8_t *signature, size_t signature_len,
                         const uint8_t *data, size_t data_len);

void tink_verifier_free(TinkVerifier *verifier);

/* --------------------------------------------------------------------------
 * Hybrid Encryption
 * -------------------------------------------------------------------------- */
int tink_hybrid_encrypt_new(const TinkKeysetHandle *handle,
                            TinkHybridEncrypt **enc_out);

int tink_hybrid_encrypt(const TinkHybridEncrypt *enc,
                        const uint8_t *plaintext, size_t plaintext_len,
                        const uint8_t *context_info, size_t context_info_len,
                        uint8_t **ciphertext_out, size_t *ciphertext_len_out);

void tink_hybrid_encrypt_free(TinkHybridEncrypt *enc);

int tink_hybrid_decrypt_new(const TinkKeysetHandle *handle,
                            TinkHybridDecrypt **dec_out);

int tink_hybrid_decrypt(const TinkHybridDecrypt *dec,
                        const uint8_t *ciphertext, size_t ciphertext_len,
                        const uint8_t *context_info, size_t context_info_len,
                        uint8_t **plaintext_out, size_t *plaintext_len_out);

void tink_hybrid_decrypt_free(TinkHybridDecrypt *dec);

/* --------------------------------------------------------------------------
 * Streaming AEAD
 *
 * Chunked streaming interface. The caller drives the stream by calling
 * write/read in a loop, then finalize/check-end.
 * -------------------------------------------------------------------------- */
int tink_streaming_aead_new(const TinkKeysetHandle *handle,
                            TinkStreamingAead **saead_out);

/* Start an encrypting stream. */
int tink_streaming_aead_encrypt_start(const TinkStreamingAead *saead,
                                      const uint8_t *aad, size_t aad_len,
                                      TinkEncryptingStream **stream_out);

/* Write plaintext chunk. Returns bytes consumed in *written_out. */
int tink_encrypting_stream_write(TinkEncryptingStream *stream,
                                 const uint8_t *data, size_t data_len,
                                 size_t *written_out);

/* Finalize encryption. Returns the complete ciphertext. */
int tink_encrypting_stream_finalize(TinkEncryptingStream *stream,
                                    uint8_t **ciphertext_out,
                                    size_t *ciphertext_len_out);

void tink_encrypting_stream_free(TinkEncryptingStream *stream);

/* Start a decrypting stream from ciphertext buffer. */
int tink_streaming_aead_decrypt_start(const TinkStreamingAead *saead,
                                      const uint8_t *ciphertext,
                                      size_t ciphertext_len,
                                      const uint8_t *aad, size_t aad_len,
                                      TinkDecryptingStream **stream_out);

/* Read decrypted plaintext chunk. Returns bytes read in *read_out.
 * Returns 0 with *read_out == 0 at end of stream. */
int tink_decrypting_stream_read(TinkDecryptingStream *stream,
                                uint8_t *buf, size_t buf_len,
                                size_t *read_out);

void tink_decrypting_stream_free(TinkDecryptingStream *stream);

void tink_streaming_aead_free(TinkStreamingAead *saead);

/* --------------------------------------------------------------------------
 * JWT MAC
 * -------------------------------------------------------------------------- */
int tink_jwt_mac_new(const TinkKeysetHandle *handle, TinkJwtMac **jwt_mac_out);

/* raw_jwt_json: JSON object with claims (e.g. {"iss":"me","exp":1234567890}).
 * Returns compact JWT string. */
int tink_jwt_mac_compute_and_encode(const TinkJwtMac *jwt_mac,
                                    const char *raw_jwt_json,
                                    char **compact_out);

/* Verify and decode. validator_json configures validation rules.
 * Returns verified claims as JSON on success. */
int tink_jwt_mac_verify_and_decode(const TinkJwtMac *jwt_mac,
                                   const char *compact,
                                   const char *validator_json,
                                   char **claims_json_out);

void tink_jwt_mac_free(TinkJwtMac *jwt_mac);

/* --------------------------------------------------------------------------
 * JWT Public Key Sign / Verify
 * -------------------------------------------------------------------------- */
int tink_jwt_signer_new(const TinkKeysetHandle *handle,
                        TinkJwtSigner **signer_out);

int tink_jwt_signer_sign_and_encode(const TinkJwtSigner *signer,
                                    const char *raw_jwt_json,
                                    char **compact_out);

void tink_jwt_signer_free(TinkJwtSigner *signer);

int tink_jwt_verifier_new(const TinkKeysetHandle *handle,
                          TinkJwtVerifier **verifier_out);

int tink_jwt_verifier_verify_and_decode(const TinkJwtVerifier *verifier,
                                        const char *compact,
                                        const char *validator_json,
                                        char **claims_json_out);

void tink_jwt_verifier_free(TinkJwtVerifier *verifier);

/* --------------------------------------------------------------------------
 * PRF Set
 * -------------------------------------------------------------------------- */
int tink_prf_set_new(const TinkKeysetHandle *handle,
                     TinkPrfSet **prf_set_out);

int tink_prf_set_primary_id(const TinkPrfSet *prf_set, uint32_t *id_out);

int tink_prf_set_compute_primary(const TinkPrfSet *prf_set,
                                 const uint8_t *input, size_t input_len,
                                 size_t output_len,
                                 uint8_t **output_out,
                                 size_t *output_len_out);

/* Get all key IDs from a PrfSet. Caller must free key_ids_out with
 * tink_free_bytes(key_ids_out, num_keys * sizeof(uint32_t)). */
int tink_prf_set_key_ids(const TinkPrfSet *prf_set,
                         uint32_t **key_ids_out, size_t *num_keys_out);

/* Compute PRF output for a specific key ID. */
int tink_prf_set_compute(const TinkPrfSet *prf_set,
                         uint32_t key_id,
                         const uint8_t *input, size_t input_len,
                         size_t output_len,
                         uint8_t **output_out, size_t *output_len_out);

void tink_prf_set_free(TinkPrfSet *prf_set);

/* --------------------------------------------------------------------------
 * Keyset Derivation
 * -------------------------------------------------------------------------- */
int tink_keyset_deriver_new(const TinkKeysetHandle *handle,
                            TinkKeysetDeriver **deriver_out);

int tink_keyset_deriver_derive(const TinkKeysetDeriver *deriver,
                               const uint8_t *salt, size_t salt_len,
                               TinkKeysetHandle **derived_handle_out);

void tink_keyset_deriver_free(TinkKeysetDeriver *deriver);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif  /* TINK_FFI_H_ */
