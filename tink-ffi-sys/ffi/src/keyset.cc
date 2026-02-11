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

#include "common.h"
#include "keyset_handle_internal.h"

#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "google/protobuf/util/json_util.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/json/json_keyset_reader.h"
#include "tink/json/json_keyset_writer.h"
#include "tink/binary_keyset_reader.h"
#include "tink/binary_keyset_writer.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/config/global_registry.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/keyset_handle.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/daead/deterministic_aead_key_templates.h"
#include "tink/mac/mac_key_templates.h"
#include "tink/signature/signature_key_templates.h"
#include "tink/hybrid/hybrid_key_templates.h"
#include "tink/streamingaead/streaming_aead_key_templates.h"
#include "tink/prf/prf_key_templates.h"
#include "tink/jwt/jwt_key_templates.h"
#include "proto/tink.pb.h"

using crypto::tink::KeysetHandle;
using crypto::tink::CleartextKeysetHandle;
using crypto::tink::JsonKeysetReader;
using crypto::tink::JsonKeysetWriter;
using crypto::tink::BinaryKeysetReader;
using crypto::tink::BinaryKeysetWriter;
using google::crypto::tink::KeyTemplate;

// Returns a pointer to a heap-allocated copy of the given string (including
// NUL terminator).  The caller takes ownership.
static char* strdup_new(const std::string& s) {
  char* out = new char[s.size() + 1];
  std::memcpy(out, s.data(), s.size());
  out[s.size()] = '\0';
  return out;
}

// Map of template name -> KeyTemplate reference.
static const KeyTemplate* find_key_template(const char* name) {
  using crypto::tink::AeadKeyTemplates;
  using crypto::tink::DeterministicAeadKeyTemplates;
  using crypto::tink::MacKeyTemplates;
  using crypto::tink::SignatureKeyTemplates;
  using crypto::tink::HybridKeyTemplates;
  using crypto::tink::StreamingAeadKeyTemplates;
  using crypto::tink::PrfKeyTemplates;

  static const auto* templates =
      new std::unordered_map<std::string, const KeyTemplate*>{
          // AEAD
          {"AES128_EAX", &AeadKeyTemplates::Aes128Eax()},
          {"AES256_EAX", &AeadKeyTemplates::Aes256Eax()},
          {"AES128_GCM", &AeadKeyTemplates::Aes128Gcm()},
          {"AES128_GCM_NO_PREFIX", &AeadKeyTemplates::Aes128GcmNoPrefix()},
          {"AES256_GCM", &AeadKeyTemplates::Aes256Gcm()},
          {"AES256_GCM_NO_PREFIX", &AeadKeyTemplates::Aes256GcmNoPrefix()},
          {"AES128_GCM_SIV", &AeadKeyTemplates::Aes128GcmSiv()},
          {"AES256_GCM_SIV", &AeadKeyTemplates::Aes256GcmSiv()},
          {"AES128_CTR_HMAC_SHA256",
           &AeadKeyTemplates::Aes128CtrHmacSha256()},
          {"AES256_CTR_HMAC_SHA256",
           &AeadKeyTemplates::Aes256CtrHmacSha256()},
          {"XCHACHA20_POLY1305", &AeadKeyTemplates::XChaCha20Poly1305()},

          // Deterministic AEAD
          {"AES256_SIV", &DeterministicAeadKeyTemplates::Aes256Siv()},

          // MAC
          {"HMAC_SHA256_128BITTAG",
           &MacKeyTemplates::HmacSha256HalfSizeTag()},
          {"HMAC_SHA256", &MacKeyTemplates::HmacSha256()},
          {"HMAC_SHA512_256BITTAG",
           &MacKeyTemplates::HmacSha512HalfSizeTag()},
          {"HMAC_SHA512", &MacKeyTemplates::HmacSha512()},
          {"AES_CMAC", &MacKeyTemplates::AesCmac()},

          // Digital Signatures
          {"ECDSA_P256", &SignatureKeyTemplates::EcdsaP256()},
          {"ECDSA_P384_SHA384", &SignatureKeyTemplates::EcdsaP384Sha384()},
          {"ECDSA_P384_SHA512", &SignatureKeyTemplates::EcdsaP384Sha512()},
          {"ECDSA_P521", &SignatureKeyTemplates::EcdsaP521()},
          {"ECDSA_P256_RAW", &SignatureKeyTemplates::EcdsaP256Raw()},
          {"ECDSA_P256_IEEE", &SignatureKeyTemplates::EcdsaP256Ieee()},
          {"ECDSA_P256_RAW_DER", &SignatureKeyTemplates::EcdsaP256RawDer()},
          {"ECDSA_P384_IEEE", &SignatureKeyTemplates::EcdsaP384Ieee()},
          {"ECDSA_P521_IEEE", &SignatureKeyTemplates::EcdsaP521Ieee()},
          {"RSA_SSA_PKCS1_3072_SHA256_F4",
           &SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4()},
          {"RSA_SSA_PKCS1_4096_SHA512_F4",
           &SignatureKeyTemplates::RsaSsaPkcs14096Sha512F4()},
          {"RSA_SSA_PSS_3072_SHA256_SHA256_F4",
           &SignatureKeyTemplates::RsaSsaPss3072Sha256Sha256F4()},
          {"RSA_SSA_PSS_4096_SHA512_SHA512_F4",
           &SignatureKeyTemplates::RsaSsaPss4096Sha512Sha512F4()},
          {"RSA_SSA_PSS_4096_SHA384_SHA384_F4",
           &SignatureKeyTemplates::RsaSsaPss4096Sha384Sha384F4()},
          {"ED25519", &SignatureKeyTemplates::Ed25519()},
          {"ED25519_RAW", &SignatureKeyTemplates::Ed25519WithRawOutput()},

          // Hybrid Encryption
          {"ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
           &HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128Gcm()},
          {"ECIES_P256_HKDF_HMAC_SHA512_AES128_GCM",
           &HybridKeyTemplates::EciesP256HkdfHmacSha512Aes128Gcm()},
          {"ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM_COMPRESSED_NO_PREFIX",
           &HybridKeyTemplates::
               EciesP256HkdfHmacSha256Aes128GcmCompressedWithoutPrefix()},
          {"ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256",
           &HybridKeyTemplates::
               EciesP256HkdfHmacSha256Aes128CtrHmacSha256()},
          {"ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM",
           &HybridKeyTemplates::
               EciesP256CompressedHkdfHmacSha256Aes128Gcm()},
          {"ECIES_X25519_HKDF_HMAC_SHA256_AES128_GCM",
           &HybridKeyTemplates::EciesX25519HkdfHmacSha256Aes128Gcm()},
          {"ECIES_X25519_HKDF_HMAC_SHA256_AES256_GCM",
           &HybridKeyTemplates::EciesX25519HkdfHmacSha256Aes256Gcm()},
          {"ECIES_X25519_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256",
           &HybridKeyTemplates::
               EciesX25519HkdfHmacSha256Aes128CtrHmacSha256()},
          {"ECIES_X25519_HKDF_HMAC_SHA256_XCHACHA20_POLY1305",
           &HybridKeyTemplates::
               EciesX25519HkdfHmacSha256XChaCha20Poly1305()},
          {"ECIES_X25519_HKDF_HMAC_SHA256_DETERMINISTIC_AES_SIV",
           &HybridKeyTemplates::
               EciesX25519HkdfHmacSha256DeterministicAesSiv()},
          {"HPKE_X25519_HKDF_SHA256_AES128_GCM",
           &HybridKeyTemplates::HpkeX25519HkdfSha256Aes128Gcm()},
          {"HPKE_X25519_HKDF_SHA256_AES128_GCM_RAW",
           &HybridKeyTemplates::HpkeX25519HkdfSha256Aes128GcmRaw()},
          {"HPKE_X25519_HKDF_SHA256_AES256_GCM",
           &HybridKeyTemplates::HpkeX25519HkdfSha256Aes256Gcm()},
          {"HPKE_X25519_HKDF_SHA256_AES256_GCM_RAW",
           &HybridKeyTemplates::HpkeX25519HkdfSha256Aes256GcmRaw()},
          {"HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305",
           &HybridKeyTemplates::HpkeX25519HkdfSha256ChaCha20Poly1305()},
          {"HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305_RAW",
           &HybridKeyTemplates::HpkeX25519HkdfSha256ChaCha20Poly1305Raw()},
          {"HPKE_P256_HKDF_SHA256_AES128_GCM",
           &HybridKeyTemplates::HpkeP256HkdfSha256Aes128Gcm()},
          {"HPKE_P256_HKDF_SHA256_AES128_GCM_RAW",
           &HybridKeyTemplates::HpkeP256HkdfSha256Aes128GcmRaw()},

          // Streaming AEAD
          {"AES128_GCM_HKDF_4KB",
           &StreamingAeadKeyTemplates::Aes128GcmHkdf4KB()},
          {"AES256_GCM_HKDF_4KB",
           &StreamingAeadKeyTemplates::Aes256GcmHkdf4KB()},
          {"AES256_GCM_HKDF_1MB",
           &StreamingAeadKeyTemplates::Aes256GcmHkdf1MB()},
          {"AES128_CTR_HMAC_SHA256_4KB",
           &StreamingAeadKeyTemplates::Aes128CtrHmacSha256Segment4KB()},
          {"AES128_CTR_HMAC_SHA256_1MB",
           &StreamingAeadKeyTemplates::Aes128CtrHmacSha256Segment1MB()},
          {"AES256_CTR_HMAC_SHA256_4KB",
           &StreamingAeadKeyTemplates::Aes256CtrHmacSha256Segment4KB()},
          {"AES256_CTR_HMAC_SHA256_1MB",
           &StreamingAeadKeyTemplates::Aes256CtrHmacSha256Segment1MB()},

          // PRF
          {"HKDF_SHA256", &PrfKeyTemplates::HkdfSha256()},
          {"HMAC_SHA256_PRF", &PrfKeyTemplates::HmacSha256()},
          {"HMAC_SHA512_PRF", &PrfKeyTemplates::HmacSha512()},
          {"AES_CMAC_PRF", &PrfKeyTemplates::AesCmac()},

          // JWT MAC
          {"JWT_HS256", &crypto::tink::JwtHs256Template()},
          {"JWT_HS256_RAW", &crypto::tink::RawJwtHs256Template()},
          {"JWT_HS384", &crypto::tink::JwtHs384Template()},
          {"JWT_HS384_RAW", &crypto::tink::RawJwtHs384Template()},
          {"JWT_HS512", &crypto::tink::JwtHs512Template()},
          {"JWT_HS512_RAW", &crypto::tink::RawJwtHs512Template()},

          // JWT Signature
          {"JWT_ES256", &crypto::tink::JwtEs256Template()},
          {"JWT_ES256_RAW", &crypto::tink::RawJwtEs256Template()},
          {"JWT_ES384", &crypto::tink::JwtEs384Template()},
          {"JWT_ES384_RAW", &crypto::tink::RawJwtEs384Template()},
          {"JWT_ES512", &crypto::tink::JwtEs512Template()},
          {"JWT_ES512_RAW", &crypto::tink::RawJwtEs512Template()},
          {"JWT_RS256_2048_F4", &crypto::tink::JwtRs256_2048_F4_Template()},
          {"JWT_RS256_2048_F4_RAW",
           &crypto::tink::RawJwtRs256_2048_F4_Template()},
          {"JWT_RS256_3072_F4", &crypto::tink::JwtRs256_3072_F4_Template()},
          {"JWT_RS256_3072_F4_RAW",
           &crypto::tink::RawJwtRs256_3072_F4_Template()},
          {"JWT_RS384_3072_F4", &crypto::tink::JwtRs384_3072_F4_Template()},
          {"JWT_RS384_3072_F4_RAW",
           &crypto::tink::RawJwtRs384_3072_F4_Template()},
          {"JWT_RS512_4096_F4", &crypto::tink::JwtRs512_4096_F4_Template()},
          {"JWT_RS512_4096_F4_RAW",
           &crypto::tink::RawJwtRs512_4096_F4_Template()},
          {"JWT_PS256_2048_F4", &crypto::tink::JwtPs256_2048_F4_Template()},
          {"JWT_PS256_2048_F4_RAW",
           &crypto::tink::RawJwtPs256_2048_F4_Template()},
          {"JWT_PS256_3072_F4", &crypto::tink::JwtPs256_3072_F4_Template()},
          {"JWT_PS256_3072_F4_RAW",
           &crypto::tink::RawJwtPs256_3072_F4_Template()},
          {"JWT_PS384_3072_F4", &crypto::tink::JwtPs384_3072_F4_Template()},
          {"JWT_PS384_3072_F4_RAW",
           &crypto::tink::RawJwtPs384_3072_F4_Template()},
          {"JWT_PS512_4096_F4", &crypto::tink::JwtPs512_4096_F4_Template()},
          {"JWT_PS512_4096_F4_RAW",
           &crypto::tink::RawJwtPs512_4096_F4_Template()},
      };

  auto it = templates->find(name);
  if (it == templates->end()) return nullptr;
  return it->second;
}

extern "C" {

int tink_keyset_handle_generate_new(const char* template_name,
                                    TinkKeysetHandle** handle_out) {
  const KeyTemplate* tmpl = find_key_template(template_name);
  if (tmpl == nullptr) {
    set_last_error(std::string("unknown key template: ") + template_name);
    return 1;
  }

  auto result = KeysetHandle::GenerateNew(
      *tmpl, crypto::tink::KeyGenConfigGlobalRegistry());
  if (!result.ok()) {
    set_last_error(result.status());
    return 1;
  }

  *handle_out = new TinkKeysetHandle{std::move(result.value())};
  return 0;
}

int tink_keyset_handle_to_json(const TinkKeysetHandle* handle,
                               char** json_out) {
  auto oss = std::make_unique<std::ostringstream>();
  std::ostringstream* oss_ptr = oss.get();
  auto writer_or = JsonKeysetWriter::New(std::move(oss));
  if (!writer_or.ok()) {
    set_last_error(writer_or.status());
    return 1;
  }

  absl::Status status =
      CleartextKeysetHandle::Write(writer_or.value().get(), *handle->handle);
  if (!status.ok()) {
    set_last_error(status);
    return 1;
  }

  std::string json = oss_ptr->str();
  *json_out = strdup_new(json);
  return 0;
}

int tink_keyset_handle_from_json(const char* json,
                                 TinkKeysetHandle** handle_out) {
  auto reader_or = JsonKeysetReader::New(absl::string_view(json));
  if (!reader_or.ok()) {
    set_last_error(reader_or.status());
    return 1;
  }

  auto handle_or = CleartextKeysetHandle::Read(std::move(reader_or.value()));
  if (!handle_or.ok()) {
    set_last_error(handle_or.status());
    return 1;
  }

  *handle_out = new TinkKeysetHandle{std::move(handle_or.value())};
  return 0;
}

int tink_keyset_handle_to_binary(const TinkKeysetHandle* handle,
                                 uint8_t** data_out, size_t* data_len_out) {
  auto oss = std::make_unique<std::ostringstream>();
  std::ostringstream* oss_ptr = oss.get();
  auto writer_or = BinaryKeysetWriter::New(std::move(oss));
  if (!writer_or.ok()) {
    set_last_error(writer_or.status());
    return 1;
  }

  absl::Status status =
      CleartextKeysetHandle::Write(writer_or.value().get(), *handle->handle);
  if (!status.ok()) {
    set_last_error(status);
    return 1;
  }

  std::string binary = oss_ptr->str();
  *data_len_out = binary.size();
  *data_out = new uint8_t[binary.size()];
  std::memcpy(*data_out, binary.data(), binary.size());
  return 0;
}

int tink_keyset_handle_from_binary(const uint8_t* data, size_t data_len,
                                   TinkKeysetHandle** handle_out) {
  auto reader_or = BinaryKeysetReader::New(
      absl::string_view(reinterpret_cast<const char*>(data), data_len));
  if (!reader_or.ok()) {
    set_last_error(reader_or.status());
    return 1;
  }

  auto handle_or = CleartextKeysetHandle::Read(std::move(reader_or.value()));
  if (!handle_or.ok()) {
    set_last_error(handle_or.status());
    return 1;
  }

  *handle_out = new TinkKeysetHandle{std::move(handle_or.value())};
  return 0;
}

int tink_keyset_handle_public(const TinkKeysetHandle* handle,
                              TinkKeysetHandle** public_out) {
  auto result = handle->handle->GetPublicKeysetHandle(
      crypto::tink::KeyGenConfigGlobalRegistry());
  if (!result.ok()) {
    set_last_error(result.status());
    return 1;
  }

  *public_out = new TinkKeysetHandle{std::move(result.value())};
  return 0;
}

int tink_keyset_handle_info(const TinkKeysetHandle* handle, char** info_out) {
  google::crypto::tink::KeysetInfo info = handle->handle->GetKeysetInfo();
  std::string json;
  google::protobuf::util::JsonPrintOptions opts;
  opts.add_whitespace = true;
  absl::Status status =
      google::protobuf::util::MessageToJsonString(info, &json, opts);
  if (!status.ok()) {
    set_last_error(std::string("failed to serialize KeysetInfo to JSON: ") +
                   std::string(status.message()));
    return 1;
  }

  *info_out = strdup_new(json);
  return 0;
}

int tink_key_template_serialize(const char* template_name,
                                uint8_t** bytes_out, size_t* len_out) {
  const KeyTemplate* tmpl = find_key_template(template_name);
  if (tmpl == nullptr) {
    set_last_error(std::string("unknown key template: ") + template_name);
    return 1;
  }

  std::string serialized;
  if (!tmpl->SerializeToString(&serialized)) {
    set_last_error("failed to serialize key template");
    return 1;
  }

  *len_out = serialized.size();
  *bytes_out = new uint8_t[serialized.size()];
  std::memcpy(*bytes_out, serialized.data(), serialized.size());
  return 0;
}

int tink_keyset_handle_generate_from_template_bytes(
    const uint8_t* template_bytes, size_t template_len,
    TinkKeysetHandle** handle_out) {
  KeyTemplate tmpl;
  if (!tmpl.ParseFromArray(template_bytes, static_cast<int>(template_len))) {
    set_last_error("failed to parse key template from bytes");
    return 1;
  }

  auto result = KeysetHandle::GenerateNew(
      tmpl, crypto::tink::KeyGenConfigGlobalRegistry());
  if (!result.ok()) {
    set_last_error(result.status());
    return 1;
  }

  *handle_out = new TinkKeysetHandle{std::move(result.value())};
  return 0;
}

int tink_keyset_handle_read_encrypted(
    const uint8_t* encrypted, size_t encrypted_len,
    const uint8_t* master_keyset, size_t master_len,
    const uint8_t* associated_data, size_t ad_len,
    TinkKeysetHandle** handle_out) {
  // Load the master keyset
  auto master_reader_or = BinaryKeysetReader::New(
      absl::string_view(reinterpret_cast<const char*>(master_keyset), master_len));
  if (!master_reader_or.ok()) {
    set_last_error(master_reader_or.status());
    return 1;
  }
  auto master_handle_or =
      CleartextKeysetHandle::Read(std::move(master_reader_or.value()));
  if (!master_handle_or.ok()) {
    set_last_error(master_handle_or.status());
    return 1;
  }

  // Get AEAD from master keyset
  auto aead_or = master_handle_or.value()->GetPrimitive<crypto::tink::Aead>(
      crypto::tink::ConfigGlobalRegistry());
  if (!aead_or.ok()) {
    set_last_error(aead_or.status());
    return 1;
  }

  // Read the encrypted keyset
  auto reader_or = BinaryKeysetReader::New(
      absl::string_view(reinterpret_cast<const char*>(encrypted), encrypted_len));
  if (!reader_or.ok()) {
    set_last_error(reader_or.status());
    return 1;
  }

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle_or;
  if (associated_data != nullptr && ad_len > 0) {
    handle_or = KeysetHandle::ReadWithAssociatedData(
        std::move(reader_or.value()), *aead_or.value(),
        absl::string_view(reinterpret_cast<const char*>(associated_data), ad_len));
  } else {
    handle_or = KeysetHandle::Read(
        std::move(reader_or.value()), *aead_or.value());
  }
  if (!handle_or.ok()) {
    set_last_error(handle_or.status());
    return 1;
  }

  *handle_out = new TinkKeysetHandle{std::move(handle_or.value())};
  return 0;
}

int tink_keyset_handle_write_encrypted(
    const TinkKeysetHandle* handle,
    const uint8_t* master_keyset, size_t master_len,
    const uint8_t* associated_data, size_t ad_len,
    uint8_t** out, size_t* out_len) {
  // Load the master keyset
  auto master_reader_or = BinaryKeysetReader::New(
      absl::string_view(reinterpret_cast<const char*>(master_keyset), master_len));
  if (!master_reader_or.ok()) {
    set_last_error(master_reader_or.status());
    return 1;
  }
  auto master_handle_or =
      CleartextKeysetHandle::Read(std::move(master_reader_or.value()));
  if (!master_handle_or.ok()) {
    set_last_error(master_handle_or.status());
    return 1;
  }

  // Get AEAD from master keyset
  auto aead_or = master_handle_or.value()->GetPrimitive<crypto::tink::Aead>(
      crypto::tink::ConfigGlobalRegistry());
  if (!aead_or.ok()) {
    set_last_error(aead_or.status());
    return 1;
  }

  // Write encrypted keyset
  auto oss = std::make_unique<std::ostringstream>();
  std::ostringstream* oss_ptr = oss.get();
  auto writer_or = BinaryKeysetWriter::New(std::move(oss));
  if (!writer_or.ok()) {
    set_last_error(writer_or.status());
    return 1;
  }

  absl::Status status;
  if (associated_data != nullptr && ad_len > 0) {
    status = handle->handle->WriteWithAssociatedData(
        writer_or.value().get(), *aead_or.value(),
        absl::string_view(reinterpret_cast<const char*>(associated_data), ad_len));
  } else {
    status = handle->handle->Write(writer_or.value().get(), *aead_or.value());
  }
  if (!status.ok()) {
    set_last_error(status);
    return 1;
  }

  std::string binary = oss_ptr->str();
  *out_len = binary.size();
  *out = new uint8_t[binary.size()];
  std::memcpy(*out, binary.data(), binary.size());
  return 0;
}

void tink_keyset_handle_free(TinkKeysetHandle* handle) { delete handle; }

}  // extern "C"
