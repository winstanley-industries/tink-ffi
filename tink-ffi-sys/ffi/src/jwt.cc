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
#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "absl/types/optional.h"
#include "google/protobuf/struct.pb.h"
#include "google/protobuf/util/json_util.h"
#include "tink/config/global_registry.h"
#include "tink/jwt/jwt_mac.h"
#include "tink/jwt/jwt_public_key_sign.h"
#include "tink/jwt/jwt_public_key_verify.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/jwt/verified_jwt.h"
#include "tink/jwt/internal/jwt_format.h"

using crypto::tink::JwtMac;
using crypto::tink::JwtPublicKeySign;
using crypto::tink::JwtPublicKeyVerify;
using crypto::tink::JwtValidator;
using crypto::tink::JwtValidatorBuilder;
using crypto::tink::RawJwt;
using crypto::tink::VerifiedJwt;
using crypto::tink::jwt_internal::RawJwtParser;

struct TinkJwtMac {
  std::unique_ptr<JwtMac> jwt_mac;
};

struct TinkJwtSigner {
  std::unique_ptr<JwtPublicKeySign> signer;
};

struct TinkJwtVerifier {
  std::unique_ptr<JwtPublicKeyVerify> verifier;
};

static char* strdup_new(const std::string& s) {
  char* out = new char[s.size() + 1];
  std::memcpy(out, s.data(), s.size());
  out[s.size()] = '\0';
  return out;
}

// Build a RawJwt from a JSON string like {"iss":"me","sub":"you","exp":123}.
static absl::StatusOr<RawJwt> raw_jwt_from_json(const char* json) {
  return RawJwtParser::FromJson(absl::nullopt, absl::string_view(json));
}

// Build a JwtValidator from a JSON config string.
// Supported fields:
//   "issuer": string - expected issuer
//   "audience": string - expected audience
//   "clock_skew_seconds": number - clock skew in seconds
//   "fixed_now_seconds": number - fixed "now" as unix timestamp
//   "allow_missing_expiration": bool
//   "ignore_type_header": bool
//   "ignore_issuer": bool
//   "ignore_audiences": bool
//   "expect_issued_in_the_past": bool
static absl::StatusOr<JwtValidator> validator_from_json(const char* json) {
  google::protobuf::Struct proto;
  absl::Status parse_status =
      google::protobuf::util::JsonStringToMessage(json, &proto);
  if (!parse_status.ok()) {
    return absl::InvalidArgumentError(
        std::string("failed to parse validator JSON: ") +
        std::string(parse_status.message()));
  }

  JwtValidatorBuilder builder;

  auto& fields = proto.fields();

  auto it = fields.find("issuer");
  if (it != fields.end()) {
    builder.ExpectIssuer(it->second.string_value());
  }

  it = fields.find("audience");
  if (it != fields.end()) {
    builder.ExpectAudience(it->second.string_value());
  }

  it = fields.find("clock_skew_seconds");
  if (it != fields.end()) {
    builder.SetClockSkew(
        absl::Seconds(static_cast<int64_t>(it->second.number_value())));
  }

  it = fields.find("fixed_now_seconds");
  if (it != fields.end()) {
    builder.SetFixedNow(
        absl::FromUnixSeconds(static_cast<int64_t>(it->second.number_value())));
  }

  it = fields.find("allow_missing_expiration");
  if (it != fields.end() && it->second.bool_value()) {
    builder.AllowMissingExpiration();
  }

  it = fields.find("ignore_type_header");
  if (it != fields.end() && it->second.bool_value()) {
    builder.IgnoreTypeHeader();
  }

  it = fields.find("ignore_issuer");
  if (it != fields.end() && it->second.bool_value()) {
    builder.IgnoreIssuer();
  }

  it = fields.find("ignore_audiences");
  if (it != fields.end() && it->second.bool_value()) {
    builder.IgnoreAudiences();
  }

  it = fields.find("expect_issued_in_the_past");
  if (it != fields.end() && it->second.bool_value()) {
    builder.ExpectIssuedInThePast();
  }

  return builder.Build();
}

extern "C" {

// --- JWT MAC ---

int tink_jwt_mac_new(const TinkKeysetHandle* handle,
                     TinkJwtMac** jwt_mac_out) {
  auto result =
      handle->handle->GetPrimitive<JwtMac>(crypto::tink::ConfigGlobalRegistry());
  if (!result.ok()) {
    set_last_error(result.status());
    return 1;
  }
  *jwt_mac_out = new TinkJwtMac{std::move(result.value())};
  return 0;
}

int tink_jwt_mac_compute_and_encode(const TinkJwtMac* jwt_mac,
                                    const char* raw_jwt_json,
                                    char** compact_out) {
  auto raw_jwt = raw_jwt_from_json(raw_jwt_json);
  if (!raw_jwt.ok()) {
    set_last_error(raw_jwt.status());
    return 1;
  }

  auto result = jwt_mac->jwt_mac->ComputeMacAndEncode(raw_jwt.value());
  if (!result.ok()) {
    set_last_error(result.status());
    return 1;
  }

  *compact_out = strdup_new(result.value());
  return 0;
}

int tink_jwt_mac_verify_and_decode(const TinkJwtMac* jwt_mac,
                                   const char* compact,
                                   const char* validator_json,
                                   char** claims_json_out) {
  auto validator = validator_from_json(validator_json);
  if (!validator.ok()) {
    set_last_error(validator.status());
    return 1;
  }

  auto result = jwt_mac->jwt_mac->VerifyMacAndDecode(
      absl::string_view(compact), validator.value());
  if (!result.ok()) {
    set_last_error(result.status());
    return 1;
  }

  auto payload = result.value().GetJsonPayload();
  if (!payload.ok()) {
    set_last_error(payload.status());
    return 1;
  }

  *claims_json_out = strdup_new(payload.value());
  return 0;
}

void tink_jwt_mac_free(TinkJwtMac* jwt_mac) { delete jwt_mac; }

// --- JWT Signer ---

int tink_jwt_signer_new(const TinkKeysetHandle* handle,
                        TinkJwtSigner** signer_out) {
  auto result = handle->handle->GetPrimitive<JwtPublicKeySign>(
      crypto::tink::ConfigGlobalRegistry());
  if (!result.ok()) {
    set_last_error(result.status());
    return 1;
  }
  *signer_out = new TinkJwtSigner{std::move(result.value())};
  return 0;
}

int tink_jwt_signer_sign_and_encode(const TinkJwtSigner* signer,
                                    const char* raw_jwt_json,
                                    char** compact_out) {
  auto raw_jwt = raw_jwt_from_json(raw_jwt_json);
  if (!raw_jwt.ok()) {
    set_last_error(raw_jwt.status());
    return 1;
  }

  auto result = signer->signer->SignAndEncode(raw_jwt.value());
  if (!result.ok()) {
    set_last_error(result.status());
    return 1;
  }

  *compact_out = strdup_new(result.value());
  return 0;
}

void tink_jwt_signer_free(TinkJwtSigner* signer) { delete signer; }

// --- JWT Verifier ---

int tink_jwt_verifier_new(const TinkKeysetHandle* handle,
                          TinkJwtVerifier** verifier_out) {
  auto result = handle->handle->GetPrimitive<JwtPublicKeyVerify>(
      crypto::tink::ConfigGlobalRegistry());
  if (!result.ok()) {
    set_last_error(result.status());
    return 1;
  }
  *verifier_out = new TinkJwtVerifier{std::move(result.value())};
  return 0;
}

int tink_jwt_verifier_verify_and_decode(const TinkJwtVerifier* verifier,
                                        const char* compact,
                                        const char* validator_json,
                                        char** claims_json_out) {
  auto validator = validator_from_json(validator_json);
  if (!validator.ok()) {
    set_last_error(validator.status());
    return 1;
  }

  auto result = verifier->verifier->VerifyAndDecode(
      absl::string_view(compact), validator.value());
  if (!result.ok()) {
    set_last_error(result.status());
    return 1;
  }

  auto payload = result.value().GetJsonPayload();
  if (!payload.ok()) {
    set_last_error(payload.status());
    return 1;
  }

  *claims_json_out = strdup_new(payload.value());
  return 0;
}

void tink_jwt_verifier_free(TinkJwtVerifier* verifier) { delete verifier; }

}  // extern "C"
