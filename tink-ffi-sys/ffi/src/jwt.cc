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
#include <vector>

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

using crypto::tink::JwtMac;
using crypto::tink::JwtPublicKeySign;
using crypto::tink::JwtPublicKeyVerify;
using crypto::tink::JwtValidator;
using crypto::tink::JwtValidatorBuilder;
using crypto::tink::RawJwt;
using crypto::tink::RawJwtBuilder;
using crypto::tink::VerifiedJwt;
using google::protobuf::Value;

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
  google::protobuf::Struct proto;
  absl::Status parse_status =
      google::protobuf::util::JsonStringToMessage(json, &proto);
  if (!parse_status.ok()) {
    return absl::InvalidArgumentError(
        std::string("failed to parse JWT JSON: ") +
        std::string(parse_status.message()));
  }

  RawJwtBuilder builder;
  auto& fields = proto.fields();

  // Registered string claims.
  auto it = fields.find("iss");
  if (it != fields.end()) {
    if (it->second.kind_case() != Value::kStringValue) {
      return absl::InvalidArgumentError("iss must be a string");
    }
    builder.SetIssuer(it->second.string_value());
  }

  it = fields.find("sub");
  if (it != fields.end()) {
    if (it->second.kind_case() != Value::kStringValue) {
      return absl::InvalidArgumentError("sub must be a string");
    }
    builder.SetSubject(it->second.string_value());
  }

  it = fields.find("jti");
  if (it != fields.end()) {
    if (it->second.kind_case() != Value::kStringValue) {
      return absl::InvalidArgumentError("jti must be a string");
    }
    builder.SetJwtId(it->second.string_value());
  }

  // Audience: can be a string or an array of strings.
  it = fields.find("aud");
  if (it != fields.end()) {
    if (it->second.kind_case() == Value::kStringValue) {
      builder.SetAudience(it->second.string_value());
    } else if (it->second.kind_case() == Value::kListValue) {
      std::vector<std::string> audiences;
      for (const auto& v : it->second.list_value().values()) {
        if (v.kind_case() != Value::kStringValue) {
          return absl::InvalidArgumentError("aud array must contain strings");
        }
        audiences.push_back(v.string_value());
      }
      builder.SetAudiences(std::move(audiences));
    } else {
      return absl::InvalidArgumentError("aud must be a string or array");
    }
  }

  // Timestamp claims.
  it = fields.find("exp");
  if (it != fields.end()) {
    if (it->second.kind_case() != Value::kNumberValue) {
      return absl::InvalidArgumentError("exp must be a number");
    }
    builder.SetExpiration(
        absl::FromUnixSeconds(static_cast<int64_t>(it->second.number_value())));
  } else {
    builder.WithoutExpiration();
  }

  it = fields.find("nbf");
  if (it != fields.end()) {
    if (it->second.kind_case() != Value::kNumberValue) {
      return absl::InvalidArgumentError("nbf must be a number");
    }
    builder.SetNotBefore(
        absl::FromUnixSeconds(static_cast<int64_t>(it->second.number_value())));
  }

  it = fields.find("iat");
  if (it != fields.end()) {
    if (it->second.kind_case() != Value::kNumberValue) {
      return absl::InvalidArgumentError("iat must be a number");
    }
    builder.SetIssuedAt(
        absl::FromUnixSeconds(static_cast<int64_t>(it->second.number_value())));
  }

  // Custom claims.
  for (const auto& [name, value] : fields) {
    if (name == "iss" || name == "sub" || name == "aud" ||
        name == "exp" || name == "nbf" || name == "iat" || name == "jti") {
      continue;
    }
    switch (value.kind_case()) {
      case Value::kNullValue:
        builder.AddNullClaim(name);
        break;
      case Value::kBoolValue:
        builder.AddBooleanClaim(name, value.bool_value());
        break;
      case Value::kStringValue:
        builder.AddStringClaim(name, value.string_value());
        break;
      case Value::kNumberValue:
        builder.AddNumberClaim(name, value.number_value());
        break;
      case Value::kStructValue: {
        std::string json_obj;
        google::protobuf::util::MessageToJsonString(
            value.struct_value(), &json_obj);
        builder.AddJsonObjectClaim(name, json_obj);
        break;
      }
      case Value::kListValue: {
        std::string json_arr;
        google::protobuf::util::MessageToJsonString(
            value.list_value(), &json_arr);
        builder.AddJsonArrayClaim(name, json_arr);
        break;
      }
      default:
        return absl::InvalidArgumentError(
            std::string("unsupported claim type for: ") + name);
    }
  }

  return builder.Build();
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
