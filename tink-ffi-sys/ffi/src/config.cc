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

#include "tink/config/tink_config.h"
#include "tink/hybrid/hpke_config.h"
#include "tink/jwt/jwt_mac_config.h"
#include "tink/jwt/jwt_signature_config.h"
#include "tink/keyderivation/key_derivation_config.h"

extern "C" {

int tink_register_all(void) {
  absl::Status status = crypto::tink::TinkConfig::Register();
  if (!status.ok()) {
    set_last_error(status);
    return 1;
  }
  status = crypto::tink::RegisterHpke();
  if (!status.ok()) {
    set_last_error(status);
    return 1;
  }
  status = crypto::tink::JwtMacRegister();
  if (!status.ok()) {
    set_last_error(status);
    return 1;
  }
  status = crypto::tink::JwtSignatureRegister();
  if (!status.ok()) {
    set_last_error(status);
    return 1;
  }
  status = crypto::tink::KeyDerivationConfig::Register();
  if (!status.ok()) {
    set_last_error(status);
    return 1;
  }
  return 0;
}

}  // extern "C"
