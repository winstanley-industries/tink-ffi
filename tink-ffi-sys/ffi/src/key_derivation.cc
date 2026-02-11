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

#include <memory>

#include "absl/strings/string_view.h"
#include "tink/config/global_registry.h"
#include "tink/keyderivation/keyset_deriver.h"

using crypto::tink::KeysetDeriver;

struct TinkKeysetDeriver {
  std::unique_ptr<KeysetDeriver> deriver;
};

extern "C" {

int tink_keyset_deriver_new(const TinkKeysetHandle* handle,
                            TinkKeysetDeriver** deriver_out) {
  auto result = handle->handle->GetPrimitive<KeysetDeriver>(
      crypto::tink::ConfigGlobalRegistry());
  if (!result.ok()) {
    set_last_error(result.status());
    return 1;
  }
  *deriver_out = new TinkKeysetDeriver{std::move(result.value())};
  return 0;
}

int tink_keyset_deriver_derive(const TinkKeysetDeriver* deriver,
                               const uint8_t* salt, size_t salt_len,
                               TinkKeysetHandle** derived_handle_out) {
  auto result = deriver->deriver->DeriveKeyset(
      absl::string_view(reinterpret_cast<const char*>(salt), salt_len));
  if (!result.ok()) {
    set_last_error(result.status());
    return 1;
  }
  *derived_handle_out = new TinkKeysetHandle{std::move(result.value())};
  return 0;
}

void tink_keyset_deriver_free(TinkKeysetDeriver* deriver) { delete deriver; }

}  // extern "C"
