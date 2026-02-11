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

#include "absl/strings/string_view.h"
#include "tink/prf/prf_set.h"
#include "tink/prf/config_v0.h"

using crypto::tink::PrfSet;

struct TinkPrfSet {
  std::unique_ptr<PrfSet> prf_set;
};

extern "C" {

int tink_prf_set_new(const TinkKeysetHandle* handle,
                     TinkPrfSet** prf_set_out) {
  auto result = handle->handle->GetPrimitive<PrfSet>(
      crypto::tink::ConfigPrfV0());
  if (!result.ok()) {
    set_last_error(result.status());
    return 1;
  }
  *prf_set_out = new TinkPrfSet{std::move(result.value())};
  return 0;
}

int tink_prf_set_primary_id(const TinkPrfSet* prf_set, uint32_t* id_out) {
  *id_out = prf_set->prf_set->GetPrimaryId();
  return 0;
}

int tink_prf_set_compute_primary(const TinkPrfSet* prf_set,
                                 const uint8_t* input, size_t input_len,
                                 size_t output_len, uint8_t** output_out,
                                 size_t* output_len_out) {
  auto result = prf_set->prf_set->ComputePrimary(
      absl::string_view(reinterpret_cast<const char*>(input), input_len),
      output_len);
  if (!result.ok()) {
    set_last_error(result.status());
    return 1;
  }
  const std::string& out = result.value();
  *output_len_out = out.size();
  *output_out = new uint8_t[out.size()];
  std::memcpy(*output_out, out.data(), out.size());
  return 0;
}

int tink_prf_set_key_ids(const TinkPrfSet* prf_set,
                         uint32_t** key_ids_out, size_t* num_keys_out) {
  const auto& prfs = prf_set->prf_set->GetPrfs();
  size_t n = prfs.size();
  *num_keys_out = n;
  if (n == 0) {
    *key_ids_out = nullptr;
    return 0;
  }
  *key_ids_out = new uint32_t[n];
  size_t i = 0;
  for (const auto& pair : prfs) {
    (*key_ids_out)[i++] = pair.first;
  }
  return 0;
}

int tink_prf_set_compute(const TinkPrfSet* prf_set,
                         uint32_t key_id,
                         const uint8_t* input, size_t input_len,
                         size_t output_len,
                         uint8_t** output_out, size_t* output_len_out) {
  const auto& prfs = prf_set->prf_set->GetPrfs();
  auto it = prfs.find(key_id);
  if (it == prfs.end()) {
    set_last_error("PRF key ID not found: " + std::to_string(key_id));
    return 1;
  }
  auto result = it->second->Compute(
      absl::string_view(reinterpret_cast<const char*>(input), input_len),
      output_len);
  if (!result.ok()) {
    set_last_error(result.status());
    return 1;
  }
  const std::string& out = result.value();
  *output_len_out = out.size();
  *output_out = new uint8_t[out.size()];
  std::memcpy(*output_out, out.data(), out.size());
  return 0;
}

void tink_prf_set_free(TinkPrfSet* prf_set) { delete prf_set; }

}  // extern "C"
