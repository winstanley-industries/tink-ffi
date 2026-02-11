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
#include "tink/mac.h"
#include "tink/mac/config_v0.h"

struct TinkMac {
    std::unique_ptr<crypto::tink::Mac> primitive;
};

extern "C" {

int tink_mac_new(const TinkKeysetHandle *handle, TinkMac **mac_out) {
    auto result = handle->handle->GetPrimitive<crypto::tink::Mac>(
        crypto::tink::ConfigMacV0());
    if (!result.ok()) {
        set_last_error(result.status());
        return 1;
    }
    *mac_out = new TinkMac{std::move(*result)};
    return 0;
}

int tink_mac_compute(const TinkMac *mac,
                     const uint8_t *data, size_t data_len,
                     uint8_t **mac_out, size_t *mac_len_out) {
    auto result = mac->primitive->ComputeMac(
        absl::string_view(reinterpret_cast<const char *>(data), data_len));
    if (!result.ok()) {
        set_last_error(result.status());
        return 1;
    }
    const std::string &tag = *result;
    *mac_len_out = tag.size();
    *mac_out = new uint8_t[tag.size()];
    std::memcpy(*mac_out, tag.data(), tag.size());
    return 0;
}

int tink_mac_verify(const TinkMac *mac,
                    const uint8_t *mac_value, size_t mac_value_len,
                    const uint8_t *data, size_t data_len) {
    auto status = mac->primitive->VerifyMac(
        absl::string_view(reinterpret_cast<const char *>(mac_value), mac_value_len),
        absl::string_view(reinterpret_cast<const char *>(data), data_len));
    if (!status.ok()) {
        set_last_error(status);
        return 1;
    }
    return 0;
}

void tink_mac_free(TinkMac *mac) {
    delete mac;
}

}  // extern "C"
