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
#include "tink/hybrid_encrypt.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid/config_v0.h"

struct TinkHybridEncrypt {
    std::unique_ptr<crypto::tink::HybridEncrypt> primitive;
};

struct TinkHybridDecrypt {
    std::unique_ptr<crypto::tink::HybridDecrypt> primitive;
};

extern "C" {

int tink_hybrid_encrypt_new(const TinkKeysetHandle *handle,
                            TinkHybridEncrypt **enc_out) {
    auto result = handle->handle->GetPrimitive<crypto::tink::HybridEncrypt>(
        crypto::tink::ConfigHybridV0());
    if (!result.ok()) {
        set_last_error(result.status());
        return 1;
    }
    *enc_out = new TinkHybridEncrypt{std::move(*result)};
    return 0;
}

int tink_hybrid_encrypt(const TinkHybridEncrypt *enc,
                        const uint8_t *plaintext, size_t plaintext_len,
                        const uint8_t *context_info, size_t context_info_len,
                        uint8_t **ciphertext_out, size_t *ciphertext_len_out) {
    auto result = enc->primitive->Encrypt(
        absl::string_view(reinterpret_cast<const char *>(plaintext), plaintext_len),
        absl::string_view(reinterpret_cast<const char *>(context_info), context_info_len));
    if (!result.ok()) {
        set_last_error(result.status());
        return 1;
    }
    const std::string &ct = *result;
    *ciphertext_len_out = ct.size();
    *ciphertext_out = new uint8_t[ct.size()];
    std::memcpy(*ciphertext_out, ct.data(), ct.size());
    return 0;
}

void tink_hybrid_encrypt_free(TinkHybridEncrypt *enc) {
    delete enc;
}

int tink_hybrid_decrypt_new(const TinkKeysetHandle *handle,
                            TinkHybridDecrypt **dec_out) {
    auto result = handle->handle->GetPrimitive<crypto::tink::HybridDecrypt>(
        crypto::tink::ConfigHybridV0());
    if (!result.ok()) {
        set_last_error(result.status());
        return 1;
    }
    *dec_out = new TinkHybridDecrypt{std::move(*result)};
    return 0;
}

int tink_hybrid_decrypt(const TinkHybridDecrypt *dec,
                        const uint8_t *ciphertext, size_t ciphertext_len,
                        const uint8_t *context_info, size_t context_info_len,
                        uint8_t **plaintext_out, size_t *plaintext_len_out) {
    auto result = dec->primitive->Decrypt(
        absl::string_view(reinterpret_cast<const char *>(ciphertext), ciphertext_len),
        absl::string_view(reinterpret_cast<const char *>(context_info), context_info_len));
    if (!result.ok()) {
        set_last_error(result.status());
        return 1;
    }
    const std::string &pt = *result;
    *plaintext_len_out = pt.size();
    *plaintext_out = new uint8_t[pt.size()];
    std::memcpy(*plaintext_out, pt.data(), pt.size());
    return 0;
}

void tink_hybrid_decrypt_free(TinkHybridDecrypt *dec) {
    delete dec;
}

}  // extern "C"
