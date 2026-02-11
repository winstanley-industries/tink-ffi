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
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/config_v0.h"

struct TinkSigner {
    std::unique_ptr<crypto::tink::PublicKeySign> primitive;
};

struct TinkVerifier {
    std::unique_ptr<crypto::tink::PublicKeyVerify> primitive;
};

extern "C" {

int tink_signer_new(const TinkKeysetHandle *handle, TinkSigner **signer_out) {
    auto result = handle->handle->GetPrimitive<crypto::tink::PublicKeySign>(
        crypto::tink::ConfigSignatureV0());
    if (!result.ok()) {
        set_last_error(result.status());
        return 1;
    }
    *signer_out = new TinkSigner{std::move(*result)};
    return 0;
}

int tink_signer_sign(const TinkSigner *signer,
                     const uint8_t *data, size_t data_len,
                     uint8_t **signature_out, size_t *signature_len_out) {
    auto result = signer->primitive->Sign(
        absl::string_view(reinterpret_cast<const char *>(data), data_len));
    if (!result.ok()) {
        set_last_error(result.status());
        return 1;
    }
    const std::string &sig = *result;
    *signature_len_out = sig.size();
    *signature_out = new uint8_t[sig.size()];
    std::memcpy(*signature_out, sig.data(), sig.size());
    return 0;
}

void tink_signer_free(TinkSigner *signer) {
    delete signer;
}

int tink_verifier_new(const TinkKeysetHandle *handle,
                      TinkVerifier **verifier_out) {
    auto result = handle->handle->GetPrimitive<crypto::tink::PublicKeyVerify>(
        crypto::tink::ConfigSignatureV0());
    if (!result.ok()) {
        set_last_error(result.status());
        return 1;
    }
    *verifier_out = new TinkVerifier{std::move(*result)};
    return 0;
}

int tink_verifier_verify(const TinkVerifier *verifier,
                         const uint8_t *signature, size_t signature_len,
                         const uint8_t *data, size_t data_len) {
    auto status = verifier->primitive->Verify(
        absl::string_view(reinterpret_cast<const char *>(signature), signature_len),
        absl::string_view(reinterpret_cast<const char *>(data), data_len));
    if (!status.ok()) {
        set_last_error(status);
        return 1;
    }
    return 0;
}

void tink_verifier_free(TinkVerifier *verifier) {
    delete verifier;
}

}  // extern "C"
