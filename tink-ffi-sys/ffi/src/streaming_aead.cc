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

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/streaming_aead.h"
#include "tink/streamingaead/config_v0.h"
#include "tink/output_stream.h"
#include "tink/input_stream.h"
#include "tink/util/ostream_output_stream.h"
#include "tink/util/istream_input_stream.h"

using crypto::tink::StreamingAead;
using crypto::tink::OutputStream;
using crypto::tink::InputStream;
using crypto::tink::util::OstreamOutputStream;
using crypto::tink::util::IstreamInputStream;

struct TinkStreamingAead {
  std::unique_ptr<StreamingAead> saead;
};

struct TinkEncryptingStream {
  std::unique_ptr<OutputStream> stream;
  std::ostringstream* oss_ptr;  // non-owning, owned by OstreamOutputStream
};

struct TinkDecryptingStream {
  std::unique_ptr<InputStream> stream;
};

extern "C" {

int tink_streaming_aead_new(const TinkKeysetHandle* handle,
                            TinkStreamingAead** saead_out) {
  auto result = handle->handle->GetPrimitive<StreamingAead>(
      crypto::tink::ConfigStreamingAeadV0());
  if (!result.ok()) {
    set_last_error(result.status());
    return 1;
  }
  *saead_out = new TinkStreamingAead{std::move(result.value())};
  return 0;
}

int tink_streaming_aead_encrypt_start(const TinkStreamingAead* saead,
                                      const uint8_t* aad, size_t aad_len,
                                      TinkEncryptingStream** stream_out) {
  auto oss = std::make_unique<std::ostringstream>();
  std::ostringstream* oss_ptr = oss.get();
  auto ct_dest = std::make_unique<OstreamOutputStream>(std::move(oss));

  auto result = saead->saead->NewEncryptingStream(
      std::move(ct_dest),
      absl::string_view(reinterpret_cast<const char*>(aad), aad_len));
  if (!result.ok()) {
    set_last_error(result.status());
    return 1;
  }

  *stream_out =
      new TinkEncryptingStream{std::move(result.value()), oss_ptr};
  return 0;
}

int tink_encrypting_stream_write(TinkEncryptingStream* stream,
                                 const uint8_t* data, size_t data_len,
                                 size_t* written_out) {
  size_t total_written = 0;
  while (total_written < data_len) {
    void* buf = nullptr;
    auto next_result = stream->stream->Next(&buf);
    if (!next_result.ok()) {
      set_last_error(next_result.status());
      *written_out = total_written;
      return 1;
    }
    int available = next_result.value();
    size_t remaining = data_len - total_written;
    size_t to_copy =
        remaining < static_cast<size_t>(available) ? remaining : available;
    std::memcpy(buf, data + total_written, to_copy);
    if (to_copy < static_cast<size_t>(available)) {
      stream->stream->BackUp(available - static_cast<int>(to_copy));
    }
    total_written += to_copy;
  }
  *written_out = total_written;
  return 0;
}

int tink_encrypting_stream_finalize(TinkEncryptingStream* stream,
                                    uint8_t** ciphertext_out,
                                    size_t* ciphertext_len_out) {
  absl::Status status = stream->stream->Close();
  if (!status.ok()) {
    set_last_error(status);
    return 1;
  }

  std::string ct = stream->oss_ptr->str();
  *ciphertext_len_out = ct.size();
  *ciphertext_out = new uint8_t[ct.size()];
  std::memcpy(*ciphertext_out, ct.data(), ct.size());
  return 0;
}

void tink_encrypting_stream_free(TinkEncryptingStream* stream) {
  delete stream;
}

int tink_streaming_aead_decrypt_start(const TinkStreamingAead* saead,
                                      const uint8_t* ciphertext,
                                      size_t ciphertext_len,
                                      const uint8_t* aad, size_t aad_len,
                                      TinkDecryptingStream** stream_out) {
  auto iss = std::make_unique<std::istringstream>(
      std::string(reinterpret_cast<const char*>(ciphertext), ciphertext_len));
  auto ct_source = std::make_unique<IstreamInputStream>(std::move(iss));

  auto result = saead->saead->NewDecryptingStream(
      std::move(ct_source),
      absl::string_view(reinterpret_cast<const char*>(aad), aad_len));
  if (!result.ok()) {
    set_last_error(result.status());
    return 1;
  }

  *stream_out = new TinkDecryptingStream{std::move(result.value())};
  return 0;
}

int tink_decrypting_stream_read(TinkDecryptingStream* stream, uint8_t* buf,
                                size_t buf_len, size_t* read_out) {
  size_t total_read = 0;
  while (total_read < buf_len) {
    const void* data = nullptr;
    auto next_result = stream->stream->Next(&data);
    if (!next_result.ok()) {
      if (absl::IsOutOfRange(next_result.status())) {
        // End of stream.
        *read_out = total_read;
        return 0;
      }
      set_last_error(next_result.status());
      *read_out = total_read;
      return 1;
    }
    int available = next_result.value();
    if (available == 0) continue;
    size_t remaining = buf_len - total_read;
    size_t to_copy =
        remaining < static_cast<size_t>(available) ? remaining : available;
    std::memcpy(buf + total_read, data, to_copy);
    if (to_copy < static_cast<size_t>(available)) {
      stream->stream->BackUp(available - static_cast<int>(to_copy));
    }
    total_read += to_copy;
  }
  *read_out = total_read;
  return 0;
}

void tink_decrypting_stream_free(TinkDecryptingStream* stream) {
  delete stream;
}

void tink_streaming_aead_free(TinkStreamingAead* saead) { delete saead; }

}  // extern "C"
