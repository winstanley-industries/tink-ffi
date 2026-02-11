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

#include <cstdlib>
#include <cstring>
#include <string>

#include "absl/status/status.h"

thread_local std::string last_error;

void set_last_error(const std::string& msg) { last_error = msg; }

void set_last_error(const absl::Status& status) {
  last_error = std::string(status.message());
}

extern "C" {

const char* tink_error_message(void) { return last_error.c_str(); }

void tink_free_bytes(uint8_t* ptr, size_t len) {
  (void)len;
  delete[] ptr;
}

void tink_free_string(char* ptr) { delete[] ptr; }

}  // extern "C"
