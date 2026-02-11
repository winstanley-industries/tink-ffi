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

use std::ffi::CStr;
use std::fmt;
use std::os::raw::c_char;

#[derive(Debug)]
pub struct TinkError {
    pub message: String,
    pub code: i32,
}

impl fmt::Display for TinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tink error ({}): {}", self.code, self.message)
    }
}

impl std::error::Error for TinkError {}

pub type Result<T> = std::result::Result<T, TinkError>;

pub(crate) fn check_status(rc: std::os::raw::c_int) -> Result<()> {
    if rc == 0 {
        return Ok(());
    }
    let msg = unsafe {
        let ptr = tink_ffi_sys::tink_error_message();
        if ptr.is_null() {
            "unknown error".to_string()
        } else {
            CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    };
    Err(TinkError {
        message: msg,
        code: rc,
    })
}

pub(crate) unsafe fn take_bytes(ptr: *mut u8, len: usize) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        if !ptr.is_null() {
            tink_ffi_sys::tink_free_bytes(ptr, 0);
        }
        return Vec::new();
    }
    let v = std::slice::from_raw_parts(ptr, len).to_vec();
    tink_ffi_sys::tink_free_bytes(ptr, len);
    v
}

pub(crate) unsafe fn take_string(ptr: *mut c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
    tink_ffi_sys::tink_free_string(ptr);
    s
}
