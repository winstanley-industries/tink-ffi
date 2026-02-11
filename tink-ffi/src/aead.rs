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

use crate::error::{check_status, take_bytes, Result};
use crate::keyset::KeysetHandle;
use crate::sealed;

pub trait Aead {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
}

pub struct AeadPrimitive {
    raw: *mut tink_ffi_sys::TinkAead,
}

unsafe impl Send for AeadPrimitive {}
unsafe impl Sync for AeadPrimitive {}

impl Drop for AeadPrimitive {
    fn drop(&mut self) {
        unsafe { tink_ffi_sys::tink_aead_free(self.raw) }
    }
}

impl sealed::Sealed for AeadPrimitive {}

impl crate::Primitive for AeadPrimitive {
    fn from_keyset_handle(handle: &KeysetHandle) -> Result<Self> {
        let mut raw = std::ptr::null_mut();
        check_status(unsafe { tink_ffi_sys::tink_aead_new(handle.as_raw(), &mut raw) })?;
        Ok(Self { raw })
    }
}

impl Aead for AeadPrimitive {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let mut out = std::ptr::null_mut();
        let mut out_len = 0;
        check_status(unsafe {
            tink_ffi_sys::tink_aead_encrypt(
                self.raw,
                plaintext.as_ptr(),
                plaintext.len(),
                aad.as_ptr(),
                aad.len(),
                &mut out,
                &mut out_len,
            )
        })?;
        Ok(unsafe { take_bytes(out, out_len) })
    }

    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let mut out = std::ptr::null_mut();
        let mut out_len = 0;
        check_status(unsafe {
            tink_ffi_sys::tink_aead_decrypt(
                self.raw,
                ciphertext.as_ptr(),
                ciphertext.len(),
                aad.as_ptr(),
                aad.len(),
                &mut out,
                &mut out_len,
            )
        })?;
        Ok(unsafe { take_bytes(out, out_len) })
    }
}
