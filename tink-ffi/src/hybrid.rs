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

pub trait HybridEncrypt {
    fn encrypt(&self, plaintext: &[u8], context_info: &[u8]) -> Result<Vec<u8>>;
}

pub trait HybridDecrypt {
    fn decrypt(&self, ciphertext: &[u8], context_info: &[u8]) -> Result<Vec<u8>>;
}

// ---------------------------------------------------------------------------
// HybridEncryptPrimitive
// ---------------------------------------------------------------------------

pub struct HybridEncryptPrimitive {
    raw: *mut tink_ffi_sys::TinkHybridEncrypt,
}

unsafe impl Send for HybridEncryptPrimitive {}
unsafe impl Sync for HybridEncryptPrimitive {}

impl Drop for HybridEncryptPrimitive {
    fn drop(&mut self) {
        unsafe { tink_ffi_sys::tink_hybrid_encrypt_free(self.raw) }
    }
}

impl sealed::Sealed for HybridEncryptPrimitive {}

impl crate::Primitive for HybridEncryptPrimitive {
    fn from_keyset_handle(handle: &KeysetHandle) -> Result<Self> {
        let mut raw = std::ptr::null_mut();
        check_status(unsafe { tink_ffi_sys::tink_hybrid_encrypt_new(handle.as_raw(), &mut raw) })?;
        Ok(Self { raw })
    }
}

impl HybridEncrypt for HybridEncryptPrimitive {
    fn encrypt(&self, plaintext: &[u8], context_info: &[u8]) -> Result<Vec<u8>> {
        let mut out = std::ptr::null_mut();
        let mut out_len = 0;
        check_status(unsafe {
            tink_ffi_sys::tink_hybrid_encrypt(
                self.raw,
                plaintext.as_ptr(),
                plaintext.len(),
                context_info.as_ptr(),
                context_info.len(),
                &mut out,
                &mut out_len,
            )
        })?;
        Ok(unsafe { take_bytes(out, out_len) })
    }
}

// ---------------------------------------------------------------------------
// HybridDecryptPrimitive
// ---------------------------------------------------------------------------

pub struct HybridDecryptPrimitive {
    raw: *mut tink_ffi_sys::TinkHybridDecrypt,
}

unsafe impl Send for HybridDecryptPrimitive {}
unsafe impl Sync for HybridDecryptPrimitive {}

impl Drop for HybridDecryptPrimitive {
    fn drop(&mut self) {
        unsafe { tink_ffi_sys::tink_hybrid_decrypt_free(self.raw) }
    }
}

impl sealed::Sealed for HybridDecryptPrimitive {}

impl crate::Primitive for HybridDecryptPrimitive {
    fn from_keyset_handle(handle: &KeysetHandle) -> Result<Self> {
        let mut raw = std::ptr::null_mut();
        check_status(unsafe { tink_ffi_sys::tink_hybrid_decrypt_new(handle.as_raw(), &mut raw) })?;
        Ok(Self { raw })
    }
}

impl HybridDecrypt for HybridDecryptPrimitive {
    fn decrypt(&self, ciphertext: &[u8], context_info: &[u8]) -> Result<Vec<u8>> {
        let mut out = std::ptr::null_mut();
        let mut out_len = 0;
        check_status(unsafe {
            tink_ffi_sys::tink_hybrid_decrypt(
                self.raw,
                ciphertext.as_ptr(),
                ciphertext.len(),
                context_info.as_ptr(),
                context_info.len(),
                &mut out,
                &mut out_len,
            )
        })?;
        Ok(unsafe { take_bytes(out, out_len) })
    }
}
