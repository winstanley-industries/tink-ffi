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

/// Deterministic Authenticated Encryption with Associated Data.
///
/// Like [`Aead`](crate::Aead), but encrypting the same plaintext and
/// `aad` always produces the same ciphertext. This is useful for key
/// wrapping and deduplication scenarios.
///
/// **Warning:** Deterministic encryption leaks whether two plaintexts
/// are identical. Prefer standard [`Aead`](crate::Aead) unless you
/// specifically need determinism.
pub trait DeterministicAead {
    /// Encrypt `plaintext` deterministically with associated data `aad`.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    fn encrypt_deterministically(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt `ciphertext` with associated data `aad`.
    ///
    /// # Errors
    ///
    /// Returns an error if the ciphertext is invalid or `aad` does
    /// not match.
    fn decrypt_deterministically(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
}

/// Concrete deterministic AEAD implementation backed by a Tink keyset.
///
/// Obtain via [`KeysetHandle::primitive::<DeterministicAeadPrimitive>()`](crate::KeysetHandle::primitive).
/// Thread-safe ([`Send`] + [`Sync`]).
pub struct DeterministicAeadPrimitive {
    raw: *mut tink_ffi_sys::TinkDeterministicAead,
}

unsafe impl Send for DeterministicAeadPrimitive {}
unsafe impl Sync for DeterministicAeadPrimitive {}

impl Drop for DeterministicAeadPrimitive {
    fn drop(&mut self) {
        unsafe { tink_ffi_sys::tink_deterministic_aead_free(self.raw) }
    }
}

impl sealed::Sealed for DeterministicAeadPrimitive {}

impl crate::Primitive for DeterministicAeadPrimitive {
    fn from_keyset_handle(handle: &KeysetHandle) -> Result<Self> {
        let mut raw = std::ptr::null_mut();
        check_status(unsafe {
            tink_ffi_sys::tink_deterministic_aead_new(handle.as_raw(), &mut raw)
        })?;
        Ok(Self { raw })
    }
}

impl DeterministicAead for DeterministicAeadPrimitive {
    fn encrypt_deterministically(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let mut out = std::ptr::null_mut();
        let mut out_len = 0;
        check_status(unsafe {
            tink_ffi_sys::tink_deterministic_aead_encrypt(
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

    fn decrypt_deterministically(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let mut out = std::ptr::null_mut();
        let mut out_len = 0;
        check_status(unsafe {
            tink_ffi_sys::tink_deterministic_aead_decrypt(
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
