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

/// Message Authentication Code (MAC).
///
/// A MAC produces a short authentication tag for a message, allowing
/// verification of data integrity and authenticity. The tag can only
/// be computed and verified by parties that share the same key.
pub trait Mac {
    /// Compute a MAC tag for `data`.
    ///
    /// # Errors
    ///
    /// Returns an error if tag computation fails.
    fn compute(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// Verify that `mac_value` is a valid tag for `data`.
    ///
    /// # Errors
    ///
    /// Returns an error if the tag is invalid or does not match.
    fn verify(&self, mac_value: &[u8], data: &[u8]) -> Result<()>;
}

/// Concrete MAC implementation backed by a Tink keyset.
///
/// Obtain via [`KeysetHandle::primitive::<MacPrimitive>()`](crate::KeysetHandle::primitive).
/// Thread-safe ([`Send`] + [`Sync`]).
pub struct MacPrimitive {
    raw: *mut tink_ffi_sys::TinkMac,
}

unsafe impl Send for MacPrimitive {}
unsafe impl Sync for MacPrimitive {}

impl Drop for MacPrimitive {
    fn drop(&mut self) {
        unsafe { tink_ffi_sys::tink_mac_free(self.raw) }
    }
}

impl sealed::Sealed for MacPrimitive {}

impl crate::Primitive for MacPrimitive {
    fn from_keyset_handle(handle: &KeysetHandle) -> Result<Self> {
        let mut raw = std::ptr::null_mut();
        check_status(unsafe { tink_ffi_sys::tink_mac_new(handle.as_raw(), &mut raw) })?;
        Ok(Self { raw })
    }
}

impl Mac for MacPrimitive {
    fn compute(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut out = std::ptr::null_mut();
        let mut out_len = 0;
        check_status(unsafe {
            tink_ffi_sys::tink_mac_compute(
                self.raw,
                data.as_ptr(),
                data.len(),
                &mut out,
                &mut out_len,
            )
        })?;
        Ok(unsafe { take_bytes(out, out_len) })
    }

    fn verify(&self, mac_value: &[u8], data: &[u8]) -> Result<()> {
        check_status(unsafe {
            tink_ffi_sys::tink_mac_verify(
                self.raw,
                mac_value.as_ptr(),
                mac_value.len(),
                data.as_ptr(),
                data.len(),
            )
        })
    }
}
