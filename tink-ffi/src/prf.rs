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

/// Pseudorandom function (PRF) set.
///
/// Computes deterministic pseudorandom output from arbitrary input. A keyset
/// can contain multiple PRF keys; use [`primary_id`](PrfSet::primary_id) to
/// identify the primary, or [`key_ids`](PrfSet::key_ids) to list all keys.
///
/// ```ignore
/// let prf: PrfSetPrimitive = handle.primitive()?;
/// let output = prf.compute_primary(b"input data", 32)?;
/// ```
pub trait PrfSet {
    /// Returns the key ID of the primary PRF key in the keyset.
    ///
    /// # Errors
    ///
    /// Returns an error if the primary ID cannot be determined.
    fn primary_id(&self) -> Result<u32>;

    /// Computes `output_len` bytes of PRF output using the primary key.
    ///
    /// # Errors
    ///
    /// Returns an error if the computation fails.
    fn compute_primary(&self, input: &[u8], output_len: usize) -> Result<Vec<u8>>;

    /// Returns the key IDs of all PRF keys in the keyset.
    ///
    /// # Errors
    ///
    /// Returns an error if the key IDs cannot be retrieved.
    fn key_ids(&self) -> Result<Vec<u32>>;

    /// Computes `output_len` bytes of PRF output using the key identified by `key_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if `key_id` is not in the keyset or the computation fails.
    fn compute(&self, key_id: u32, input: &[u8], output_len: usize) -> Result<Vec<u8>>;
}

/// Concrete implementation of [`PrfSet`] backed by a Tink keyset.
///
/// Created via [`KeysetHandle::primitive`].
pub struct PrfSetPrimitive {
    raw: *mut tink_ffi_sys::TinkPrfSet,
}

unsafe impl Send for PrfSetPrimitive {}
unsafe impl Sync for PrfSetPrimitive {}

impl Drop for PrfSetPrimitive {
    fn drop(&mut self) {
        unsafe { tink_ffi_sys::tink_prf_set_free(self.raw) }
    }
}

impl sealed::Sealed for PrfSetPrimitive {}

impl crate::Primitive for PrfSetPrimitive {
    fn from_keyset_handle(handle: &KeysetHandle) -> Result<Self> {
        let mut raw = std::ptr::null_mut();
        check_status(unsafe { tink_ffi_sys::tink_prf_set_new(handle.as_raw(), &mut raw) })?;
        Ok(Self { raw })
    }
}

impl PrfSet for PrfSetPrimitive {
    fn primary_id(&self) -> Result<u32> {
        let mut id = 0u32;
        check_status(unsafe { tink_ffi_sys::tink_prf_set_primary_id(self.raw, &mut id) })?;
        Ok(id)
    }

    fn compute_primary(&self, input: &[u8], output_len: usize) -> Result<Vec<u8>> {
        let mut out = std::ptr::null_mut();
        let mut out_len = 0;
        check_status(unsafe {
            tink_ffi_sys::tink_prf_set_compute_primary(
                self.raw,
                input.as_ptr(),
                input.len(),
                output_len,
                &mut out,
                &mut out_len,
            )
        })?;
        Ok(unsafe { take_bytes(out, out_len) })
    }

    fn key_ids(&self) -> Result<Vec<u32>> {
        let mut ids_out: *mut u32 = std::ptr::null_mut();
        let mut num_keys = 0usize;
        check_status(unsafe {
            tink_ffi_sys::tink_prf_set_key_ids(self.raw, &mut ids_out, &mut num_keys)
        })?;
        if ids_out.is_null() || num_keys == 0 {
            return Ok(Vec::new());
        }
        let ids = unsafe { std::slice::from_raw_parts(ids_out, num_keys) }.to_vec();
        unsafe {
            tink_ffi_sys::tink_free_bytes(
                ids_out as *mut u8,
                num_keys * std::mem::size_of::<u32>(),
            );
        }
        Ok(ids)
    }

    fn compute(&self, key_id: u32, input: &[u8], output_len: usize) -> Result<Vec<u8>> {
        let mut out = std::ptr::null_mut();
        let mut out_len = 0;
        check_status(unsafe {
            tink_ffi_sys::tink_prf_set_compute(
                self.raw,
                key_id,
                input.as_ptr(),
                input.len(),
                output_len,
                &mut out,
                &mut out_len,
            )
        })?;
        Ok(unsafe { take_bytes(out, out_len) })
    }
}
