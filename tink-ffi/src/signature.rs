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

pub trait Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
}

pub trait Verifier {
    fn verify(&self, signature: &[u8], data: &[u8]) -> Result<()>;
}

// ---------------------------------------------------------------------------
// SignerPrimitive
// ---------------------------------------------------------------------------

pub struct SignerPrimitive {
    raw: *mut tink_ffi_sys::TinkSigner,
}

unsafe impl Send for SignerPrimitive {}
unsafe impl Sync for SignerPrimitive {}

impl Drop for SignerPrimitive {
    fn drop(&mut self) {
        unsafe { tink_ffi_sys::tink_signer_free(self.raw) }
    }
}

impl sealed::Sealed for SignerPrimitive {}

impl crate::Primitive for SignerPrimitive {
    fn from_keyset_handle(handle: &KeysetHandle) -> Result<Self> {
        let mut raw = std::ptr::null_mut();
        check_status(unsafe { tink_ffi_sys::tink_signer_new(handle.as_raw(), &mut raw) })?;
        Ok(Self { raw })
    }
}

impl Signer for SignerPrimitive {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut out = std::ptr::null_mut();
        let mut out_len = 0;
        check_status(unsafe {
            tink_ffi_sys::tink_signer_sign(
                self.raw,
                data.as_ptr(),
                data.len(),
                &mut out,
                &mut out_len,
            )
        })?;
        Ok(unsafe { take_bytes(out, out_len) })
    }
}

// ---------------------------------------------------------------------------
// VerifierPrimitive
// ---------------------------------------------------------------------------

pub struct VerifierPrimitive {
    raw: *mut tink_ffi_sys::TinkVerifier,
}

unsafe impl Send for VerifierPrimitive {}
unsafe impl Sync for VerifierPrimitive {}

impl Drop for VerifierPrimitive {
    fn drop(&mut self) {
        unsafe { tink_ffi_sys::tink_verifier_free(self.raw) }
    }
}

impl sealed::Sealed for VerifierPrimitive {}

impl crate::Primitive for VerifierPrimitive {
    fn from_keyset_handle(handle: &KeysetHandle) -> Result<Self> {
        let mut raw = std::ptr::null_mut();
        check_status(unsafe { tink_ffi_sys::tink_verifier_new(handle.as_raw(), &mut raw) })?;
        Ok(Self { raw })
    }
}

impl Verifier for VerifierPrimitive {
    fn verify(&self, signature: &[u8], data: &[u8]) -> Result<()> {
        check_status(unsafe {
            tink_ffi_sys::tink_verifier_verify(
                self.raw,
                signature.as_ptr(),
                signature.len(),
                data.as_ptr(),
                data.len(),
            )
        })
    }
}
