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

/// Creates digital signatures using asymmetric private keys.
///
/// ```ignore
/// let signer: SignerPrimitive = private_handle.primitive()?;
/// let signature = signer.sign(b"data to sign")?;
/// ```
pub trait Signer {
    /// Signs the given `data` and returns the signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
}

/// Verifies digital signatures using asymmetric public keys.
///
/// Use [`KeysetHandle::public_handle`] to extract the public key from a
/// private keyset before creating a verifier.
///
/// ```ignore
/// let public_handle = private_handle.public_handle()?;
/// let verifier: VerifierPrimitive = public_handle.primitive()?;
/// verifier.verify(&signature, b"data to sign")?;
/// ```
pub trait Verifier {
    /// Verifies that `signature` is valid for the given `data`.
    ///
    /// Returns `Ok(())` if the signature is valid.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid or verification fails.
    fn verify(&self, signature: &[u8], data: &[u8]) -> Result<()>;
}

// ---------------------------------------------------------------------------
// SignerPrimitive
// ---------------------------------------------------------------------------

/// Concrete implementation of [`Signer`] backed by a Tink keyset.
///
/// Created via [`KeysetHandle::primitive`] with a private-key keyset.
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

/// Concrete implementation of [`Verifier`] backed by a Tink keyset.
///
/// Created via [`KeysetHandle::primitive`] with a public-key keyset.
/// Use [`KeysetHandle::public_handle`] to extract the public key from a
/// private keyset.
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
