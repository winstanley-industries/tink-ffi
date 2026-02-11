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

use std::ffi::CString;

use crate::error::{check_status, take_string, Result};
use crate::keyset::KeysetHandle;
use crate::sealed;

// ---------------------------------------------------------------------------
// RawJwt — claims to sign/encode
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RawJwt {
    claims: serde_json::Value,
}

impl RawJwt {
    pub fn new(claims: serde_json::Value) -> Self {
        Self { claims }
    }

    pub fn claims(&self) -> &serde_json::Value {
        &self.claims
    }

    pub(crate) fn to_json_cstring(&self) -> CString {
        let s = serde_json::to_string(&self.claims).expect("claims should serialize");
        CString::new(s).expect("json contains nul byte")
    }
}

// ---------------------------------------------------------------------------
// JwtValidator — validation rules
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct JwtValidator {
    config: serde_json::Value,
}

impl JwtValidator {
    pub fn new(config: serde_json::Value) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &serde_json::Value {
        &self.config
    }

    pub(crate) fn to_json_cstring(&self) -> CString {
        let s = serde_json::to_string(&self.config).expect("config should serialize");
        CString::new(s).expect("json contains nul byte")
    }
}

// ---------------------------------------------------------------------------
// VerifiedJwt — decoded, verified claims
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct VerifiedJwt {
    claims: serde_json::Value,
}

impl VerifiedJwt {
    pub fn claims(&self) -> &serde_json::Value {
        &self.claims
    }

    pub fn into_claims(self) -> serde_json::Value {
        self.claims
    }
}

// ---------------------------------------------------------------------------
// JwtMac
// ---------------------------------------------------------------------------

pub trait JwtMac {
    fn compute_and_encode(&self, raw_jwt: &RawJwt) -> Result<String>;
    fn verify_and_decode(&self, compact: &str, validator: &JwtValidator) -> Result<VerifiedJwt>;
}

pub struct JwtMacPrimitive {
    raw: *mut tink_ffi_sys::TinkJwtMac,
}

unsafe impl Send for JwtMacPrimitive {}
unsafe impl Sync for JwtMacPrimitive {}

impl Drop for JwtMacPrimitive {
    fn drop(&mut self) {
        unsafe { tink_ffi_sys::tink_jwt_mac_free(self.raw) }
    }
}

impl sealed::Sealed for JwtMacPrimitive {}

impl crate::Primitive for JwtMacPrimitive {
    fn from_keyset_handle(handle: &KeysetHandle) -> Result<Self> {
        let mut raw = std::ptr::null_mut();
        check_status(unsafe { tink_ffi_sys::tink_jwt_mac_new(handle.as_raw(), &mut raw) })?;
        Ok(Self { raw })
    }
}

impl JwtMac for JwtMacPrimitive {
    fn compute_and_encode(&self, raw_jwt: &RawJwt) -> Result<String> {
        let jwt_json = raw_jwt.to_json_cstring();
        let mut compact_out = std::ptr::null_mut();
        check_status(unsafe {
            tink_ffi_sys::tink_jwt_mac_compute_and_encode(
                self.raw,
                jwt_json.as_ptr(),
                &mut compact_out,
            )
        })?;
        Ok(unsafe { take_string(compact_out) })
    }

    fn verify_and_decode(&self, compact: &str, validator: &JwtValidator) -> Result<VerifiedJwt> {
        let compact_c = CString::new(compact).expect("compact contains nul byte");
        let validator_json = validator.to_json_cstring();
        let mut claims_out = std::ptr::null_mut();
        check_status(unsafe {
            tink_ffi_sys::tink_jwt_mac_verify_and_decode(
                self.raw,
                compact_c.as_ptr(),
                validator_json.as_ptr(),
                &mut claims_out,
            )
        })?;
        let claims_str = unsafe { take_string(claims_out) };
        let claims: serde_json::Value =
            serde_json::from_str(&claims_str).map_err(|e| crate::TinkError {
                message: format!("failed to parse verified JWT claims: {e}"),
                code: -1,
            })?;
        Ok(VerifiedJwt { claims })
    }
}

// ---------------------------------------------------------------------------
// JwtSigner
// ---------------------------------------------------------------------------

pub trait JwtSign {
    fn sign_and_encode(&self, raw_jwt: &RawJwt) -> Result<String>;
}

pub struct JwtSignerPrimitive {
    raw: *mut tink_ffi_sys::TinkJwtSigner,
}

unsafe impl Send for JwtSignerPrimitive {}
unsafe impl Sync for JwtSignerPrimitive {}

impl Drop for JwtSignerPrimitive {
    fn drop(&mut self) {
        unsafe { tink_ffi_sys::tink_jwt_signer_free(self.raw) }
    }
}

impl sealed::Sealed for JwtSignerPrimitive {}

impl crate::Primitive for JwtSignerPrimitive {
    fn from_keyset_handle(handle: &KeysetHandle) -> Result<Self> {
        let mut raw = std::ptr::null_mut();
        check_status(unsafe { tink_ffi_sys::tink_jwt_signer_new(handle.as_raw(), &mut raw) })?;
        Ok(Self { raw })
    }
}

impl JwtSign for JwtSignerPrimitive {
    fn sign_and_encode(&self, raw_jwt: &RawJwt) -> Result<String> {
        let jwt_json = raw_jwt.to_json_cstring();
        let mut compact_out = std::ptr::null_mut();
        check_status(unsafe {
            tink_ffi_sys::tink_jwt_signer_sign_and_encode(
                self.raw,
                jwt_json.as_ptr(),
                &mut compact_out,
            )
        })?;
        Ok(unsafe { take_string(compact_out) })
    }
}

// ---------------------------------------------------------------------------
// JwtVerifier
// ---------------------------------------------------------------------------

pub trait JwtVerify {
    fn verify_and_decode(&self, compact: &str, validator: &JwtValidator) -> Result<VerifiedJwt>;
}

pub struct JwtVerifierPrimitive {
    raw: *mut tink_ffi_sys::TinkJwtVerifier,
}

unsafe impl Send for JwtVerifierPrimitive {}
unsafe impl Sync for JwtVerifierPrimitive {}

impl Drop for JwtVerifierPrimitive {
    fn drop(&mut self) {
        unsafe { tink_ffi_sys::tink_jwt_verifier_free(self.raw) }
    }
}

impl sealed::Sealed for JwtVerifierPrimitive {}

impl crate::Primitive for JwtVerifierPrimitive {
    fn from_keyset_handle(handle: &KeysetHandle) -> Result<Self> {
        let mut raw = std::ptr::null_mut();
        check_status(unsafe { tink_ffi_sys::tink_jwt_verifier_new(handle.as_raw(), &mut raw) })?;
        Ok(Self { raw })
    }
}

impl JwtVerify for JwtVerifierPrimitive {
    fn verify_and_decode(&self, compact: &str, validator: &JwtValidator) -> Result<VerifiedJwt> {
        let compact_c = CString::new(compact).expect("compact contains nul byte");
        let validator_json = validator.to_json_cstring();
        let mut claims_out = std::ptr::null_mut();
        check_status(unsafe {
            tink_ffi_sys::tink_jwt_verifier_verify_and_decode(
                self.raw,
                compact_c.as_ptr(),
                validator_json.as_ptr(),
                &mut claims_out,
            )
        })?;
        let claims_str = unsafe { take_string(claims_out) };
        let claims: serde_json::Value =
            serde_json::from_str(&claims_str).map_err(|e| crate::TinkError {
                message: format!("failed to parse verified JWT claims: {e}"),
                code: -1,
            })?;
        Ok(VerifiedJwt { claims })
    }
}
