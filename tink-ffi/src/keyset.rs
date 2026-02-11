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
use std::fmt;

use crate::error::{check_status, take_bytes, take_string, Result};
use crate::Primitive;

pub struct KeysetHandle {
    raw: *mut tink_ffi_sys::TinkKeysetHandle,
}

unsafe impl Send for KeysetHandle {}
unsafe impl Sync for KeysetHandle {}

impl Drop for KeysetHandle {
    fn drop(&mut self) {
        unsafe { tink_ffi_sys::tink_keyset_handle_free(self.raw) }
    }
}

impl KeysetHandle {
    pub(crate) fn as_raw(&self) -> *const tink_ffi_sys::TinkKeysetHandle {
        self.raw as *const _
    }

    pub(crate) fn from_raw(raw: *mut tink_ffi_sys::TinkKeysetHandle) -> Self {
        Self { raw }
    }

    pub fn generate_new(template: KeyTemplate) -> Result<Self> {
        let name = CString::new(template.as_str()).expect("template name contains nul byte");
        let mut raw = std::ptr::null_mut();
        check_status(unsafe {
            tink_ffi_sys::tink_keyset_handle_generate_new(name.as_ptr(), &mut raw)
        })?;
        Ok(Self { raw })
    }

    pub fn to_json(&self) -> Result<String> {
        let mut json_out = std::ptr::null_mut();
        check_status(unsafe {
            tink_ffi_sys::tink_keyset_handle_to_json(self.as_raw(), &mut json_out)
        })?;
        Ok(unsafe { take_string(json_out) })
    }

    pub fn from_json(json: &str) -> Result<Self> {
        let json_c = CString::new(json).expect("json contains nul byte");
        let mut raw = std::ptr::null_mut();
        check_status(unsafe {
            tink_ffi_sys::tink_keyset_handle_from_json(json_c.as_ptr(), &mut raw)
        })?;
        Ok(Self { raw })
    }

    pub fn to_binary(&self) -> Result<Vec<u8>> {
        let mut data_out = std::ptr::null_mut();
        let mut data_len = 0;
        check_status(unsafe {
            tink_ffi_sys::tink_keyset_handle_to_binary(self.as_raw(), &mut data_out, &mut data_len)
        })?;
        Ok(unsafe { take_bytes(data_out, data_len) })
    }

    pub fn from_binary(data: &[u8]) -> Result<Self> {
        let mut raw = std::ptr::null_mut();
        check_status(unsafe {
            tink_ffi_sys::tink_keyset_handle_from_binary(data.as_ptr(), data.len(), &mut raw)
        })?;
        Ok(Self { raw })
    }

    pub fn public_handle(&self) -> Result<Self> {
        let mut public_out = std::ptr::null_mut();
        check_status(unsafe {
            tink_ffi_sys::tink_keyset_handle_public(self.as_raw(), &mut public_out)
        })?;
        Ok(Self { raw: public_out })
    }

    pub fn info(&self) -> Result<String> {
        let mut info_out = std::ptr::null_mut();
        check_status(unsafe {
            tink_ffi_sys::tink_keyset_handle_info(self.as_raw(), &mut info_out)
        })?;
        Ok(unsafe { take_string(info_out) })
    }

    pub fn generate_from_template_bytes(template_bytes: &[u8]) -> Result<Self> {
        let mut raw = std::ptr::null_mut();
        check_status(unsafe {
            tink_ffi_sys::tink_keyset_handle_generate_from_template_bytes(
                template_bytes.as_ptr(),
                template_bytes.len(),
                &mut raw,
            )
        })?;
        Ok(Self { raw })
    }

    pub fn read_encrypted(
        encrypted: &[u8],
        master_keyset: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Self> {
        let (ad_ptr, ad_len) = match associated_data {
            Some(ad) => (ad.as_ptr(), ad.len()),
            None => (std::ptr::null(), 0),
        };
        let mut raw = std::ptr::null_mut();
        check_status(unsafe {
            tink_ffi_sys::tink_keyset_handle_read_encrypted(
                encrypted.as_ptr(),
                encrypted.len(),
                master_keyset.as_ptr(),
                master_keyset.len(),
                ad_ptr,
                ad_len,
                &mut raw,
            )
        })?;
        Ok(Self { raw })
    }

    pub fn write_encrypted(
        &self,
        master_keyset: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let (ad_ptr, ad_len) = match associated_data {
            Some(ad) => (ad.as_ptr(), ad.len()),
            None => (std::ptr::null(), 0),
        };
        let mut out = std::ptr::null_mut();
        let mut out_len = 0;
        check_status(unsafe {
            tink_ffi_sys::tink_keyset_handle_write_encrypted(
                self.as_raw(),
                master_keyset.as_ptr(),
                master_keyset.len(),
                ad_ptr,
                ad_len,
                &mut out,
                &mut out_len,
            )
        })?;
        Ok(unsafe { take_bytes(out, out_len) })
    }

    pub fn key_template_serialize(name: &str) -> Result<Vec<u8>> {
        let name_c = CString::new(name).expect("template name contains nul byte");
        let mut out = std::ptr::null_mut();
        let mut out_len = 0;
        check_status(unsafe {
            tink_ffi_sys::tink_key_template_serialize(name_c.as_ptr(), &mut out, &mut out_len)
        })?;
        Ok(unsafe { take_bytes(out, out_len) })
    }

    pub fn primitive<P: Primitive>(&self) -> Result<P> {
        P::from_keyset_handle(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyTemplate {
    // AEAD
    Aes128Eax,
    Aes256Eax,
    Aes128Gcm,
    Aes128GcmNoPrefix,
    Aes256Gcm,
    Aes256GcmNoPrefix,
    Aes128GcmSiv,
    Aes256GcmSiv,
    Aes128CtrHmacSha256,
    Aes256CtrHmacSha256,
    XChaCha20Poly1305,

    // Deterministic AEAD
    Aes256Siv,

    // MAC
    HmacSha256HalfSizeTag,
    HmacSha256,
    HmacSha512HalfSizeTag,
    HmacSha512,
    AesCmac,

    // Digital Signatures
    EcdsaP256,
    EcdsaP384Sha384,
    EcdsaP384Sha512,
    EcdsaP521,
    EcdsaP256Raw,
    EcdsaP256Ieee,
    EcdsaP256RawDer,
    EcdsaP384Ieee,
    EcdsaP521Ieee,
    RsaSsaPkcs13072Sha256F4,
    RsaSsaPkcs14096Sha512F4,
    RsaSsaPss3072Sha256Sha256F4,
    RsaSsaPss4096Sha512Sha512F4,
    RsaSsaPss4096Sha384Sha384F4,
    Ed25519,
    Ed25519Raw,

    // Hybrid Encryption
    EciesP256HkdfHmacSha256Aes128Gcm,
    EciesP256HkdfHmacSha512Aes128Gcm,
    EciesP256HkdfHmacSha256Aes128GcmCompressedNoPrefix,
    EciesP256HkdfHmacSha256Aes128CtrHmacSha256,
    EciesP256CompressedHkdfHmacSha256Aes128Gcm,
    EciesX25519HkdfHmacSha256Aes128Gcm,
    EciesX25519HkdfHmacSha256Aes256Gcm,
    EciesX25519HkdfHmacSha256Aes128CtrHmacSha256,
    EciesX25519HkdfHmacSha256XChaCha20Poly1305,
    EciesX25519HkdfHmacSha256DeterministicAesSiv,
    HpkeX25519HkdfSha256Aes128Gcm,
    HpkeX25519HkdfSha256Aes128GcmRaw,
    HpkeX25519HkdfSha256Aes256Gcm,
    HpkeX25519HkdfSha256Aes256GcmRaw,
    HpkeX25519HkdfSha256ChaCha20Poly1305,
    HpkeX25519HkdfSha256ChaCha20Poly1305Raw,
    HpkeP256HkdfSha256Aes128Gcm,
    HpkeP256HkdfSha256Aes128GcmRaw,

    // Streaming AEAD
    Aes128GcmHkdf4kb,
    Aes256GcmHkdf4kb,
    Aes256GcmHkdf1mb,
    Aes128CtrHmacSha256Segment4kb,
    Aes128CtrHmacSha256Segment1mb,
    Aes256CtrHmacSha256Segment4kb,
    Aes256CtrHmacSha256Segment1mb,

    // JWT MAC
    JwtHs256,
    JwtHs256Raw,
    JwtHs384,
    JwtHs384Raw,
    JwtHs512,
    JwtHs512Raw,

    // JWT Signatures
    JwtEs256,
    JwtEs256Raw,
    JwtEs384,
    JwtEs384Raw,
    JwtEs512,
    JwtEs512Raw,
    JwtRs256_2048F4,
    JwtRs256_2048F4Raw,
    JwtRs256_3072F4,
    JwtRs256_3072F4Raw,
    JwtRs384_3072F4,
    JwtRs384_3072F4Raw,
    JwtRs512_4096F4,
    JwtRs512_4096F4Raw,
    JwtPs256_2048F4,
    JwtPs256_2048F4Raw,
    JwtPs256_3072F4,
    JwtPs256_3072F4Raw,
    JwtPs384_3072F4,
    JwtPs384_3072F4Raw,
    JwtPs512_4096F4,
    JwtPs512_4096F4Raw,

    // PRF
    HkdfSha256,
    HmacSha256Prf,
    HmacSha512Prf,
    AesCmacPrf,
}

impl KeyTemplate {
    pub fn as_str(&self) -> &'static str {
        match self {
            // AEAD
            Self::Aes128Eax => "AES128_EAX",
            Self::Aes256Eax => "AES256_EAX",
            Self::Aes128Gcm => "AES128_GCM",
            Self::Aes128GcmNoPrefix => "AES128_GCM_NO_PREFIX",
            Self::Aes256Gcm => "AES256_GCM",
            Self::Aes256GcmNoPrefix => "AES256_GCM_NO_PREFIX",
            Self::Aes128GcmSiv => "AES128_GCM_SIV",
            Self::Aes256GcmSiv => "AES256_GCM_SIV",
            Self::Aes128CtrHmacSha256 => "AES128_CTR_HMAC_SHA256",
            Self::Aes256CtrHmacSha256 => "AES256_CTR_HMAC_SHA256",
            Self::XChaCha20Poly1305 => "XCHACHA20_POLY1305",

            // Deterministic AEAD
            Self::Aes256Siv => "AES256_SIV",

            // MAC
            Self::HmacSha256HalfSizeTag => "HMAC_SHA256_128BITTAG",
            Self::HmacSha256 => "HMAC_SHA256",
            Self::HmacSha512HalfSizeTag => "HMAC_SHA512_256BITTAG",
            Self::HmacSha512 => "HMAC_SHA512",
            Self::AesCmac => "AES_CMAC",

            // Digital Signatures
            Self::EcdsaP256 => "ECDSA_P256",
            Self::EcdsaP384Sha384 => "ECDSA_P384_SHA384",
            Self::EcdsaP384Sha512 => "ECDSA_P384_SHA512",
            Self::EcdsaP521 => "ECDSA_P521",
            Self::EcdsaP256Raw => "ECDSA_P256_RAW",
            Self::EcdsaP256Ieee => "ECDSA_P256_IEEE",
            Self::EcdsaP256RawDer => "ECDSA_P256_RAW_DER",
            Self::EcdsaP384Ieee => "ECDSA_P384_IEEE",
            Self::EcdsaP521Ieee => "ECDSA_P521_IEEE",
            Self::RsaSsaPkcs13072Sha256F4 => "RSA_SSA_PKCS1_3072_SHA256_F4",
            Self::RsaSsaPkcs14096Sha512F4 => "RSA_SSA_PKCS1_4096_SHA512_F4",
            Self::RsaSsaPss3072Sha256Sha256F4 => "RSA_SSA_PSS_3072_SHA256_SHA256_F4",
            Self::RsaSsaPss4096Sha512Sha512F4 => "RSA_SSA_PSS_4096_SHA512_SHA512_F4",
            Self::RsaSsaPss4096Sha384Sha384F4 => "RSA_SSA_PSS_4096_SHA384_SHA384_F4",
            Self::Ed25519 => "ED25519",
            Self::Ed25519Raw => "ED25519_RAW",

            // Hybrid Encryption
            Self::EciesP256HkdfHmacSha256Aes128Gcm => "ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
            Self::EciesP256HkdfHmacSha512Aes128Gcm => "ECIES_P256_HKDF_HMAC_SHA512_AES128_GCM",
            Self::EciesP256HkdfHmacSha256Aes128GcmCompressedNoPrefix => {
                "ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM_COMPRESSED_NO_PREFIX"
            }
            Self::EciesP256HkdfHmacSha256Aes128CtrHmacSha256 => {
                "ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256"
            }
            Self::EciesP256CompressedHkdfHmacSha256Aes128Gcm => {
                "ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM"
            }
            Self::EciesX25519HkdfHmacSha256Aes128Gcm => "ECIES_X25519_HKDF_HMAC_SHA256_AES128_GCM",
            Self::EciesX25519HkdfHmacSha256Aes256Gcm => "ECIES_X25519_HKDF_HMAC_SHA256_AES256_GCM",
            Self::EciesX25519HkdfHmacSha256Aes128CtrHmacSha256 => {
                "ECIES_X25519_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256"
            }
            Self::EciesX25519HkdfHmacSha256XChaCha20Poly1305 => {
                "ECIES_X25519_HKDF_HMAC_SHA256_XCHACHA20_POLY1305"
            }
            Self::EciesX25519HkdfHmacSha256DeterministicAesSiv => {
                "ECIES_X25519_HKDF_HMAC_SHA256_DETERMINISTIC_AES_SIV"
            }
            Self::HpkeX25519HkdfSha256Aes128Gcm => "HPKE_X25519_HKDF_SHA256_AES128_GCM",
            Self::HpkeX25519HkdfSha256Aes128GcmRaw => "HPKE_X25519_HKDF_SHA256_AES128_GCM_RAW",
            Self::HpkeX25519HkdfSha256Aes256Gcm => "HPKE_X25519_HKDF_SHA256_AES256_GCM",
            Self::HpkeX25519HkdfSha256Aes256GcmRaw => "HPKE_X25519_HKDF_SHA256_AES256_GCM_RAW",
            Self::HpkeX25519HkdfSha256ChaCha20Poly1305 => {
                "HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305"
            }
            Self::HpkeX25519HkdfSha256ChaCha20Poly1305Raw => {
                "HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305_RAW"
            }
            Self::HpkeP256HkdfSha256Aes128Gcm => "HPKE_P256_HKDF_SHA256_AES128_GCM",
            Self::HpkeP256HkdfSha256Aes128GcmRaw => "HPKE_P256_HKDF_SHA256_AES128_GCM_RAW",

            // Streaming AEAD
            Self::Aes128GcmHkdf4kb => "AES128_GCM_HKDF_4KB",
            Self::Aes256GcmHkdf4kb => "AES256_GCM_HKDF_4KB",
            Self::Aes256GcmHkdf1mb => "AES256_GCM_HKDF_1MB",
            Self::Aes128CtrHmacSha256Segment4kb => "AES128_CTR_HMAC_SHA256_4KB",
            Self::Aes128CtrHmacSha256Segment1mb => "AES128_CTR_HMAC_SHA256_1MB",
            Self::Aes256CtrHmacSha256Segment4kb => "AES256_CTR_HMAC_SHA256_4KB",
            Self::Aes256CtrHmacSha256Segment1mb => "AES256_CTR_HMAC_SHA256_1MB",

            // JWT MAC
            Self::JwtHs256 => "JWT_HS256",
            Self::JwtHs256Raw => "JWT_HS256_RAW",
            Self::JwtHs384 => "JWT_HS384",
            Self::JwtHs384Raw => "JWT_HS384_RAW",
            Self::JwtHs512 => "JWT_HS512",
            Self::JwtHs512Raw => "JWT_HS512_RAW",

            // JWT Signatures
            Self::JwtEs256 => "JWT_ES256",
            Self::JwtEs256Raw => "JWT_ES256_RAW",
            Self::JwtEs384 => "JWT_ES384",
            Self::JwtEs384Raw => "JWT_ES384_RAW",
            Self::JwtEs512 => "JWT_ES512",
            Self::JwtEs512Raw => "JWT_ES512_RAW",
            Self::JwtRs256_2048F4 => "JWT_RS256_2048_F4",
            Self::JwtRs256_2048F4Raw => "JWT_RS256_2048_F4_RAW",
            Self::JwtRs256_3072F4 => "JWT_RS256_3072_F4",
            Self::JwtRs256_3072F4Raw => "JWT_RS256_3072_F4_RAW",
            Self::JwtRs384_3072F4 => "JWT_RS384_3072_F4",
            Self::JwtRs384_3072F4Raw => "JWT_RS384_3072_F4_RAW",
            Self::JwtRs512_4096F4 => "JWT_RS512_4096_F4",
            Self::JwtRs512_4096F4Raw => "JWT_RS512_4096_F4_RAW",
            Self::JwtPs256_2048F4 => "JWT_PS256_2048_F4",
            Self::JwtPs256_2048F4Raw => "JWT_PS256_2048_F4_RAW",
            Self::JwtPs256_3072F4 => "JWT_PS256_3072_F4",
            Self::JwtPs256_3072F4Raw => "JWT_PS256_3072_F4_RAW",
            Self::JwtPs384_3072F4 => "JWT_PS384_3072_F4",
            Self::JwtPs384_3072F4Raw => "JWT_PS384_3072_F4_RAW",
            Self::JwtPs512_4096F4 => "JWT_PS512_4096_F4",
            Self::JwtPs512_4096F4Raw => "JWT_PS512_4096_F4_RAW",

            // PRF
            Self::HkdfSha256 => "HKDF_SHA256",
            Self::HmacSha256Prf => "HMAC_SHA256_PRF",
            Self::HmacSha512Prf => "HMAC_SHA512_PRF",
            Self::AesCmacPrf => "AES_CMAC_PRF",
        }
    }
}

impl fmt::Display for KeyTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
