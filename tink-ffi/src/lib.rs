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

mod aead;
mod deterministic_aead;
mod error;
mod hybrid;
mod jwt;
mod key_derivation;
mod keyset;
mod mac;
mod prf;
mod signature;
mod streaming_aead;

pub use error::{Result, TinkError};
pub use keyset::{KeyTemplate, KeysetHandle};

pub use aead::{Aead, AeadPrimitive};
pub use deterministic_aead::{DeterministicAead, DeterministicAeadPrimitive};
pub use hybrid::{HybridDecrypt, HybridDecryptPrimitive, HybridEncrypt, HybridEncryptPrimitive};
pub use jwt::{
    JwtMac, JwtMacPrimitive, JwtSign, JwtSignerPrimitive, JwtValidator, JwtVerifierPrimitive,
    JwtVerify, RawJwt, VerifiedJwt,
};
pub use key_derivation::{KeysetDeriver, KeysetDeriverPrimitive};
pub use mac::{Mac, MacPrimitive};
pub use prf::{PrfSet, PrfSetPrimitive};
pub use signature::{Signer, SignerPrimitive, Verifier, VerifierPrimitive};
pub use streaming_aead::{
    DecryptingReader, EncryptingWriter, StreamingAead, StreamingAeadPrimitive,
};

mod sealed {
    pub trait Sealed {}
}

pub trait Primitive: sealed::Sealed {
    fn from_keyset_handle(handle: &KeysetHandle) -> Result<Self>
    where
        Self: Sized;
}

/// Initialize the Tink library. Must be called before any other operations.
pub fn register_all() -> Result<()> {
    error::check_status(unsafe { tink_ffi_sys::tink_register_all() })
}
