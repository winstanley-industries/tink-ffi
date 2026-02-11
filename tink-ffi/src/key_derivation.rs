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

use crate::error::{check_status, Result};
use crate::keyset::KeysetHandle;
use crate::sealed;

pub trait KeysetDeriver {
    fn derive(&self, salt: &[u8]) -> Result<KeysetHandle>;
}

pub struct KeysetDeriverPrimitive {
    raw: *mut tink_ffi_sys::TinkKeysetDeriver,
}

unsafe impl Send for KeysetDeriverPrimitive {}
unsafe impl Sync for KeysetDeriverPrimitive {}

impl Drop for KeysetDeriverPrimitive {
    fn drop(&mut self) {
        unsafe { tink_ffi_sys::tink_keyset_deriver_free(self.raw) }
    }
}

impl sealed::Sealed for KeysetDeriverPrimitive {}

impl crate::Primitive for KeysetDeriverPrimitive {
    fn from_keyset_handle(handle: &KeysetHandle) -> Result<Self> {
        let mut raw = std::ptr::null_mut();
        check_status(unsafe { tink_ffi_sys::tink_keyset_deriver_new(handle.as_raw(), &mut raw) })?;
        Ok(Self { raw })
    }
}

impl KeysetDeriver for KeysetDeriverPrimitive {
    fn derive(&self, salt: &[u8]) -> Result<KeysetHandle> {
        let mut derived = std::ptr::null_mut();
        check_status(unsafe {
            tink_ffi_sys::tink_keyset_deriver_derive(
                self.raw,
                salt.as_ptr(),
                salt.len(),
                &mut derived,
            )
        })?;
        Ok(KeysetHandle::from_raw(derived))
    }
}
