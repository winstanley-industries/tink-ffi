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

use tonic::{Request, Response, Status};

use tink_ffi::{KeysetDeriver, KeysetDeriverPrimitive, KeysetHandle};

use crate::proto::{
    derive_keyset_response, keyset_deriver_server, CreationRequest, CreationResponse,
    DeriveKeysetRequest, DeriveKeysetResponse,
};

pub struct KeysetDeriverServiceImpl;

#[tonic::async_trait]
impl keyset_deriver_server::KeysetDeriver for KeysetDeriverServiceImpl {
    async fn create(
        &self,
        request: Request<CreationRequest>,
    ) -> Result<Response<CreationResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        match KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<KeysetDeriverPrimitive>())
        {
            Ok(_) => Ok(Response::new(CreationResponse { err: String::new() })),
            Err(e) => Ok(Response::new(CreationResponse { err: e.message })),
        }
    }

    async fn derive_keyset(
        &self,
        request: Request<DeriveKeysetRequest>,
    ) -> Result<Response<DeriveKeysetResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        let result = KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<KeysetDeriverPrimitive>())
            .and_then(|d| d.derive(&req.salt))
            .and_then(|derived| derived.to_binary());
        match result {
            Ok(keyset) => Ok(Response::new(DeriveKeysetResponse {
                result: Some(derive_keyset_response::Result::DerivedKeyset(keyset)),
            })),
            Err(e) => Ok(Response::new(DeriveKeysetResponse {
                result: Some(derive_keyset_response::Result::Err(e.message)),
            })),
        }
    }
}
