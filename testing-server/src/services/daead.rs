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

use tink_ffi::{DeterministicAead, DeterministicAeadPrimitive, KeysetHandle};

use crate::proto::{
    deterministic_aead_decrypt_response, deterministic_aead_encrypt_response,
    deterministic_aead_server, CreationRequest, CreationResponse, DeterministicAeadDecryptRequest,
    DeterministicAeadDecryptResponse, DeterministicAeadEncryptRequest,
    DeterministicAeadEncryptResponse,
};

pub struct DeterministicAeadServiceImpl;

#[tonic::async_trait]
impl deterministic_aead_server::DeterministicAead for DeterministicAeadServiceImpl {
    async fn create(
        &self,
        request: Request<CreationRequest>,
    ) -> Result<Response<CreationResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        match KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<DeterministicAeadPrimitive>())
        {
            Ok(_) => Ok(Response::new(CreationResponse { err: String::new() })),
            Err(e) => Ok(Response::new(CreationResponse { err: e.message })),
        }
    }

    async fn encrypt_deterministically(
        &self,
        request: Request<DeterministicAeadEncryptRequest>,
    ) -> Result<Response<DeterministicAeadEncryptResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        let result = KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<DeterministicAeadPrimitive>())
            .and_then(|d| d.encrypt_deterministically(&req.plaintext, &req.associated_data));
        match result {
            Ok(ct) => Ok(Response::new(DeterministicAeadEncryptResponse {
                result: Some(deterministic_aead_encrypt_response::Result::Ciphertext(ct)),
            })),
            Err(e) => Ok(Response::new(DeterministicAeadEncryptResponse {
                result: Some(deterministic_aead_encrypt_response::Result::Err(e.message)),
            })),
        }
    }

    async fn decrypt_deterministically(
        &self,
        request: Request<DeterministicAeadDecryptRequest>,
    ) -> Result<Response<DeterministicAeadDecryptResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        let result = KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<DeterministicAeadPrimitive>())
            .and_then(|d| d.decrypt_deterministically(&req.ciphertext, &req.associated_data));
        match result {
            Ok(pt) => Ok(Response::new(DeterministicAeadDecryptResponse {
                result: Some(deterministic_aead_decrypt_response::Result::Plaintext(pt)),
            })),
            Err(e) => Ok(Response::new(DeterministicAeadDecryptResponse {
                result: Some(deterministic_aead_decrypt_response::Result::Err(e.message)),
            })),
        }
    }
}
