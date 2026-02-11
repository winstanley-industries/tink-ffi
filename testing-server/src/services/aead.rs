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

use tink_ffi::{Aead, AeadPrimitive, KeysetHandle};

use crate::proto::{
    aead_decrypt_response, aead_encrypt_response, aead_server, AeadDecryptRequest,
    AeadDecryptResponse, AeadEncryptRequest, AeadEncryptResponse, CreationRequest,
    CreationResponse,
};

pub struct AeadServiceImpl;

fn keyset_from_creation(req: &CreationRequest) -> Result<KeysetHandle, String> {
    let ak = req
        .annotated_keyset
        .as_ref()
        .ok_or("missing annotated_keyset")?;
    KeysetHandle::from_binary(&ak.serialized_keyset).map_err(|e| e.message)
}

fn get_aead(req: &CreationRequest) -> Result<AeadPrimitive, String> {
    let handle = keyset_from_creation(req)?;
    handle.primitive::<AeadPrimitive>().map_err(|e| e.message)
}

#[tonic::async_trait]
impl aead_server::Aead for AeadServiceImpl {
    async fn create(
        &self,
        request: Request<CreationRequest>,
    ) -> Result<Response<CreationResponse>, Status> {
        let req = request.into_inner();
        match get_aead(&req) {
            Ok(_) => Ok(Response::new(CreationResponse { err: String::new() })),
            Err(e) => Ok(Response::new(CreationResponse { err: e })),
        }
    }

    async fn encrypt(
        &self,
        request: Request<AeadEncryptRequest>,
    ) -> Result<Response<AeadEncryptResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        let result = KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<AeadPrimitive>())
            .and_then(|aead| aead.encrypt(&req.plaintext, &req.associated_data));
        match result {
            Ok(ct) => Ok(Response::new(AeadEncryptResponse {
                result: Some(aead_encrypt_response::Result::Ciphertext(ct)),
            })),
            Err(e) => Ok(Response::new(AeadEncryptResponse {
                result: Some(aead_encrypt_response::Result::Err(e.message)),
            })),
        }
    }

    async fn decrypt(
        &self,
        request: Request<AeadDecryptRequest>,
    ) -> Result<Response<AeadDecryptResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        let result = KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<AeadPrimitive>())
            .and_then(|aead| aead.decrypt(&req.ciphertext, &req.associated_data));
        match result {
            Ok(pt) => Ok(Response::new(AeadDecryptResponse {
                result: Some(aead_decrypt_response::Result::Plaintext(pt)),
            })),
            Err(e) => Ok(Response::new(AeadDecryptResponse {
                result: Some(aead_decrypt_response::Result::Err(e.message)),
            })),
        }
    }
}
