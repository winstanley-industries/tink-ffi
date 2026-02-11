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

use tink_ffi::{
    HybridDecrypt, HybridDecryptPrimitive, HybridEncrypt, HybridEncryptPrimitive, KeysetHandle,
};

use crate::proto::{
    hybrid_decrypt_response, hybrid_encrypt_response, hybrid_server::Hybrid, CreationRequest,
    CreationResponse, HybridDecryptRequest, HybridDecryptResponse, HybridEncryptRequest,
    HybridEncryptResponse,
};

pub struct HybridServiceImpl;

#[tonic::async_trait]
impl Hybrid for HybridServiceImpl {
    async fn create_hybrid_encrypt(
        &self,
        request: Request<CreationRequest>,
    ) -> Result<Response<CreationResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        match KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<HybridEncryptPrimitive>())
        {
            Ok(_) => Ok(Response::new(CreationResponse { err: String::new() })),
            Err(e) => Ok(Response::new(CreationResponse { err: e.message })),
        }
    }

    async fn create_hybrid_decrypt(
        &self,
        request: Request<CreationRequest>,
    ) -> Result<Response<CreationResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        match KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<HybridDecryptPrimitive>())
        {
            Ok(_) => Ok(Response::new(CreationResponse { err: String::new() })),
            Err(e) => Ok(Response::new(CreationResponse { err: e.message })),
        }
    }

    async fn encrypt(
        &self,
        request: Request<HybridEncryptRequest>,
    ) -> Result<Response<HybridEncryptResponse>, Status> {
        let req = request.into_inner();
        let ak = req.public_annotated_keyset.as_ref().unwrap();
        let result = KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<HybridEncryptPrimitive>())
            .and_then(|enc| enc.encrypt(&req.plaintext, &req.context_info));
        match result {
            Ok(ct) => Ok(Response::new(HybridEncryptResponse {
                result: Some(hybrid_encrypt_response::Result::Ciphertext(ct)),
            })),
            Err(e) => Ok(Response::new(HybridEncryptResponse {
                result: Some(hybrid_encrypt_response::Result::Err(e.message)),
            })),
        }
    }

    async fn decrypt(
        &self,
        request: Request<HybridDecryptRequest>,
    ) -> Result<Response<HybridDecryptResponse>, Status> {
        let req = request.into_inner();
        let ak = req.private_annotated_keyset.as_ref().unwrap();
        let result = KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<HybridDecryptPrimitive>())
            .and_then(|dec| dec.decrypt(&req.ciphertext, &req.context_info));
        match result {
            Ok(pt) => Ok(Response::new(HybridDecryptResponse {
                result: Some(hybrid_decrypt_response::Result::Plaintext(pt)),
            })),
            Err(e) => Ok(Response::new(HybridDecryptResponse {
                result: Some(hybrid_decrypt_response::Result::Err(e.message)),
            })),
        }
    }
}
