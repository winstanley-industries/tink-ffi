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

use tink_ffi::{KeysetHandle, Signer, SignerPrimitive, Verifier, VerifierPrimitive};

use crate::proto::{
    signature_server::Signature, signature_sign_response, CreationRequest, CreationResponse,
    SignatureSignRequest, SignatureSignResponse, SignatureVerifyRequest, SignatureVerifyResponse,
};

pub struct SignatureServiceImpl;

#[tonic::async_trait]
impl Signature for SignatureServiceImpl {
    async fn create_public_key_sign(
        &self,
        request: Request<CreationRequest>,
    ) -> Result<Response<CreationResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        match KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<SignerPrimitive>())
        {
            Ok(_) => Ok(Response::new(CreationResponse { err: String::new() })),
            Err(e) => Ok(Response::new(CreationResponse { err: e.message })),
        }
    }

    async fn create_public_key_verify(
        &self,
        request: Request<CreationRequest>,
    ) -> Result<Response<CreationResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        match KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<VerifierPrimitive>())
        {
            Ok(_) => Ok(Response::new(CreationResponse { err: String::new() })),
            Err(e) => Ok(Response::new(CreationResponse { err: e.message })),
        }
    }

    async fn sign(
        &self,
        request: Request<SignatureSignRequest>,
    ) -> Result<Response<SignatureSignResponse>, Status> {
        let req = request.into_inner();
        let ak = req.private_annotated_keyset.as_ref().unwrap();
        let result = KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<SignerPrimitive>())
            .and_then(|s| s.sign(&req.data));
        match result {
            Ok(sig) => Ok(Response::new(SignatureSignResponse {
                result: Some(signature_sign_response::Result::Signature(sig)),
            })),
            Err(e) => Ok(Response::new(SignatureSignResponse {
                result: Some(signature_sign_response::Result::Err(e.message)),
            })),
        }
    }

    async fn verify(
        &self,
        request: Request<SignatureVerifyRequest>,
    ) -> Result<Response<SignatureVerifyResponse>, Status> {
        let req = request.into_inner();
        let ak = req.public_annotated_keyset.as_ref().unwrap();
        let result = KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<VerifierPrimitive>())
            .and_then(|v| v.verify(&req.signature, &req.data));
        match result {
            Ok(()) => Ok(Response::new(SignatureVerifyResponse {
                err: String::new(),
            })),
            Err(e) => Ok(Response::new(SignatureVerifyResponse { err: e.message })),
        }
    }
}
