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

use tink_ffi::KeysetHandle;

use crate::proto::{
    keyset_from_json_response, keyset_generate_response, keyset_public_response,
    keyset_read_encrypted_response, keyset_server::Keyset, keyset_template_response,
    keyset_to_json_response, keyset_write_encrypted_response, KeysetFromJsonRequest,
    KeysetFromJsonResponse, KeysetGenerateRequest, KeysetGenerateResponse, KeysetPublicRequest,
    KeysetPublicResponse, KeysetReadEncryptedRequest, KeysetReadEncryptedResponse,
    KeysetTemplateRequest, KeysetTemplateResponse, KeysetToJsonRequest, KeysetToJsonResponse,
    KeysetWriteEncryptedRequest, KeysetWriteEncryptedResponse,
};

pub struct KeysetServiceImpl;

#[tonic::async_trait]
impl Keyset for KeysetServiceImpl {
    async fn get_template(
        &self,
        request: Request<KeysetTemplateRequest>,
    ) -> Result<Response<KeysetTemplateResponse>, Status> {
        let req = request.into_inner();
        match KeysetHandle::key_template_serialize(&req.template_name) {
            Ok(bytes) => Ok(Response::new(KeysetTemplateResponse {
                result: Some(keyset_template_response::Result::KeyTemplate(bytes)),
            })),
            Err(e) => Ok(Response::new(KeysetTemplateResponse {
                result: Some(keyset_template_response::Result::Err(e.message)),
            })),
        }
    }

    async fn generate(
        &self,
        request: Request<KeysetGenerateRequest>,
    ) -> Result<Response<KeysetGenerateResponse>, Status> {
        let req = request.into_inner();
        let result =
            KeysetHandle::generate_from_template_bytes(&req.template).and_then(|h| h.to_binary());
        match result {
            Ok(keyset) => Ok(Response::new(KeysetGenerateResponse {
                result: Some(keyset_generate_response::Result::Keyset(keyset)),
            })),
            Err(e) => Ok(Response::new(KeysetGenerateResponse {
                result: Some(keyset_generate_response::Result::Err(e.message)),
            })),
        }
    }

    async fn public(
        &self,
        request: Request<KeysetPublicRequest>,
    ) -> Result<Response<KeysetPublicResponse>, Status> {
        let req = request.into_inner();
        let result = KeysetHandle::from_binary(&req.private_keyset)
            .and_then(|h| h.public_handle())
            .and_then(|h| h.to_binary());
        match result {
            Ok(keyset) => Ok(Response::new(KeysetPublicResponse {
                result: Some(keyset_public_response::Result::PublicKeyset(keyset)),
            })),
            Err(e) => Ok(Response::new(KeysetPublicResponse {
                result: Some(keyset_public_response::Result::Err(e.message)),
            })),
        }
    }

    async fn to_json(
        &self,
        request: Request<KeysetToJsonRequest>,
    ) -> Result<Response<KeysetToJsonResponse>, Status> {
        let req = request.into_inner();
        let result = KeysetHandle::from_binary(&req.keyset).and_then(|h| h.to_json());
        match result {
            Ok(json) => Ok(Response::new(KeysetToJsonResponse {
                result: Some(keyset_to_json_response::Result::JsonKeyset(json)),
            })),
            Err(e) => Ok(Response::new(KeysetToJsonResponse {
                result: Some(keyset_to_json_response::Result::Err(e.message)),
            })),
        }
    }

    async fn from_json(
        &self,
        request: Request<KeysetFromJsonRequest>,
    ) -> Result<Response<KeysetFromJsonResponse>, Status> {
        let req = request.into_inner();
        let result = KeysetHandle::from_json(&req.json_keyset).and_then(|h| h.to_binary());
        match result {
            Ok(keyset) => Ok(Response::new(KeysetFromJsonResponse {
                result: Some(keyset_from_json_response::Result::Keyset(keyset)),
            })),
            Err(e) => Ok(Response::new(KeysetFromJsonResponse {
                result: Some(keyset_from_json_response::Result::Err(e.message)),
            })),
        }
    }

    async fn read_encrypted(
        &self,
        request: Request<KeysetReadEncryptedRequest>,
    ) -> Result<Response<KeysetReadEncryptedResponse>, Status> {
        let req = request.into_inner();
        let ad = req.associated_data.map(|v| v.value);
        let result =
            KeysetHandle::read_encrypted(&req.encrypted_keyset, &req.master_keyset, ad.as_deref())
                .and_then(|h| h.to_binary());
        match result {
            Ok(keyset) => Ok(Response::new(KeysetReadEncryptedResponse {
                result: Some(keyset_read_encrypted_response::Result::Keyset(keyset)),
            })),
            Err(e) => Ok(Response::new(KeysetReadEncryptedResponse {
                result: Some(keyset_read_encrypted_response::Result::Err(e.message)),
            })),
        }
    }

    async fn write_encrypted(
        &self,
        request: Request<KeysetWriteEncryptedRequest>,
    ) -> Result<Response<KeysetWriteEncryptedResponse>, Status> {
        let req = request.into_inner();
        let ad = req.associated_data.map(|v| v.value);
        let result = KeysetHandle::from_binary(&req.keyset)
            .and_then(|h| h.write_encrypted(&req.master_keyset, ad.as_deref()));
        match result {
            Ok(encrypted) => Ok(Response::new(KeysetWriteEncryptedResponse {
                result: Some(keyset_write_encrypted_response::Result::EncryptedKeyset(
                    encrypted,
                )),
            })),
            Err(e) => Ok(Response::new(KeysetWriteEncryptedResponse {
                result: Some(keyset_write_encrypted_response::Result::Err(e.message)),
            })),
        }
    }
}
