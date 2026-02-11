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

use std::io::{self, Read, Write};

use tonic::{Request, Response, Status};

use tink_ffi::{KeysetHandle, StreamingAead, StreamingAeadPrimitive};

use crate::proto::{
    streaming_aead_decrypt_response, streaming_aead_encrypt_response, streaming_aead_server,
    CreationRequest, CreationResponse, StreamingAeadDecryptRequest, StreamingAeadDecryptResponse,
    StreamingAeadEncryptRequest, StreamingAeadEncryptResponse,
};

pub struct StreamingAeadServiceImpl;

fn streaming_encrypt(
    keyset: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, tink_ffi::TinkError> {
    let handle = KeysetHandle::from_binary(keyset)?;
    let saead = handle.primitive::<StreamingAeadPrimitive>()?;
    let mut ct_buf = Vec::new();
    let mut writer = saead.new_encrypting_writer(&mut ct_buf, aad)?;
    writer
        .write_all(plaintext)
        .map_err(|e| tink_ffi::TinkError {
            message: format!("write failed: {e}"),
            code: -1,
        })?;
    writer.finalize()?;
    Ok(ct_buf)
}

fn streaming_decrypt(
    keyset: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, tink_ffi::TinkError> {
    let handle = KeysetHandle::from_binary(keyset)?;
    let saead = handle.primitive::<StreamingAeadPrimitive>()?;
    let cursor = io::Cursor::new(ciphertext);
    let mut reader = saead.new_decrypting_reader(cursor, aad)?;
    let mut pt = Vec::new();
    reader
        .read_to_end(&mut pt)
        .map_err(|e| tink_ffi::TinkError {
            message: format!("read failed: {e}"),
            code: -1,
        })?;
    Ok(pt)
}

#[tonic::async_trait]
impl streaming_aead_server::StreamingAead for StreamingAeadServiceImpl {
    async fn create(
        &self,
        request: Request<CreationRequest>,
    ) -> Result<Response<CreationResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        match KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<StreamingAeadPrimitive>())
        {
            Ok(_) => Ok(Response::new(CreationResponse { err: String::new() })),
            Err(e) => Ok(Response::new(CreationResponse { err: e.message })),
        }
    }

    async fn encrypt(
        &self,
        request: Request<StreamingAeadEncryptRequest>,
    ) -> Result<Response<StreamingAeadEncryptResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        match streaming_encrypt(&ak.serialized_keyset, &req.plaintext, &req.associated_data) {
            Ok(ct) => Ok(Response::new(StreamingAeadEncryptResponse {
                result: Some(streaming_aead_encrypt_response::Result::Ciphertext(ct)),
            })),
            Err(e) => Ok(Response::new(StreamingAeadEncryptResponse {
                result: Some(streaming_aead_encrypt_response::Result::Err(e.message)),
            })),
        }
    }

    async fn decrypt(
        &self,
        request: Request<StreamingAeadDecryptRequest>,
    ) -> Result<Response<StreamingAeadDecryptResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        match streaming_decrypt(&ak.serialized_keyset, &req.ciphertext, &req.associated_data) {
            Ok(pt) => Ok(Response::new(StreamingAeadDecryptResponse {
                result: Some(streaming_aead_decrypt_response::Result::Plaintext(pt)),
            })),
            Err(e) => Ok(Response::new(StreamingAeadDecryptResponse {
                result: Some(streaming_aead_decrypt_response::Result::Err(e.message)),
            })),
        }
    }
}
