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

use tink_ffi::{KeysetHandle, Mac, MacPrimitive};

use crate::proto::{
    compute_mac_response, mac_server, ComputeMacRequest, ComputeMacResponse, CreationRequest,
    CreationResponse, VerifyMacRequest, VerifyMacResponse,
};

pub struct MacServiceImpl;

#[tonic::async_trait]
impl mac_server::Mac for MacServiceImpl {
    async fn create(
        &self,
        request: Request<CreationRequest>,
    ) -> Result<Response<CreationResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        match KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<MacPrimitive>())
        {
            Ok(_) => Ok(Response::new(CreationResponse { err: String::new() })),
            Err(e) => Ok(Response::new(CreationResponse { err: e.message })),
        }
    }

    async fn compute_mac(
        &self,
        request: Request<ComputeMacRequest>,
    ) -> Result<Response<ComputeMacResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        let result = KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<MacPrimitive>())
            .and_then(|m| m.compute(&req.data));
        match result {
            Ok(mac_value) => Ok(Response::new(ComputeMacResponse {
                result: Some(compute_mac_response::Result::MacValue(mac_value)),
            })),
            Err(e) => Ok(Response::new(ComputeMacResponse {
                result: Some(compute_mac_response::Result::Err(e.message)),
            })),
        }
    }

    async fn verify_mac(
        &self,
        request: Request<VerifyMacRequest>,
    ) -> Result<Response<VerifyMacResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        let result = KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<MacPrimitive>())
            .and_then(|m| m.verify(&req.mac_value, &req.data));
        match result {
            Ok(()) => Ok(Response::new(VerifyMacResponse { err: String::new() })),
            Err(e) => Ok(Response::new(VerifyMacResponse { err: e.message })),
        }
    }
}
