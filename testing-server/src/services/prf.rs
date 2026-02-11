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

use tink_ffi::{KeysetHandle, PrfSet, PrfSetPrimitive};

use crate::proto::{
    prf_set_compute_response, prf_set_key_ids_response, prf_set_server, CreationRequest,
    CreationResponse, PrfSetComputeRequest, PrfSetComputeResponse, PrfSetKeyIdsRequest,
    PrfSetKeyIdsResponse,
};

pub struct PrfSetServiceImpl;

#[tonic::async_trait]
impl prf_set_server::PrfSet for PrfSetServiceImpl {
    async fn create(
        &self,
        request: Request<CreationRequest>,
    ) -> Result<Response<CreationResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        match KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<PrfSetPrimitive>())
        {
            Ok(_) => Ok(Response::new(CreationResponse { err: String::new() })),
            Err(e) => Ok(Response::new(CreationResponse { err: e.message })),
        }
    }

    async fn key_ids(
        &self,
        request: Request<PrfSetKeyIdsRequest>,
    ) -> Result<Response<PrfSetKeyIdsResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        let result = KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<PrfSetPrimitive>())
            .and_then(|prf| {
                let primary_id = prf.primary_id()?;
                let key_ids = prf.key_ids()?;
                Ok((primary_id, key_ids))
            });
        match result {
            Ok((primary_id, key_ids)) => Ok(Response::new(PrfSetKeyIdsResponse {
                result: Some(prf_set_key_ids_response::Result::Output(
                    prf_set_key_ids_response::Output {
                        primary_key_id: primary_id,
                        key_id: key_ids,
                    },
                )),
            })),
            Err(e) => Ok(Response::new(PrfSetKeyIdsResponse {
                result: Some(prf_set_key_ids_response::Result::Err(e.message)),
            })),
        }
    }

    async fn compute(
        &self,
        request: Request<PrfSetComputeRequest>,
    ) -> Result<Response<PrfSetComputeResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        let result = KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<PrfSetPrimitive>())
            .and_then(|prf| prf.compute(req.key_id, &req.input_data, req.output_length as usize));
        match result {
            Ok(output) => Ok(Response::new(PrfSetComputeResponse {
                result: Some(prf_set_compute_response::Result::Output(output)),
            })),
            Err(e) => Ok(Response::new(PrfSetComputeResponse {
                result: Some(prf_set_compute_response::Result::Err(e.message)),
            })),
        }
    }
}
