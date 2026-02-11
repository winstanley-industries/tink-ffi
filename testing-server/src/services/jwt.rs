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
    JwtMac, JwtMacPrimitive, JwtSign, JwtSignerPrimitive, JwtVerifierPrimitive, JwtVerify,
    KeysetHandle, RawJwt,
};

use crate::proto::{
    jwt_from_jwk_set_response, jwt_server::Jwt, jwt_sign_response, jwt_to_jwk_set_response,
    jwt_verify_response, CreationRequest, CreationResponse, JwtClaimValue, JwtFromJwkSetRequest,
    JwtFromJwkSetResponse, JwtSignRequest, JwtSignResponse, JwtToJwkSetRequest,
    JwtToJwkSetResponse, JwtToken, JwtValidator, JwtVerifyRequest, JwtVerifyResponse,
};

/// Convert a proto JwtToken to the JSON format our FFI expects.
fn jwt_token_to_json(token: &JwtToken) -> serde_json::Value {
    let mut claims = serde_json::Map::new();

    if let Some(ref iss) = token.issuer {
        claims.insert("iss".into(), serde_json::Value::String(iss.clone()));
    }
    if let Some(ref sub) = token.subject {
        claims.insert("sub".into(), serde_json::Value::String(sub.clone()));
    }
    if !token.audiences.is_empty() {
        if token.audiences.len() == 1 {
            claims.insert(
                "aud".into(),
                serde_json::Value::String(token.audiences[0].clone()),
            );
        } else {
            claims.insert(
                "aud".into(),
                serde_json::Value::Array(
                    token
                        .audiences
                        .iter()
                        .map(|a| serde_json::Value::String(a.clone()))
                        .collect(),
                ),
            );
        }
    }
    if let Some(ref jti) = token.jwt_id {
        claims.insert("jti".into(), serde_json::Value::String(jti.clone()));
    }
    if let Some(ref exp) = token.expiration {
        claims.insert("exp".into(), serde_json::json!(exp.seconds));
    }
    if let Some(ref nbf) = token.not_before {
        claims.insert("nbf".into(), serde_json::json!(nbf.seconds));
    }
    if let Some(ref iat) = token.issued_at {
        claims.insert("iat".into(), serde_json::json!(iat.seconds));
    }

    for (key, value) in &token.custom_claims {
        if let Some(ref kind) = value.kind {
            let json_val = match kind {
                crate::proto::jwt_claim_value::Kind::NullValue(_) => serde_json::Value::Null,
                crate::proto::jwt_claim_value::Kind::NumberValue(n) => serde_json::json!(n),
                crate::proto::jwt_claim_value::Kind::StringValue(s) => {
                    serde_json::Value::String(s.clone())
                }
                crate::proto::jwt_claim_value::Kind::BoolValue(b) => serde_json::json!(b),
                crate::proto::jwt_claim_value::Kind::JsonObjectValue(s) => {
                    serde_json::from_str(s).unwrap_or(serde_json::Value::Null)
                }
                crate::proto::jwt_claim_value::Kind::JsonArrayValue(s) => {
                    serde_json::from_str(s).unwrap_or(serde_json::Value::Null)
                }
            };
            claims.insert(key.clone(), json_val);
        }
    }

    if let Some(ref type_header) = token.type_header {
        claims.insert(
            "type_header".into(),
            serde_json::Value::String(type_header.clone()),
        );
    }

    serde_json::Value::Object(claims)
}

/// Convert a proto JwtValidator to the JSON format our FFI expects.
fn jwt_validator_to_json(v: &JwtValidator) -> serde_json::Value {
    let mut config = serde_json::Map::new();

    if let Some(ref expected_type) = v.expected_type_header {
        config.insert(
            "expected_type_header".into(),
            serde_json::Value::String(expected_type.clone()),
        );
    }
    if let Some(ref expected_issuer) = v.expected_issuer {
        config.insert(
            "expected_issuer".into(),
            serde_json::Value::String(expected_issuer.clone()),
        );
    }
    if let Some(ref expected_audience) = v.expected_audience {
        config.insert(
            "expected_audience".into(),
            serde_json::Value::String(expected_audience.clone()),
        );
    }
    if v.ignore_type_header {
        config.insert("ignore_type_header".into(), serde_json::json!(true));
    }
    if v.ignore_issuer {
        config.insert("ignore_issuer".into(), serde_json::json!(true));
    }
    if v.ignore_audience {
        config.insert("ignore_audiences".into(), serde_json::json!(true));
    }
    if v.allow_missing_expiration {
        config.insert("allow_missing_expiration".into(), serde_json::json!(true));
    }
    if v.expect_issued_in_the_past {
        config.insert("expect_issued_in_the_past".into(), serde_json::json!(true));
    }
    if let Some(ref now) = v.now {
        config.insert("now_seconds".into(), serde_json::json!(now.seconds));
    }
    if let Some(ref clock_skew) = v.clock_skew {
        config.insert(
            "clock_skew_seconds".into(),
            serde_json::json!(clock_skew.seconds),
        );
    }

    serde_json::Value::Object(config)
}

/// Convert verified JWT claims JSON back to a proto JwtToken.
fn json_to_jwt_token(claims: &serde_json::Value) -> JwtToken {
    let obj = claims.as_object();

    let issuer = obj
        .and_then(|o| o.get("iss"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let subject = obj
        .and_then(|o| o.get("sub"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let audiences = if let Some(aud) = obj.and_then(|o| o.get("aud")) {
        match aud {
            serde_json::Value::String(s) => vec![s.clone()],
            serde_json::Value::Array(arr) => arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            _ => vec![],
        }
    } else {
        vec![]
    };

    let jwt_id = obj
        .and_then(|o| o.get("jti"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let expiration = obj
        .and_then(|o| o.get("exp"))
        .and_then(|v| v.as_i64())
        .map(|s| prost_types::Timestamp {
            seconds: s,
            nanos: 0,
        });

    let not_before = obj
        .and_then(|o| o.get("nbf"))
        .and_then(|v| v.as_i64())
        .map(|s| prost_types::Timestamp {
            seconds: s,
            nanos: 0,
        });

    let issued_at = obj
        .and_then(|o| o.get("iat"))
        .and_then(|v| v.as_i64())
        .map(|s| prost_types::Timestamp {
            seconds: s,
            nanos: 0,
        });

    let type_header = obj
        .and_then(|o| o.get("type_header"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let known_keys = [
        "iss",
        "sub",
        "aud",
        "jti",
        "exp",
        "nbf",
        "iat",
        "type_header",
    ];
    let mut custom_claims = std::collections::HashMap::new();
    if let Some(o) = obj {
        for (k, v) in o {
            if known_keys.contains(&k.as_str()) {
                continue;
            }
            let claim_value = match v {
                serde_json::Value::Null => JwtClaimValue {
                    kind: Some(crate::proto::jwt_claim_value::Kind::NullValue(0)),
                },
                serde_json::Value::Bool(b) => JwtClaimValue {
                    kind: Some(crate::proto::jwt_claim_value::Kind::BoolValue(*b)),
                },
                serde_json::Value::Number(n) => JwtClaimValue {
                    kind: Some(crate::proto::jwt_claim_value::Kind::NumberValue(
                        n.as_f64().unwrap_or(0.0),
                    )),
                },
                serde_json::Value::String(s) => JwtClaimValue {
                    kind: Some(crate::proto::jwt_claim_value::Kind::StringValue(s.clone())),
                },
                serde_json::Value::Array(_) => JwtClaimValue {
                    kind: Some(crate::proto::jwt_claim_value::Kind::JsonArrayValue(
                        serde_json::to_string(v).unwrap_or_default(),
                    )),
                },
                serde_json::Value::Object(_) => JwtClaimValue {
                    kind: Some(crate::proto::jwt_claim_value::Kind::JsonObjectValue(
                        serde_json::to_string(v).unwrap_or_default(),
                    )),
                },
            };
            custom_claims.insert(k.clone(), claim_value);
        }
    }

    JwtToken {
        issuer,
        subject,
        audiences,
        jwt_id,
        expiration,
        not_before,
        issued_at,
        custom_claims,
        type_header,
    }
}

pub struct JwtServiceImpl;

#[tonic::async_trait]
impl Jwt for JwtServiceImpl {
    async fn create_jwt_mac(
        &self,
        request: Request<CreationRequest>,
    ) -> Result<Response<CreationResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        match KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<JwtMacPrimitive>())
        {
            Ok(_) => Ok(Response::new(CreationResponse { err: String::new() })),
            Err(e) => Ok(Response::new(CreationResponse { err: e.message })),
        }
    }

    async fn create_jwt_public_key_sign(
        &self,
        request: Request<CreationRequest>,
    ) -> Result<Response<CreationResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        match KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<JwtSignerPrimitive>())
        {
            Ok(_) => Ok(Response::new(CreationResponse { err: String::new() })),
            Err(e) => Ok(Response::new(CreationResponse { err: e.message })),
        }
    }

    async fn create_jwt_public_key_verify(
        &self,
        request: Request<CreationRequest>,
    ) -> Result<Response<CreationResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        match KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<JwtVerifierPrimitive>())
        {
            Ok(_) => Ok(Response::new(CreationResponse { err: String::new() })),
            Err(e) => Ok(Response::new(CreationResponse { err: e.message })),
        }
    }

    async fn compute_mac_and_encode(
        &self,
        request: Request<JwtSignRequest>,
    ) -> Result<Response<JwtSignResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        let token = req.raw_jwt.as_ref().unwrap();
        let raw_jwt = RawJwt::new(jwt_token_to_json(token));
        let result = KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<JwtMacPrimitive>())
            .and_then(|mac| mac.compute_and_encode(&raw_jwt));
        match result {
            Ok(compact) => Ok(Response::new(JwtSignResponse {
                result: Some(jwt_sign_response::Result::SignedCompactJwt(compact)),
            })),
            Err(e) => Ok(Response::new(JwtSignResponse {
                result: Some(jwt_sign_response::Result::Err(e.message)),
            })),
        }
    }

    async fn verify_mac_and_decode(
        &self,
        request: Request<JwtVerifyRequest>,
    ) -> Result<Response<JwtVerifyResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        let validator = req.validator.as_ref().unwrap();
        let validator_json = jwt_validator_to_json(validator);
        let tink_validator = tink_ffi::JwtValidator::new(validator_json);
        let result = KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<JwtMacPrimitive>())
            .and_then(|mac| mac.verify_and_decode(&req.signed_compact_jwt, &tink_validator));
        match result {
            Ok(verified) => Ok(Response::new(JwtVerifyResponse {
                result: Some(jwt_verify_response::Result::VerifiedJwt(json_to_jwt_token(
                    verified.claims(),
                ))),
            })),
            Err(e) => Ok(Response::new(JwtVerifyResponse {
                result: Some(jwt_verify_response::Result::Err(e.message)),
            })),
        }
    }

    async fn public_key_sign_and_encode(
        &self,
        request: Request<JwtSignRequest>,
    ) -> Result<Response<JwtSignResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        let token = req.raw_jwt.as_ref().unwrap();
        let raw_jwt = RawJwt::new(jwt_token_to_json(token));
        let result = KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<JwtSignerPrimitive>())
            .and_then(|signer| signer.sign_and_encode(&raw_jwt));
        match result {
            Ok(compact) => Ok(Response::new(JwtSignResponse {
                result: Some(jwt_sign_response::Result::SignedCompactJwt(compact)),
            })),
            Err(e) => Ok(Response::new(JwtSignResponse {
                result: Some(jwt_sign_response::Result::Err(e.message)),
            })),
        }
    }

    async fn public_key_verify_and_decode(
        &self,
        request: Request<JwtVerifyRequest>,
    ) -> Result<Response<JwtVerifyResponse>, Status> {
        let req = request.into_inner();
        let ak = req.annotated_keyset.as_ref().unwrap();
        let validator = req.validator.as_ref().unwrap();
        let validator_json = jwt_validator_to_json(validator);
        let tink_validator = tink_ffi::JwtValidator::new(validator_json);
        let result = KeysetHandle::from_binary(&ak.serialized_keyset)
            .and_then(|h| h.primitive::<JwtVerifierPrimitive>())
            .and_then(|v| v.verify_and_decode(&req.signed_compact_jwt, &tink_validator));
        match result {
            Ok(verified) => Ok(Response::new(JwtVerifyResponse {
                result: Some(jwt_verify_response::Result::VerifiedJwt(json_to_jwt_token(
                    verified.claims(),
                ))),
            })),
            Err(e) => Ok(Response::new(JwtVerifyResponse {
                result: Some(jwt_verify_response::Result::Err(e.message)),
            })),
        }
    }

    async fn to_jwk_set(
        &self,
        _request: Request<JwtToJwkSetRequest>,
    ) -> Result<Response<JwtToJwkSetResponse>, Status> {
        Ok(Response::new(JwtToJwkSetResponse {
            result: Some(jwt_to_jwk_set_response::Result::Err(
                "JWK set conversion not supported".into(),
            )),
        }))
    }

    async fn from_jwk_set(
        &self,
        _request: Request<JwtFromJwkSetRequest>,
    ) -> Result<Response<JwtFromJwkSetResponse>, Status> {
        Ok(Response::new(JwtFromJwkSetResponse {
            result: Some(jwt_from_jwk_set_response::Result::Err(
                "JWK set conversion not supported".into(),
            )),
        }))
    }
}
