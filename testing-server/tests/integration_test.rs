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

/// Integration tests that start the testing server and exercise all primitives
/// via the gRPC API, mirroring what the cross-language test suite does.
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;
use tonic::transport::Channel;

use testing_server::proto::*;
use testing_server::services;

async fn start_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    tink_ffi::register_all().expect("register_all");

    let listener = TcpListener::bind("[::1]:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(metadata_server::MetadataServer::new(
                services::metadata::MetadataServiceImpl,
            ))
            .add_service(keyset_server::KeysetServer::new(
                services::keyset::KeysetServiceImpl,
            ))
            .add_service(aead_server::AeadServer::new(
                services::aead::AeadServiceImpl,
            ))
            .add_service(deterministic_aead_server::DeterministicAeadServer::new(
                services::daead::DeterministicAeadServiceImpl,
            ))
            .add_service(streaming_aead_server::StreamingAeadServer::new(
                services::streaming_aead::StreamingAeadServiceImpl,
            ))
            .add_service(mac_server::MacServer::new(services::mac::MacServiceImpl))
            .add_service(hybrid_server::HybridServer::new(
                services::hybrid::HybridServiceImpl,
            ))
            .add_service(signature_server::SignatureServer::new(
                services::signature::SignatureServiceImpl,
            ))
            .add_service(prf_set_server::PrfSetServer::new(
                services::prf::PrfSetServiceImpl,
            ))
            .add_service(jwt_server::JwtServer::new(services::jwt::JwtServiceImpl))
            .add_service(keyset_deriver_server::KeysetDeriverServer::new(
                services::keyset_deriver::KeysetDeriverServiceImpl,
            ))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    // Wait for server to be ready
    tokio::time::sleep(Duration::from_millis(200)).await;

    (addr, handle)
}

async fn connect(addr: SocketAddr) -> Channel {
    Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap()
}

/// Helper: generate a keyset for the given template name.
async fn generate_keyset(
    keyset_client: &mut keyset_client::KeysetClient<Channel>,
    template_name: &str,
) -> Vec<u8> {
    // Get the template bytes
    let template_resp = keyset_client
        .get_template(KeysetTemplateRequest {
            template_name: template_name.to_string(),
        })
        .await
        .unwrap()
        .into_inner();
    let template_bytes = match template_resp.result.unwrap() {
        keyset_template_response::Result::KeyTemplate(t) => t,
        keyset_template_response::Result::Err(e) => {
            panic!("get_template({template_name}) failed: {e}")
        }
    };

    // Generate a keyset
    let gen_resp = keyset_client
        .generate(KeysetGenerateRequest {
            template: template_bytes,
        })
        .await
        .unwrap()
        .into_inner();
    match gen_resp.result.unwrap() {
        keyset_generate_response::Result::Keyset(k) => k,
        keyset_generate_response::Result::Err(e) => panic!("generate({template_name}) failed: {e}"),
    }
}

/// Helper: get the public keyset from a private keyset.
async fn public_keyset(
    keyset_client: &mut keyset_client::KeysetClient<Channel>,
    private_keyset: &[u8],
) -> Vec<u8> {
    let resp = keyset_client
        .public(KeysetPublicRequest {
            private_keyset: private_keyset.to_vec(),
        })
        .await
        .unwrap()
        .into_inner();
    match resp.result.unwrap() {
        keyset_public_response::Result::PublicKeyset(k) => k,
        keyset_public_response::Result::Err(e) => panic!("public() failed: {e}"),
    }
}

fn annotated(keyset: &[u8]) -> Option<AnnotatedKeyset> {
    Some(AnnotatedKeyset {
        serialized_keyset: keyset.to_vec(),
        annotations: Default::default(),
    })
}

#[tokio::test]
async fn test_metadata() {
    let (addr, _handle) = start_server().await;
    let channel = connect(addr).await;
    let mut client = metadata_client::MetadataClient::new(channel);

    let resp = client
        .get_server_info(ServerInfoRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.language, "rust");
    assert_eq!(resp.tink_version, "2.2.0");
}

#[tokio::test]
async fn test_aead_encrypt_decrypt() {
    let (addr, _handle) = start_server().await;
    let channel = connect(addr).await;
    let mut kc = keyset_client::KeysetClient::new(channel.clone());
    let mut ac = aead_client::AeadClient::new(channel);

    let keyset = generate_keyset(&mut kc, "AES128_GCM").await;

    // Create
    let create_resp = ac
        .create(CreationRequest {
            annotated_keyset: annotated(&keyset),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(create_resp.err.is_empty(), "create: {}", create_resp.err);

    // Encrypt
    let plaintext = b"hello world".to_vec();
    let aad = b"associated data".to_vec();
    let enc_resp = ac
        .encrypt(AeadEncryptRequest {
            annotated_keyset: annotated(&keyset),
            plaintext: plaintext.clone(),
            associated_data: aad.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    let ciphertext = match enc_resp.result.unwrap() {
        aead_encrypt_response::Result::Ciphertext(ct) => ct,
        aead_encrypt_response::Result::Err(e) => panic!("encrypt: {e}"),
    };

    // Decrypt
    let dec_resp = ac
        .decrypt(AeadDecryptRequest {
            annotated_keyset: annotated(&keyset),
            ciphertext,
            associated_data: aad,
        })
        .await
        .unwrap()
        .into_inner();
    let decrypted = match dec_resp.result.unwrap() {
        aead_decrypt_response::Result::Plaintext(pt) => pt,
        aead_decrypt_response::Result::Err(e) => panic!("decrypt: {e}"),
    };
    assert_eq!(decrypted, plaintext);
}

#[tokio::test]
async fn test_daead_encrypt_decrypt() {
    let (addr, _handle) = start_server().await;
    let channel = connect(addr).await;
    let mut kc = keyset_client::KeysetClient::new(channel.clone());
    let mut dc = deterministic_aead_client::DeterministicAeadClient::new(channel);

    let keyset = generate_keyset(&mut kc, "AES256_SIV").await;

    let plaintext = b"deterministic test".to_vec();
    let aad = b"aad".to_vec();

    let enc_resp = dc
        .encrypt_deterministically(DeterministicAeadEncryptRequest {
            annotated_keyset: annotated(&keyset),
            plaintext: plaintext.clone(),
            associated_data: aad.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    let ct = match enc_resp.result.unwrap() {
        deterministic_aead_encrypt_response::Result::Ciphertext(ct) => ct,
        deterministic_aead_encrypt_response::Result::Err(e) => panic!("encrypt: {e}"),
    };

    // Deterministic: same input should produce same ciphertext
    let enc_resp2 = dc
        .encrypt_deterministically(DeterministicAeadEncryptRequest {
            annotated_keyset: annotated(&keyset),
            plaintext: plaintext.clone(),
            associated_data: aad.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    let ct2 = match enc_resp2.result.unwrap() {
        deterministic_aead_encrypt_response::Result::Ciphertext(ct) => ct,
        deterministic_aead_encrypt_response::Result::Err(e) => panic!("encrypt2: {e}"),
    };
    assert_eq!(ct, ct2);

    let dec_resp = dc
        .decrypt_deterministically(DeterministicAeadDecryptRequest {
            annotated_keyset: annotated(&keyset),
            ciphertext: ct,
            associated_data: aad,
        })
        .await
        .unwrap()
        .into_inner();
    let decrypted = match dec_resp.result.unwrap() {
        deterministic_aead_decrypt_response::Result::Plaintext(pt) => pt,
        deterministic_aead_decrypt_response::Result::Err(e) => panic!("decrypt: {e}"),
    };
    assert_eq!(decrypted, plaintext);
}

#[tokio::test]
async fn test_streaming_aead() {
    let (addr, _handle) = start_server().await;
    let channel = connect(addr).await;
    let mut kc = keyset_client::KeysetClient::new(channel.clone());
    let mut sc = streaming_aead_client::StreamingAeadClient::new(channel);

    let keyset = generate_keyset(&mut kc, "AES128_GCM_HKDF_4KB").await;

    let plaintext = b"streaming test data".to_vec();
    let aad = b"streaming aad".to_vec();

    let enc_resp = sc
        .encrypt(StreamingAeadEncryptRequest {
            annotated_keyset: annotated(&keyset),
            plaintext: plaintext.clone(),
            associated_data: aad.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    let ct = match enc_resp.result.unwrap() {
        streaming_aead_encrypt_response::Result::Ciphertext(ct) => ct,
        streaming_aead_encrypt_response::Result::Err(e) => panic!("encrypt: {e}"),
    };

    let dec_resp = sc
        .decrypt(StreamingAeadDecryptRequest {
            annotated_keyset: annotated(&keyset),
            ciphertext: ct,
            associated_data: aad,
        })
        .await
        .unwrap()
        .into_inner();
    let decrypted = match dec_resp.result.unwrap() {
        streaming_aead_decrypt_response::Result::Plaintext(pt) => pt,
        streaming_aead_decrypt_response::Result::Err(e) => panic!("decrypt: {e}"),
    };
    assert_eq!(decrypted, plaintext);
}

#[tokio::test]
async fn test_mac_compute_verify() {
    let (addr, _handle) = start_server().await;
    let channel = connect(addr).await;
    let mut kc = keyset_client::KeysetClient::new(channel.clone());
    let mut mc = mac_client::MacClient::new(channel);

    let keyset = generate_keyset(&mut kc, "HMAC_SHA256_128BITTAG").await;
    let data = b"mac test data".to_vec();

    let compute_resp = mc
        .compute_mac(ComputeMacRequest {
            annotated_keyset: annotated(&keyset),
            data: data.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    let mac_value = match compute_resp.result.unwrap() {
        compute_mac_response::Result::MacValue(v) => v,
        compute_mac_response::Result::Err(e) => panic!("compute: {e}"),
    };

    let verify_resp = mc
        .verify_mac(VerifyMacRequest {
            annotated_keyset: annotated(&keyset),
            mac_value,
            data,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(verify_resp.err.is_empty(), "verify: {}", verify_resp.err);
}

#[tokio::test]
async fn test_signature_sign_verify() {
    let (addr, _handle) = start_server().await;
    let channel = connect(addr).await;
    let mut kc = keyset_client::KeysetClient::new(channel.clone());
    let mut sc = signature_client::SignatureClient::new(channel);

    let private_keyset = generate_keyset(&mut kc, "ECDSA_P256").await;
    let pub_keyset = public_keyset(&mut kc, &private_keyset).await;

    let data = b"data to sign".to_vec();

    let sign_resp = sc
        .sign(SignatureSignRequest {
            private_annotated_keyset: annotated(&private_keyset),
            data: data.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    let sig = match sign_resp.result.unwrap() {
        signature_sign_response::Result::Signature(s) => s,
        signature_sign_response::Result::Err(e) => panic!("sign: {e}"),
    };

    let verify_resp = sc
        .verify(SignatureVerifyRequest {
            public_annotated_keyset: annotated(&pub_keyset),
            signature: sig,
            data,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(verify_resp.err.is_empty(), "verify: {}", verify_resp.err);
}

#[tokio::test]
async fn test_hybrid_encrypt_decrypt() {
    let (addr, _handle) = start_server().await;
    let channel = connect(addr).await;
    let mut kc = keyset_client::KeysetClient::new(channel.clone());
    let mut hc = hybrid_client::HybridClient::new(channel);

    let private_keyset = generate_keyset(&mut kc, "ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM").await;
    let pub_keyset = public_keyset(&mut kc, &private_keyset).await;

    let plaintext = b"hybrid test".to_vec();
    let context_info = b"context".to_vec();

    let enc_resp = hc
        .encrypt(HybridEncryptRequest {
            public_annotated_keyset: annotated(&pub_keyset),
            plaintext: plaintext.clone(),
            context_info: context_info.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    let ct = match enc_resp.result.unwrap() {
        hybrid_encrypt_response::Result::Ciphertext(ct) => ct,
        hybrid_encrypt_response::Result::Err(e) => panic!("encrypt: {e}"),
    };

    let dec_resp = hc
        .decrypt(HybridDecryptRequest {
            private_annotated_keyset: annotated(&private_keyset),
            ciphertext: ct,
            context_info,
        })
        .await
        .unwrap()
        .into_inner();
    let decrypted = match dec_resp.result.unwrap() {
        hybrid_decrypt_response::Result::Plaintext(pt) => pt,
        hybrid_decrypt_response::Result::Err(e) => panic!("decrypt: {e}"),
    };
    assert_eq!(decrypted, plaintext);
}

#[tokio::test]
async fn test_prf_set() {
    let (addr, _handle) = start_server().await;
    let channel = connect(addr).await;
    let mut kc = keyset_client::KeysetClient::new(channel.clone());
    let mut pc = prf_set_client::PrfSetClient::new(channel);

    let keyset = generate_keyset(&mut kc, "HMAC_SHA256_PRF").await;

    let key_ids_resp = pc
        .key_ids(PrfSetKeyIdsRequest {
            annotated_keyset: annotated(&keyset),
        })
        .await
        .unwrap()
        .into_inner();
    let output = match key_ids_resp.result.unwrap() {
        prf_set_key_ids_response::Result::Output(o) => o,
        prf_set_key_ids_response::Result::Err(e) => panic!("key_ids: {e}"),
    };
    assert!(!output.key_id.is_empty());

    let compute_resp = pc
        .compute(PrfSetComputeRequest {
            annotated_keyset: annotated(&keyset),
            key_id: output.primary_key_id,
            input_data: b"prf input".to_vec(),
            output_length: 32,
        })
        .await
        .unwrap()
        .into_inner();
    let prf_output = match compute_resp.result.unwrap() {
        prf_set_compute_response::Result::Output(o) => o,
        prf_set_compute_response::Result::Err(e) => panic!("compute: {e}"),
    };
    assert_eq!(prf_output.len(), 32);
}

#[tokio::test]
async fn test_keyset_json_roundtrip() {
    let (addr, _handle) = start_server().await;
    let channel = connect(addr).await;
    let mut kc = keyset_client::KeysetClient::new(channel);

    let keyset = generate_keyset(&mut kc, "AES128_GCM").await;

    let json_resp = kc
        .to_json(KeysetToJsonRequest {
            keyset: keyset.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    let json_keyset = match json_resp.result.unwrap() {
        keyset_to_json_response::Result::JsonKeyset(j) => j,
        keyset_to_json_response::Result::Err(e) => panic!("to_json: {e}"),
    };
    assert!(!json_keyset.is_empty());

    let from_json_resp = kc
        .from_json(KeysetFromJsonRequest { json_keyset })
        .await
        .unwrap()
        .into_inner();
    let roundtripped = match from_json_resp.result.unwrap() {
        keyset_from_json_response::Result::Keyset(k) => k,
        keyset_from_json_response::Result::Err(e) => panic!("from_json: {e}"),
    };
    assert!(!roundtripped.is_empty());
}

#[tokio::test]
async fn test_keyset_deriver() {
    let (addr, _handle) = start_server().await;
    let channel = connect(addr).await;
    let mut kc = keyset_client::KeysetClient::new(channel.clone());
    let mut dc = keyset_deriver_client::KeysetDeriverClient::new(channel);

    // Key derivation templates are constructed programmatically (PRF template +
    // derived key template), not via named lookups. Build the
    // PrfBasedDeriverKeyFormat proto manually.
    let prf_template = get_template_bytes(&mut kc, "HKDF_SHA256").await;
    let derived_template = get_template_bytes(&mut kc, "AES128_GCM").await;

    // Construct PrfBasedDeriverKeyFormat proto by hand (prost encoding).
    // message PrfBasedDeriverKeyFormat {
    //   KeyTemplate prf_key_template = 1;
    //   PrfBasedDeriverParams params = 2;
    // }
    // message PrfBasedDeriverParams {
    //   KeyTemplate derived_key_template = 1;
    // }
    // We encode using the raw KeyTemplate bytes from tink.
    let params = encode_proto_msg(&[(1, &derived_template)]);
    let key_format = encode_proto_msg(&[(1, &prf_template), (2, &params)]);

    // Wrap in a KeyTemplate proto:
    // message KeyTemplate { string type_url=1; bytes value=2; OutputPrefixType output_prefix_type=3; }
    let type_url = b"type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey";
    let mut template = Vec::new();
    // field 1 (type_url): tag=0x0a, len-delimited string
    template.push(0x0a);
    encode_varint(type_url.len() as u64, &mut template);
    template.extend_from_slice(type_url);
    // field 2 (value): tag=0x12, len-delimited bytes
    template.push(0x12);
    encode_varint(key_format.len() as u64, &mut template);
    template.extend_from_slice(&key_format);
    // field 3 (output_prefix_type): TINK = 1, tag=0x18, varint
    template.push(0x18);
    template.push(0x01);

    // Generate keyset from the template
    let gen_resp = kc
        .generate(KeysetGenerateRequest { template })
        .await
        .unwrap()
        .into_inner();
    let keyset = match gen_resp.result.unwrap() {
        keyset_generate_response::Result::Keyset(k) => k,
        keyset_generate_response::Result::Err(e) => panic!("generate deriver keyset: {e}"),
    };

    // Now test derivation
    let derive_resp = dc
        .derive_keyset(DeriveKeysetRequest {
            annotated_keyset: annotated(&keyset),
            salt: b"test salt".to_vec(),
        })
        .await
        .unwrap()
        .into_inner();
    let derived = match derive_resp.result.unwrap() {
        derive_keyset_response::Result::DerivedKeyset(k) => k,
        derive_keyset_response::Result::Err(e) => panic!("derive: {e}"),
    };
    assert!(!derived.is_empty());
}

/// Get raw template bytes for a named template.
async fn get_template_bytes(kc: &mut keyset_client::KeysetClient<Channel>, name: &str) -> Vec<u8> {
    let resp = kc
        .get_template(KeysetTemplateRequest {
            template_name: name.to_string(),
        })
        .await
        .unwrap()
        .into_inner();
    match resp.result.unwrap() {
        keyset_template_response::Result::KeyTemplate(t) => t,
        keyset_template_response::Result::Err(e) => panic!("get_template({name}): {e}"),
    }
}

/// Encode a sequence of (field_number, embedded_message_bytes) as a protobuf message.
/// All fields are length-delimited (wire type 2).
fn encode_proto_msg(fields: &[(u32, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    for &(field_num, data) in fields {
        let tag = (field_num << 3) | 2;
        encode_varint(tag as u64, &mut buf);
        encode_varint(data.len() as u64, &mut buf);
        buf.extend_from_slice(data);
    }
    buf
}

fn encode_varint(mut val: u64, buf: &mut Vec<u8>) {
    loop {
        let mut byte = (val & 0x7f) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if val == 0 {
            break;
        }
    }
}
