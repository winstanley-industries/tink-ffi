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

use clap::Parser;
use tonic::transport::Server;

use testing_server::proto::*;
use testing_server::services;

#[derive(Parser)]
#[command(name = "testing_server")]
struct Args {
    #[arg(long, default_value = "0")]
    port: u16,
    /// Ignored — accepted for compatibility with the cross-language test harness.
    #[arg(long = "gcp_credentials_path")]
    gcp_credentials_path: Option<String>,
    #[arg(long = "aws_credentials_path")]
    aws_credentials_path: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    tink_ffi::register_all().expect("failed to register tink");

    let addr: std::net::SocketAddr = format!("[::]:{}", args.port).parse()?;

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    // The test framework reads this line to discover the port.
    println!("Server started on port {}", local_addr.port());

    Server::builder()
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
        .await?;

    Ok(())
}
