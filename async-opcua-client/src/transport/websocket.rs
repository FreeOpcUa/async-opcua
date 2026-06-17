// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Client connector for OPC UA over secure WebSockets.

use std::{fmt::Debug, net::SocketAddr, sync::Arc, time::Duration};

use opcua_core::comms::{
    tcp_codec::TcpCodec,
    url::{hostname_port_from_wss_url, is_opc_ua_wss_url},
    wss::WsByteStream,
};
use opcua_types::{DecodingOptions, EndpointDescription, Error, StatusCode};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use rustls_pki_types::pem::PemObject;
use tokio::{
    io::{ReadHalf, WriteHalf},
    net::TcpStream,
};
use tokio_rustls::{client::TlsStream, TlsConnector};
use tokio_tungstenite::{
    client_async_with_config,
    tungstenite::{client::ClientRequestBuilder, http::Uri},
};
use tokio_util::codec::FramedRead;
use tracing::{error, warn};

use crate::{
    config::{TcpKeepaliveConfig, WssTlsConfig},
    transport::{
        core::OutgoingMessage,
        state::SecureChannelState,
        stream::{StreamConnection, StreamConnector},
        Connector, StreamTransport,
    },
};

use super::tcp::TransportConfiguration;

const DEFAULT_OPC_WSS_PORT: u16 = 443;
const OPC_WSS_SUBPROTOCOL: &str = "opcua+uacp";

type WssIo = WsByteStream<TlsStream<TcpStream>>;

/// Type alias for a stream transport over secure WebSockets.
pub type WebSocketTransport = StreamTransport<ReadHalf<WssIo>, WriteHalf<WssIo>>;

/// Connector for `opc.wss` transport.
pub struct WebSocketConnector {
    endpoint_url: String,
    tls_config: WssTlsConfig,
}

impl WebSocketConnector {
    /// Create a new `WebSocketConnector` with the given endpoint URL.
    pub fn new(endpoint_url: &str, tls_config: WssTlsConfig) -> Result<Self, Error> {
        if is_opc_ua_wss_url(endpoint_url) {
            Ok(Self {
                endpoint_url: endpoint_url.to_string(),
                tls_config,
            })
        } else {
            Err(Error::new(
                StatusCode::BadInvalidArgument,
                format!("Invalid OPC-UA WSS URL: {endpoint_url}"),
            ))
        }
    }

    async fn connect_wss(
        endpoint_url: String,
        decoding_options: DecodingOptions,
        connect_timeout: Duration,
        tcp_keepalive: TcpKeepaliveConfig,
        tls_config: WssTlsConfig,
    ) -> Result<StreamConnection<ReadHalf<WssIo>, WriteHalf<WssIo>>, Error> {
        let (host, port) = hostname_port_from_wss_url(&endpoint_url, DEFAULT_OPC_WSS_PORT)
            .map_err(|e| Error::new(e, "Failed to resolve WSS URL to hostname and port"))?;
        let addr = resolve_addr(&endpoint_url, &host, port).await?;
        let socket = connect_tcp(addr, connect_timeout).await?;
        configure_tcp_stream(&socket, addr, &tcp_keepalive);

        let server_name = ServerName::try_from(host.clone()).map_err(|_| {
            Error::new(
                StatusCode::BadTcpEndpointUrlInvalid,
                format!("Invalid WSS TLS server name: {host}"),
            )
        })?;
        let tls = TlsConnector::from(tls_config.into_rustls_config()?)
            .connect(server_name, socket)
            .await
            .map_err(|err| {
                Error::new(
                    StatusCode::BadCommunicationError,
                    format!("WSS TLS handshake failed: {err}"),
                )
            })?;

        let request = ClientRequestBuilder::new(wss_uri_from_endpoint_url(&endpoint_url)?)
            .with_sub_protocol(OPC_WSS_SUBPROTOCOL);
        let (ws, _) = client_async_with_config(request, tls, None)
            .await
            .map_err(|err| {
                Error::new(
                    StatusCode::BadCommunicationError,
                    format!("WSS WebSocket handshake failed: {err}"),
                )
            })?;
        let stream = WsByteStream::new(ws);
        let (reader, writer) = tokio::io::split(stream);
        Ok(StreamConnection::new(
            FramedRead::new(reader, TcpCodec::new(decoding_options)),
            writer,
            endpoint_url,
        ))
    }
}

impl Connector for WebSocketConnector {
    type Transport = WebSocketTransport;

    async fn connect(
        &self,
        channel: Arc<SecureChannelState>,
        outgoing_recv: tokio::sync::mpsc::Receiver<OutgoingMessage>,
        config: TransportConfiguration,
    ) -> Result<Self::Transport, Error> {
        let connect_timeout = config.connect_timeout;
        let tcp_keepalive = config.tcp_keepalive;
        let tls_config = self.tls_config.clone();
        let inner = StreamConnector::new(
            move |endpoint_url: String, decoding_options: DecodingOptions| {
                Self::connect_wss(
                    endpoint_url,
                    decoding_options,
                    connect_timeout,
                    tcp_keepalive,
                    tls_config.clone(),
                )
            },
            self.endpoint_url.clone(),
        );
        inner.connect(channel, outgoing_recv, config).await
    }

    fn default_endpoint(&self) -> EndpointDescription {
        EndpointDescription::from(self.endpoint_url.as_str())
    }
}

trait WssTlsConfigExt {
    fn into_rustls_config(self) -> Result<Arc<ClientConfig>, Error>;
}

impl WssTlsConfigExt for WssTlsConfig {
    fn into_rustls_config(self) -> Result<Arc<ClientConfig>, Error> {
        match self {
            WssTlsConfig::Default => default_rustls_config(None),
            WssTlsConfig::CaPem(path) => default_rustls_config(Some(path)),
            WssTlsConfig::Custom(config) => Ok(config),
            WssTlsConfig::DangerouslyAcceptInvalid => {
                warn!("WSS TLS certificate verification disabled -- do NOT use in production");
                let mut config = ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .expect("ring provider supports safe default protocol versions")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
                .with_no_client_auth();
                config.alpn_protocols = vec![OPC_WSS_SUBPROTOCOL.as_bytes().to_vec()];
                Ok(Arc::new(config))
            }
        }
    }
}

fn default_rustls_config(
    extra_ca_pem: Option<std::path::PathBuf>,
) -> Result<Arc<ClientConfig>, Error> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for err in native.errors {
        warn!("Failed to load a native TLS root certificate: {err}");
    }
    roots.add_parsable_certificates(native.certs);
    roots
        .roots
        .extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Some(path) = extra_ca_pem {
        let certs = CertificateDer::pem_file_iter(&path).map_err(|err| {
            Error::new(
                StatusCode::BadConfigurationError,
                format!("Failed to open WSS CA PEM file {}: {err}", path.display()),
            )
        })?;
        for cert in certs {
            let cert = cert.map_err(|err| {
                Error::new(
                    StatusCode::BadConfigurationError,
                    format!("Failed to read WSS CA PEM file {}: {err}", path.display()),
                )
            })?;
            roots.add(cert).map_err(|err| {
                Error::new(
                    StatusCode::BadConfigurationError,
                    format!("Failed to add WSS CA certificate {}: {err}", path.display()),
                )
            })?;
        }
    }

    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring provider supports safe default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![OPC_WSS_SUBPROTOCOL.as_bytes().to_vec()];
    Ok(Arc::new(config))
}

async fn resolve_addr(endpoint_url: &str, host: &str, port: u16) -> Result<SocketAddr, Error> {
    let addr = format!("{host}:{port}");
    match tokio::net::lookup_host(addr).await {
        Ok(mut addrs) => addrs.next().ok_or_else(|| {
            error!("Invalid address {endpoint_url}, does not resolve to any socket");
            Error::new(
                StatusCode::BadTcpEndpointUrlInvalid,
                format!("Invalid address {endpoint_url}, does not resolve to any socket"),
            )
        }),
        Err(err) => {
            error!("Invalid address {endpoint_url}, cannot be parsed {err:?}");
            Err(Error::new(
                StatusCode::BadTcpEndpointUrlInvalid,
                format!("Invalid address {endpoint_url}, cannot be parsed {err:?}"),
            ))
        }
    }
}

async fn connect_tcp(addr: SocketAddr, connect_timeout: Duration) -> Result<TcpStream, Error> {
    tokio::time::timeout(connect_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| {
            error!("Timed out connecting to host {addr} after {connect_timeout:?}");
            Error::new(
                StatusCode::BadTimeout,
                format!("Timed out connecting to host {addr} after {connect_timeout:?}"),
            )
        })?
        .map_err(|err| {
            error!("Could not connect to host {addr}, {err:?}");
            Error::new(
                StatusCode::BadCommunicationError,
                format!("Could not connect to host {addr}, {err:?}"),
            )
        })
}

fn configure_tcp_stream(stream: &TcpStream, addr: SocketAddr, tcp_keepalive: &TcpKeepaliveConfig) {
    if let Err(err) = stream.set_nodelay(true) {
        warn!("Failed to set TCP_NODELAY for {addr}: {err}");
    }
    if tcp_keepalive.enabled {
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(tcp_keepalive.idle_secs))
            .with_interval(Duration::from_secs(tcp_keepalive.interval_secs))
            .with_retries(tcp_keepalive.retries);
        if let Err(err) = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive) {
            warn!("Failed to set TCP keep-alive for {addr}: {err}");
        }
    }
}

fn wss_uri_from_endpoint_url(endpoint_url: &str) -> Result<Uri, Error> {
    let Some(rest) = endpoint_url.strip_prefix("opc.wss://") else {
        return Err(Error::new(
            StatusCode::BadTcpEndpointUrlInvalid,
            format!("Invalid OPC-UA WSS URL: {endpoint_url}"),
        ));
    };
    format!("wss://{rest}").parse::<Uri>().map_err(|err| {
        Error::new(
            StatusCode::BadTcpEndpointUrlInvalid,
            format!("Invalid WebSocket URL for {endpoint_url}: {err}"),
        )
    })
}

#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
