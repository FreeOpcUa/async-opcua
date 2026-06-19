// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Server connector for OPC UA over secure WebSockets.

use std::{sync::Arc, time::Instant};

use opcua_core::comms::{tcp_codec::TcpCodec, wss::WsByteStream};
use opcua_types::{DecodingOptions, StatusCode};
use tokio::{
    io::{ReadHalf, WriteHalf},
    net::TcpStream,
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        handshake::server::ErrorResponse,
        handshake::server::{Request, Response},
        http::{header::SEC_WEBSOCKET_PROTOCOL, HeaderValue},
    },
};
use tokio_util::{codec::FramedRead, sync::CancellationToken};
use tracing::info_span;
use tracing_futures::Instrument;

use crate::info::ServerInfo;

use super::{
    connect::Connector,
    tcp::{TcpConnector, Transport, TransportConfig},
};

const OPC_WSS_SUBPROTOCOL: &str = "opcua+uacp";

type WssIo = WsByteStream<TlsStream<TcpStream>>;

/// Transport implementation for `opc.wss`.
pub(crate) type WebSocketTransport = Transport<ReadHalf<WssIo>, WriteHalf<WssIo>>;

/// Connector for an accepted `opc.wss` stream.
pub(crate) struct WebSocketConnector {
    stream: TcpStream,
    tls_config: Arc<rustls::ServerConfig>,
    config: TransportConfig,
    decoding_options: DecodingOptions,
}

impl WebSocketConnector {
    /// Creates a connector from an accepted TCP stream and WSS TLS configuration.
    pub(crate) fn new(
        stream: TcpStream,
        tls_config: Arc<rustls::ServerConfig>,
        config: TransportConfig,
        decoding_options: DecodingOptions,
    ) -> Self {
        Self {
            stream,
            tls_config,
            config,
            decoding_options,
        }
    }

    async fn upgrade(self) -> Result<TcpConnector<ReadHalf<WssIo>, WriteHalf<WssIo>>, StatusCode> {
        let tls = TlsAcceptor::from(self.tls_config)
            .accept(self.stream)
            .await
            .map_err(|err| {
                tracing::warn!("WSS TLS handshake failed: {err}");
                StatusCode::BadCommunicationError
            })?;

        let ws = accept_hdr_async(tls, negotiate_subprotocol)
            .await
            .map_err(|err| {
                tracing::warn!("WSS WebSocket handshake failed: {err}");
                StatusCode::BadCommunicationError
            })?;

        let stream = WsByteStream::new(ws);
        let (read, write) = tokio::io::split(stream);
        let read = FramedRead::new(read, TcpCodec::new(self.decoding_options.clone()));
        Ok(TcpConnector::new_split(
            read,
            write,
            self.config,
            self.decoding_options,
        ))
    }
}

impl Connector for WebSocketConnector {
    type Transport = WebSocketTransport;

    async fn connect(
        self,
        info: Arc<ServerInfo>,
        token: CancellationToken,
    ) -> Result<Self::Transport, StatusCode> {
        let deadline = Instant::now() + self.config.hello_timeout;
        let err = tokio::select! {
            _ = tokio::time::sleep_until(deadline.into()) => StatusCode::BadTimeout,
            _ = token.cancelled() => StatusCode::BadServerHalted,
            r = self.upgrade().instrument(info_span!("OPC-UA WSS upgrade")) => {
                match r {
                    Ok(connector) => return connector.connect(info, token).await,
                    Err(err) => err,
                }
            }
        };

        Err(err)
    }
}

#[allow(
    clippy::result_large_err,
    reason = "tokio-tungstenite Callback requires ErrorResponse; this callback never returns Err"
)]
fn negotiate_subprotocol(
    request: &Request,
    mut response: Response,
) -> Result<Response, ErrorResponse> {
    let supports_opcua = request
        .headers()
        .get(SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|protocol| protocol.trim() == OPC_WSS_SUBPROTOCOL)
        });

    if supports_opcua {
        response.headers_mut().insert(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static(OPC_WSS_SUBPROTOCOL),
        );
    }

    Ok(response)
}
