use std::{net::SocketAddr, time::Instant};

use opcua_core::comms::{tcp_codec::TcpCodec, tcp_types::ReverseHelloMessage};
use opcua_types::{DecodingOptions, Error, StatusCode};
use tokio::{
    io::{AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
};
use tokio_util::codec::FramedRead;
use tracing::debug;
use tracing_futures::Instrument;

use crate::transport::{
    tcp::{TcpConnector, TransportConfig},
    Connector,
};

pub(crate) struct ReverseTcpConnector {
    deadline: Instant,
    config: TransportConfig,
    decoding_options: DecodingOptions,
    target: SocketAddr,
    server_uri: String,
    endpoint_url: String,
}

impl ReverseTcpConnector {
    pub(crate) fn new(
        config: TransportConfig,
        decoding_options: DecodingOptions,
        target: SocketAddr,
        server_uri: String,
        endpoint_url: String,
    ) -> Self {
        Self {
            deadline: Instant::now() + config.hello_timeout,
            config,
            decoding_options,
            target,
            server_uri,
            endpoint_url,
        }
    }

    async fn reverse_hello(
        &mut self,
    ) -> Result<
        (
            FramedRead<ReadHalf<TcpStream>, TcpCodec>,
            WriteHalf<TcpStream>,
        ),
        Error,
    > {
        let stream = TcpStream::connect(self.target).await.map_err(|e| {
            Error::new(
                StatusCode::BadCommunicationError,
                format!("Failed to connect to {}: {}", self.target, e),
            )
        })?;

        let (read_half, mut write_half) = tokio::io::split(stream);
        let read = FramedRead::new(read_half, TcpCodec::new(self.decoding_options.clone()));

        let reverse_hello =
            ReverseHelloMessage::new(self.server_uri.as_ref(), self.endpoint_url.as_ref());
        let mut buf =
            Vec::with_capacity(opcua_types::SimpleBinaryEncodable::byte_len(&reverse_hello));
        opcua_types::SimpleBinaryEncodable::encode(&reverse_hello, &mut buf)
            .map_err(|e| Error::new(e.into(), "Failed to encode reverse hello"))?;

        write_half.write_all(&buf).await.map_err(|e| {
            Error::new(
                opcua_types::StatusCode::BadCommunicationError,
                format!("Failed to send reverse hello: {}", e),
            )
        })?;
        Ok((read, write_half))
    }
}

impl Connector for ReverseTcpConnector {
    async fn connect(
        mut self,
        info: std::sync::Arc<crate::ServerInfo>,
        token: tokio_util::sync::CancellationToken,
    ) -> Result<super::tcp::TcpTransport, opcua_types::StatusCode> {
        tokio::select! {
            _ = tokio::time::sleep_until(self.deadline.into()) => {
                debug!("Timeout sending REVERSE HELLO to {}", self.target);
                Err(StatusCode::BadTimeout)
            }
            r = self.reverse_hello().instrument(tracing::info_span!("OPC-UA TCP Reverse Hello")) => {
                match r {
                    Ok((read, write)) => {
                        let inner = TcpConnector::new_split(
                            read,
                            write,
                            self.config,
                            self.decoding_options
                        );
                        inner.connect(info, token).await
                    }
                    Err(e) => {
                        debug!("Error sending REVERSE HELLO to {}: {}", self.target, e);
                        Err(e.status())
                    }
                }
            }
        }
    }
}
