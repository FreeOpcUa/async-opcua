// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! WebSocket byte-stream adapter for OPC UA over WebSockets.

use std::{
    cmp,
    io::{self, ErrorKind},
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures::{ready, Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{
    tungstenite::{Error as TungsteniteError, Message},
    WebSocketStream,
};

/// Adapts a WebSocket stream carrying binary UACP frames into an async byte stream.
///
/// OPC UA over WebSockets wraps the same UACP bytes used by `opc.tcp` in binary
/// WebSocket messages. This type exposes those bytes through [`AsyncRead`] and
/// accepts outbound bytes through [`AsyncWrite`], allowing the existing TCP codec
/// and chunking stack to run unchanged over a WebSocket transport.
pub struct WsByteStream<S> {
    ws: WebSocketStream<S>,
    read_buf: BytesMut,
}

impl<S> WsByteStream<S> {
    /// Creates a new WebSocket byte-stream adapter.
    pub fn new(ws: WebSocketStream<S>) -> Self {
        Self {
            ws,
            read_buf: BytesMut::new(),
        }
    }
}

impl<S> AsyncRead for WsByteStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if dst.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        if !this.read_buf.is_empty() {
            copy_to_read_buf(&mut this.read_buf, dst);
            return Poll::Ready(Ok(()));
        }

        loop {
            match ready!(Pin::new(&mut this.ws).poll_next(cx)) {
                Some(Ok(Message::Binary(data))) => {
                    copy_binary_to_read_buf(data, &mut this.read_buf, dst);
                    return Poll::Ready(Ok(()));
                }
                Some(Ok(Message::Text(_))) => {
                    return Poll::Ready(Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "opc.wss received a text WebSocket message; binary messages are required",
                    )));
                }
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {}
                Some(Ok(Message::Frame(_))) => {}
                Some(Ok(Message::Close(_))) | None => return Poll::Ready(Ok(())),
                Some(Err(err)) => return Poll::Ready(Err(map_tungstenite_error(err))),
            }
        }
    }
}

impl<S> AsyncWrite for WsByteStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        ready!(Pin::new(&mut this.ws).poll_ready(cx)).map_err(map_tungstenite_error)?;
        Pin::new(&mut this.ws)
            .start_send(Message::Binary(Bytes::copy_from_slice(buf)))
            .map_err(map_tungstenite_error)?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.ws)
            .poll_flush(cx)
            .map_err(map_tungstenite_error)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.ws)
            .poll_close(cx)
            .map_err(map_tungstenite_error)
    }
}

fn copy_binary_to_read_buf(data: Bytes, leftover: &mut BytesMut, dst: &mut ReadBuf<'_>) {
    let len = cmp::min(data.len(), dst.remaining());
    dst.put_slice(&data[..len]);
    if len < data.len() {
        leftover.extend_from_slice(&data[len..]);
    }
}

fn copy_to_read_buf(src: &mut BytesMut, dst: &mut ReadBuf<'_>) {
    let len = cmp::min(src.len(), dst.remaining());
    let chunk = src.split_to(len);
    dst.put_slice(&chunk);
}

fn map_tungstenite_error(err: TungsteniteError) -> io::Error {
    match err {
        TungsteniteError::Io(err) => err,
        TungsteniteError::ConnectionClosed | TungsteniteError::AlreadyClosed => {
            io::Error::new(ErrorKind::BrokenPipe, err)
        }
        _ => io::Error::new(ErrorKind::Other, err),
    }
}
