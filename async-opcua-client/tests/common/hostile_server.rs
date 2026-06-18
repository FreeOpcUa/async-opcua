use std::{
    io::{self, Cursor},
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use opcua_core::comms::{
    message_chunk::{
        MessageChunkHeader, MessageChunkType, MESSAGE_CHUNK_HEADER_SIZE, MESSAGE_SIZE_OFFSET,
    },
    security_header::{SequenceHeader, SymmetricSecurityHeader},
    tcp_types::{MessageHeader, MessageType, MESSAGE_HEADER_LEN},
};
use opcua_server::{ServerBuilder, ServerHandle, ANONYMOUS_USER_TOKEN_ID};
use opcua_types::{
    BinaryDecodable, BinaryEncodable, ContextOwned, DeleteSubscriptionsResponse,
    GetEndpointsResponse, MessageSecurityMode, NodeId, ObjectId, ReadValueId,
    SimpleBinaryDecodable, SimpleBinaryEncodable, UAString, VariableId,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

use opcua_client::{
    transport::DefaultConnector, ClientBuilder, IdentityToken, Session, SessionEventLoop,
};
use opcua_crypto::SecurityPolicy;

static NEXT_TEST_ID: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostileBehavior {
    PassThrough,
    EmptyDeleteSubscriptionsResults,
    StallChannelRenewal,
}

pub(crate) struct HostileServer {
    endpoint_url: String,
    hits: Arc<AtomicUsize>,
    server_handle: ServerHandle,
    server_task: JoinHandle<()>,
    proxy_task: JoinHandle<()>,
    _temp_dir: TempDir,
}

impl HostileServer {
    pub(crate) async fn start(behavior: HostileBehavior) -> Self {
        let temp_dir = TempDir::new("hostile-client-server");
        let real_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("real server listener should bind");
        let real_addr = real_listener
            .local_addr()
            .expect("real server listener address");
        let proxy_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("proxy listener should bind");
        let proxy_addr = proxy_listener.local_addr().expect("proxy listener address");
        let endpoint_url = format!("opc.tcp://127.0.0.1:{}/", proxy_addr.port());

        let (server, server_handle) = ServerBuilder::new()
            .application_name("hostile_client_test_server")
            .application_uri("urn:async-opcua:hostile-client-test-server")
            .product_uri("urn:async-opcua:hostile-client-test-server")
            .host("127.0.0.1")
            .pki_dir(temp_dir.path.join("server-pki"))
            .create_sample_keypair(true)
            .discovery_urls(vec![endpoint_url.clone()])
            .add_endpoint(
                "none",
                (
                    "/",
                    SecurityPolicy::None,
                    MessageSecurityMode::None,
                    &[ANONYMOUS_USER_TOKEN_ID] as &[&str],
                ),
            )
            .build()
            .expect("hostile test server should build");

        let server_task = tokio::spawn(async move {
            server
                .run_with(real_listener)
                .await
                .expect("hostile test server should run");
        });

        let hits = Arc::new(AtomicUsize::new(0));
        let proxy_task = tokio::spawn(run_proxy(
            proxy_listener,
            real_addr,
            endpoint_url.clone(),
            behavior,
            Arc::clone(&hits),
        ));

        Self {
            endpoint_url,
            hits,
            server_handle,
            server_task,
            proxy_task,
            _temp_dir: temp_dir,
        }
    }

    pub(crate) fn endpoint_url(&self) -> &str {
        &self.endpoint_url
    }

    pub(crate) fn hook_hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    pub(crate) async fn connect(&self) -> (Arc<Session>, SessionEventLoop<DefaultConnector>) {
        self.connect_with(|b| b).await
    }

    /// Connect a real client through the proxy, letting the caller tweak the
    /// `ClientBuilder` (e.g. a short `channel_lifetime` to force secure-channel
    /// renewal quickly for the stalled-renewal test).
    pub(crate) async fn connect_with(
        &self,
        customize: impl FnOnce(ClientBuilder) -> ClientBuilder,
    ) -> (Arc<Session>, SessionEventLoop<DefaultConnector>) {
        let builder = ClientBuilder::new()
            .application_name("hostile_client_test_client")
            .application_uri("urn:async-opcua:hostile-client-test-client")
            .product_uri("urn:async-opcua:hostile-client-test-client")
            .pki_dir(self._temp_dir.path.join("client-pki"))
            .create_sample_keypair(true)
            .trust_server_certs(true);
        let mut client = customize(builder)
            .client()
            .expect("hostile test client should build");

        client
            .connect_to_matching_endpoint(
                (
                    self.endpoint_url(),
                    SecurityPolicy::None.to_str(),
                    MessageSecurityMode::None,
                ),
                IdentityToken::Anonymous,
            )
            .await
            .expect("hostile test client should connect")
    }
}

impl Drop for HostileServer {
    fn drop(&mut self) {
        self.server_handle.cancel();
        self.server_task.abort();
        self.proxy_task.abort();
    }
}

async fn run_proxy(
    listener: TcpListener,
    real_addr: SocketAddr,
    advertised_endpoint_url: String,
    behavior: HostileBehavior,
    hits: Arc<AtomicUsize>,
) {
    while let Ok((client, _)) = listener.accept().await {
        let hits = Arc::clone(&hits);
        let advertised_endpoint_url = advertised_endpoint_url.clone();
        tokio::spawn(async move {
            if let Err(err) =
                proxy_connection(client, real_addr, &advertised_endpoint_url, behavior, hits).await
            {
                tracing::debug!("hostile proxy connection ended: {err}");
            }
        });
    }
}

async fn proxy_connection(
    mut client: TcpStream,
    real_addr: SocketAddr,
    advertised_endpoint_url: &str,
    behavior: HostileBehavior,
    hits: Arc<AtomicUsize>,
) -> io::Result<()> {
    let mut server = TcpStream::connect(real_addr).await?;
    let mut opn_requests = 0usize;

    loop {
        tokio::select! {
            frame = read_uacp_frame(&mut client) => {
                let Some(frame) = frame? else {
                    return Ok(());
                };
                if frame_chunk_type(&frame)? == Some(MessageChunkType::OpenSecureChannel) {
                    opn_requests += 1;
                }
                server.write_all(&frame).await?;
            }
            frame = read_uacp_frame(&mut server) => {
                let Some(mut frame) = frame? else {
                    return Ok(());
                };
                if behavior == HostileBehavior::StallChannelRenewal
                    && opn_requests >= 2
                    && frame_chunk_type(&frame)? == Some(MessageChunkType::OpenSecureChannel)
                {
                    hits.fetch_add(1, Ordering::SeqCst);
                    continue;
                }
                if let Some(mutated) = rewrite_get_endpoints_urls(&frame, advertised_endpoint_url)? {
                    frame = mutated;
                }
                if behavior == HostileBehavior::EmptyDeleteSubscriptionsResults {
                    if let Some(mutated) = empty_delete_subscriptions_results(&frame)? {
                        frame = mutated;
                        hits.fetch_add(1, Ordering::SeqCst);
                    }
                }
                client.write_all(&frame).await?;
            }
        }
    }
}

async fn read_uacp_frame<R>(reader: &mut R) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut header_bytes = [0u8; MESSAGE_HEADER_LEN];
    match reader.read_exact(&mut header_bytes).await {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }

    let header = <MessageHeader as SimpleBinaryDecodable>::decode(
        &mut Cursor::new(header_bytes),
        &Default::default(),
    )?;
    let message_size = header.message_size as usize;
    if message_size < MESSAGE_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid OPC UA frame size",
        ));
    }

    let mut frame = Vec::with_capacity(message_size);
    frame.extend_from_slice(&header_bytes);
    frame.resize(message_size, 0);
    reader.read_exact(&mut frame[MESSAGE_HEADER_LEN..]).await?;
    Ok(Some(frame))
}

fn empty_delete_subscriptions_results(frame: &[u8]) -> io::Result<Option<Vec<u8>>> {
    let Some(mut decoded_chunk) = decode_symmetric_message_chunk(frame)? else {
        return Ok(None);
    };
    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    let body_offset = decoded_chunk.cursor.position() as usize;
    let type_id = NodeId::decode(&mut decoded_chunk.cursor, &ctx)?;
    if type_id.as_object_id().ok()
        != Some(ObjectId::DeleteSubscriptionsResponse_Encoding_DefaultBinary)
    {
        return Ok(None);
    }

    let mut response = DeleteSubscriptionsResponse::decode(&mut decoded_chunk.cursor, &ctx)?;
    response.results = Some(Vec::new());

    encode_symmetric_message_chunk(
        &decoded_chunk.chunk_header,
        &decoded_chunk.security_header,
        &decoded_chunk.sequence_header,
        body_offset,
        &type_id,
        &response,
    )
    .map(Some)
}

fn rewrite_get_endpoints_urls(
    frame: &[u8],
    advertised_endpoint_url: &str,
) -> io::Result<Option<Vec<u8>>> {
    let Some(mut decoded_chunk) = decode_symmetric_message_chunk(frame)? else {
        return Ok(None);
    };
    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    let body_offset = decoded_chunk.cursor.position() as usize;
    let type_id = NodeId::decode(&mut decoded_chunk.cursor, &ctx)?;
    if type_id.as_object_id().ok() != Some(ObjectId::GetEndpointsResponse_Encoding_DefaultBinary) {
        return Ok(None);
    }

    let mut response = GetEndpointsResponse::decode(&mut decoded_chunk.cursor, &ctx)?;
    if let Some(endpoints) = response.endpoints.as_mut() {
        for endpoint in endpoints {
            endpoint.endpoint_url = UAString::from(advertised_endpoint_url);
        }
    }

    encode_symmetric_message_chunk(
        &decoded_chunk.chunk_header,
        &decoded_chunk.security_header,
        &decoded_chunk.sequence_header,
        body_offset,
        &type_id,
        &response,
    )
    .map(Some)
}

struct DecodedSymmetricMessageChunk<'a> {
    chunk_header: MessageChunkHeader,
    security_header: SymmetricSecurityHeader,
    sequence_header: SequenceHeader,
    cursor: Cursor<&'a [u8]>,
}

fn decode_symmetric_message_chunk(
    frame: &[u8],
) -> io::Result<Option<DecodedSymmetricMessageChunk<'_>>> {
    if frame_header(frame)?.message_type != MessageType::Chunk {
        return Ok(None);
    }
    if frame_chunk_type(frame)? != Some(MessageChunkType::Message) {
        return Ok(None);
    }

    let decoding_options = Default::default();
    let mut cursor = Cursor::new(frame);
    let chunk_header =
        <MessageChunkHeader as SimpleBinaryDecodable>::decode(&mut cursor, &decoding_options)?;
    if chunk_header.message_type != MessageChunkType::Message {
        return Ok(None);
    }
    let security_header =
        <SymmetricSecurityHeader as SimpleBinaryDecodable>::decode(&mut cursor, &decoding_options)?;
    let sequence_header =
        <SequenceHeader as SimpleBinaryDecodable>::decode(&mut cursor, &decoding_options)?;

    Ok(Some(DecodedSymmetricMessageChunk {
        chunk_header,
        security_header,
        sequence_header,
        cursor,
    }))
}

fn encode_symmetric_message_chunk<T>(
    chunk_header: &MessageChunkHeader,
    security_header: &SymmetricSecurityHeader,
    sequence_header: &SequenceHeader,
    body_offset: usize,
    type_id: &NodeId,
    message: &T,
) -> io::Result<Vec<u8>>
where
    T: BinaryEncodable,
{
    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    let mut body = Vec::with_capacity(type_id.byte_len(&ctx) + message.byte_len(&ctx));
    type_id.encode(&mut body, &ctx)?;
    message.encode(&mut body, &ctx)?;

    let mut out = Vec::with_capacity(body_offset + body.len());
    SimpleBinaryEncodable::encode(chunk_header, &mut out)?;
    SimpleBinaryEncodable::encode(security_header, &mut out)?;
    SimpleBinaryEncodable::encode(sequence_header, &mut out)?;
    out.extend_from_slice(&body);
    let message_size = u32::try_from(out.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "mutated OPC UA frame exceeds u32 message size",
        )
    })?;
    out[MESSAGE_SIZE_OFFSET..MESSAGE_SIZE_OFFSET + std::mem::size_of::<u32>()]
        .copy_from_slice(&message_size.to_le_bytes());
    Ok(out)
}

fn frame_header(frame: &[u8]) -> io::Result<MessageHeader> {
    if frame.len() < MESSAGE_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short OPC UA frame header",
        ));
    }
    Ok(<MessageHeader as SimpleBinaryDecodable>::decode(
        &mut Cursor::new(&frame[..MESSAGE_HEADER_LEN]),
        &Default::default(),
    )?)
}

fn frame_chunk_type(frame: &[u8]) -> io::Result<Option<MessageChunkType>> {
    if frame_header(frame)?.message_type != MessageType::Chunk {
        return Ok(None);
    }
    if frame.len() < MESSAGE_CHUNK_HEADER_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short OPC UA chunk header",
        ));
    }
    let header = <MessageChunkHeader as SimpleBinaryDecodable>::decode(
        &mut Cursor::new(&frame[..MESSAGE_CHUNK_HEADER_SIZE]),
        &Default::default(),
    )?;
    Ok(Some(header.message_type))
}

pub(crate) fn current_time_read() -> ReadValueId {
    ReadValueId::from(<VariableId as Into<NodeId>>::into(
        VariableId::Server_ServerStatus_CurrentTime,
    ))
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(test_name: &str) -> Self {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::current_dir()
            .expect("current directory")
            .join("target")
            .join("hostile_server_tests")
            .join(format!("{test_name}-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path)
            .expect("temporary hostile server test dir should be created");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
