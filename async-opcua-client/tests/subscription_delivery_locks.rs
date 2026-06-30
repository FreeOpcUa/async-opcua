#![allow(missing_docs)]

use std::{
    io::{self, Cursor},
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
        mpsc, Arc,
    },
    time::Duration,
};

use opcua_client::{
    transport::DefaultConnector, ClientBuilder, IdentityToken, MonitoredItemMap,
    OnSubscriptionNotificationCore, Session, SessionEventLoop,
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
    BinaryDecodable, BinaryEncodable, ContextOwned, ExtensionObject, GetEndpointsResponse,
    MessageSecurityMode, MonitoredItemCreateRequest, MonitoringMode, MonitoringParameters, NodeId,
    NotificationMessage, ObjectId, PublishRequest, ReadValueId, SimpleBinaryDecodable,
    SimpleBinaryEncodable, SubscriptionAcknowledgement, TimestampsToReturn, UAString, VariableId,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc as tokio_mpsc,
    task::JoinHandle,
};

use opcua_crypto::SecurityPolicy;

static NEXT_TEST_ID: AtomicUsize = AtomicUsize::new(0);

/// HPL-004 expected-red proof grounded in OPC-10000-4 5.14.1 and 5.14.5:
/// notification sequence acknowledgements must be retained for the next Publish
/// request, and user callback delivery must not run under subscription_state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publish_notification_callback_runs_outside_subscription_state() {
    let mut server = PublishAckProbeServer::start().await;
    let (session, event_loop) = server.connect().await;
    let event_loop_task = event_loop.spawn();

    tokio::time::timeout(Duration::from_secs(5), session.wait_for_connection())
        .await
        .expect("session should connect through publish ack probe proxy");

    let (observation_tx, mut observation_rx) = tokio_mpsc::unbounded_channel();
    let subscription_id_seen = Arc::new(AtomicU32::new(0));
    let callback = ReentrantSubscriptionCallback {
        session: Arc::clone(&session),
        subscription_id: Arc::clone(&subscription_id_seen),
        sent_observation: Arc::new(AtomicBool::new(false)),
        observation_tx,
    };

    let subscription_id = session
        .create_subscription(Duration::from_millis(100), 30, 10, 0, 0, true, callback)
        .await
        .expect("subscription should be created");
    subscription_id_seen.store(subscription_id, Ordering::SeqCst);

    let created = session
        .create_monitored_items(
            subscription_id,
            TimestampsToReturn::Both,
            vec![current_time_monitored_item()],
        )
        .await
        .expect("monitored item should be created");
    assert_eq!(created.len(), 1);
    assert!(
        created[0].result.status_code.is_good(),
        "monitored item create should succeed, got {}",
        created[0].result.status_code
    );

    let observation = tokio::time::timeout(Duration::from_secs(10), observation_rx.recv())
        .await
        .expect("data-change callback should run")
        .expect("callback observation channel should stay open");

    session.trigger_publish_now();
    let ack_observed = server
        .wait_for_ack(
            subscription_id,
            observation.sequence_number,
            Duration::from_secs(5),
        )
        .await;

    assert!(
        observation.reentry_completed,
        "callback re-entry into subscription_state timed out; Publish response delivery still holds subscription_state"
    );
    assert!(
        observation.subscription_known,
        "reentrant subscription_state access should see the delivered subscription"
    );
    assert!(
        ack_observed,
        "next PublishRequest should acknowledge notification sequence {} for subscription {}",
        observation.sequence_number, subscription_id
    );

    event_loop_task.abort();
}

#[derive(Debug)]
struct CallbackObservation {
    sequence_number: u32,
    reentry_completed: bool,
    subscription_known: bool,
}

struct ReentrantSubscriptionCallback {
    session: Arc<Session>,
    subscription_id: Arc<AtomicU32>,
    sent_observation: Arc<AtomicBool>,
    observation_tx: tokio_mpsc::UnboundedSender<CallbackObservation>,
}

impl OnSubscriptionNotificationCore for ReentrantSubscriptionCallback {
    fn on_subscription_notification(
        &mut self,
        notification: NotificationMessage,
        _monitored_items: MonitoredItemMap<'_>,
    ) {
        let has_notification_data = notification
            .notification_data
            .as_ref()
            .is_some_and(|data| !data.is_empty());
        if !has_notification_data || self.sent_observation.swap(true, Ordering::SeqCst) {
            return;
        }

        let session = Arc::clone(&self.session);
        let subscription_id = self.subscription_id.load(Ordering::SeqCst);
        let (reentry_tx, reentry_rx) = mpsc::channel();

        std::thread::spawn(move || {
            let state = session.subscription_state.lock();
            let _ = reentry_tx.send(state.subscription_exists(subscription_id));
        });

        let subscription_known = reentry_rx.recv_timeout(Duration::from_millis(200)).ok();
        let _ = self.observation_tx.send(CallbackObservation {
            sequence_number: notification.sequence_number,
            reentry_completed: subscription_known.is_some(),
            subscription_known: subscription_known.unwrap_or(false),
        });
    }
}

struct PublishAckProbeServer {
    endpoint_url: String,
    ack_rx: tokio_mpsc::UnboundedReceiver<SubscriptionAcknowledgement>,
    server_handle: ServerHandle,
    server_task: JoinHandle<()>,
    proxy_task: JoinHandle<()>,
    _temp_dir: TempDir,
}

impl PublishAckProbeServer {
    async fn start() -> Self {
        let temp_dir = TempDir::new("subscription-delivery-locks");
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
            .application_name("subscription_delivery_lock_test_server")
            .application_uri("urn:async-opcua:subscription-delivery-lock-test-server")
            .product_uri("urn:async-opcua:subscription-delivery-lock-test-server")
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
            .expect("publish ack probe server should build");

        let server_task = tokio::spawn(async move {
            server
                .run_with(real_listener)
                .await
                .expect("publish ack probe server should run");
        });

        let (ack_tx, ack_rx) = tokio_mpsc::unbounded_channel();
        let proxy_task = tokio::spawn(run_proxy(
            proxy_listener,
            real_addr,
            endpoint_url.clone(),
            ack_tx,
        ));

        Self {
            endpoint_url,
            ack_rx,
            server_handle,
            server_task,
            proxy_task,
            _temp_dir: temp_dir,
        }
    }

    async fn connect(&self) -> (Arc<Session>, SessionEventLoop<DefaultConnector>) {
        let mut client = ClientBuilder::new()
            .application_name("subscription_delivery_lock_test_client")
            .application_uri("urn:async-opcua:subscription-delivery-lock-test-client")
            .product_uri("urn:async-opcua:subscription-delivery-lock-test-client")
            .pki_dir(self._temp_dir.path.join("client-pki"))
            .create_sample_keypair(true)
            .trust_server_certs(true)
            .publish_timeout(Duration::from_secs(2))
            .client()
            .expect("publish ack probe client should build");

        client
            .connect_to_matching_endpoint(
                (
                    self.endpoint_url.as_str(),
                    SecurityPolicy::None.to_str(),
                    MessageSecurityMode::None,
                ),
                IdentityToken::Anonymous,
            )
            .await
            .expect("publish ack probe client should connect")
    }

    async fn wait_for_ack(
        &mut self,
        subscription_id: u32,
        sequence_number: u32,
        timeout: Duration,
    ) -> bool {
        tokio::time::timeout(timeout, async {
            while let Some(ack) = self.ack_rx.recv().await {
                if ack.subscription_id == subscription_id && ack.sequence_number == sequence_number
                {
                    return true;
                }
            }
            false
        })
        .await
        .unwrap_or(false)
    }
}

impl Drop for PublishAckProbeServer {
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
    ack_tx: tokio_mpsc::UnboundedSender<SubscriptionAcknowledgement>,
) {
    while let Ok((client, _)) = listener.accept().await {
        let advertised_endpoint_url = advertised_endpoint_url.clone();
        let ack_tx = ack_tx.clone();
        tokio::spawn(async move {
            if let Err(err) =
                proxy_connection(client, real_addr, &advertised_endpoint_url, ack_tx).await
            {
                tracing::debug!("publish ack probe proxy connection ended: {err}");
            }
        });
    }
}

async fn proxy_connection(
    mut client: TcpStream,
    real_addr: SocketAddr,
    advertised_endpoint_url: &str,
    ack_tx: tokio_mpsc::UnboundedSender<SubscriptionAcknowledgement>,
) -> io::Result<()> {
    let mut server = TcpStream::connect(real_addr).await?;

    loop {
        tokio::select! {
            frame = read_uacp_frame(&mut client) => {
                let Some(frame) = frame? else {
                    return Ok(());
                };
                if let Some(acks) = publish_request_acks(&frame)? {
                    for ack in acks {
                        let _ = ack_tx.send(ack);
                    }
                }
                server.write_all(&frame).await?;
            }
            frame = read_uacp_frame(&mut server) => {
                let Some(mut frame) = frame? else {
                    return Ok(());
                };
                if let Some(mutated) = rewrite_get_endpoints_urls(&frame, advertised_endpoint_url)? {
                    frame = mutated;
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

fn publish_request_acks(frame: &[u8]) -> io::Result<Option<Vec<SubscriptionAcknowledgement>>> {
    let Some(mut decoded_chunk) = decode_symmetric_message_chunk(frame)? else {
        return Ok(None);
    };
    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    let type_id = NodeId::decode(&mut decoded_chunk.cursor, &ctx)?;
    if type_id.as_object_id().ok() != Some(ObjectId::PublishRequest_Encoding_DefaultBinary) {
        return Ok(None);
    }

    let request = PublishRequest::decode(&mut decoded_chunk.cursor, &ctx)?;
    Ok(request.subscription_acknowledgements)
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

fn current_time_monitored_item() -> MonitoredItemCreateRequest {
    MonitoredItemCreateRequest::new(
        ReadValueId::from(<VariableId as Into<NodeId>>::into(
            VariableId::Server_ServerStatus_CurrentTime,
        )),
        MonitoringMode::Reporting,
        MonitoringParameters {
            client_handle: 1,
            sampling_interval: 50.0,
            filter: ExtensionObject::null(),
            queue_size: 1,
            discard_oldest: true,
        },
    )
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
            .join("subscription_delivery_lock_tests")
            .join(format!("{test_name}-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path)
            .expect("temporary subscription delivery lock test dir should be created");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
