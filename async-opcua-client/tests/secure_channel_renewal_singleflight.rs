//! Focused SecureChannel renewal single-flight tests.

#![allow(missing_docs)]

use std::{
    io::{self, Cursor},
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use opcua_client::{
    transport::DefaultConnector, ClientBuilder, IdentityToken, Session, SessionEventLoop,
};
use opcua_core::comms::{
    message_chunk::{MessageChunkHeader, MessageChunkType, MESSAGE_CHUNK_HEADER_SIZE},
    security_header::{SecurityHeader, SequenceHeader},
    tcp_types::{MessageHeader, MessageType, MESSAGE_HEADER_LEN},
};
use opcua_crypto::SecurityPolicy;
use opcua_server::{ServerBuilder, ServerHandle, ANONYMOUS_USER_TOKEN_ID};
use opcua_types::{
    BinaryDecodable, BinaryEncodable, ContextOwned, GetEndpointsResponse, MessageSecurityMode,
    NodeId, ObjectId, ReadValueId, SimpleBinaryDecodable, TimestampsToReturn, UAString, VariableId,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

static NEXT_TEST_ID: AtomicUsize = AtomicUsize::new(0);

/// OPC-10000-6 6.7.4: concurrent waiters that discover an expiring SecureChannel
/// must share one renewal and continue on one valid renewed channel state.
#[tokio::test]
async fn secure_channel_renewal_singleflight_opc10000_6_6_7_4_concurrent_waiters_share_one_renewal()
{
    const CHANNEL_LIFETIME_MS: u32 = 1_200;
    const WAITER_COUNT: usize = 12;

    let proxy = CountingRenewalServer::start().await;
    let (session, event_loop) = proxy
        .connect_with(|builder| {
            builder
                .channel_lifetime(CHANNEL_LIFETIME_MS)
                .keep_alive_interval(Duration::from_millis(250))
                .session_retry_limit(0)
        })
        .await;
    let event_loop_task = event_loop.spawn();

    tokio::time::timeout(Duration::from_secs(5), session.wait_for_connection())
        .await
        .expect("session should connect through counting proxy");

    let initial = tokio::time::timeout(
        Duration::from_secs(3),
        session.read(&[current_time_read()], TimestampsToReturn::Both, 0.0),
    )
    .await
    .expect("initial read should not hang")
    .expect("initial read should succeed");
    assert_eq!(initial.len(), 1);

    let open_secure_channel_count_before = proxy.open_secure_channel_requests();

    tokio::time::sleep(Duration::from_millis(
        u64::from(CHANNEL_LIFETIME_MS) * 4 / 5,
    ))
    .await;

    let barrier = Arc::new(tokio::sync::Barrier::new(WAITER_COUNT + 1));
    let mut waiters = Vec::with_capacity(WAITER_COUNT);
    for _ in 0..WAITER_COUNT {
        let session = Arc::clone(&session);
        let barrier = Arc::clone(&barrier);
        waiters.push(tokio::spawn(async move {
            barrier.wait().await;
            tokio::time::timeout(
                Duration::from_secs(5),
                session.read(&[current_time_read()], TimestampsToReturn::Both, 0.0),
            )
            .await
            .expect("concurrent read should not hang")
            .expect("concurrent read should succeed")
        }));
    }

    barrier.wait().await;

    for waiter in waiters {
        let values = waiter.await.expect("read task should not panic");
        assert_eq!(values.len(), 1);
    }

    let renewed_open_secure_channels =
        proxy.open_secure_channel_requests() - open_secure_channel_count_before;
    assert_eq!(
        renewed_open_secure_channels, 1,
        "concurrent renewal waiters must be served by one Renew OpenSecureChannel attempt"
    );

    event_loop_task.abort();
}

/// OPC-10000-6 6.7.4: cancellation while a SecureChannel renewal is in flight
/// must not wedge later callers waiting for the renewed or closed channel state.
#[tokio::test]
async fn secure_channel_renewal_singleflight_opc10000_6_6_7_4_cancelled_waiter_does_not_wedge_later_reads(
) {
    const CHANNEL_LIFETIME_MS: u32 = 1_200;

    let proxy =
        CountingRenewalServer::start_with_renewal_response_delay(Duration::from_secs(2)).await;
    let (session, event_loop) = proxy
        .connect_with(|builder| {
            builder
                .channel_lifetime(CHANNEL_LIFETIME_MS)
                .keep_alive_interval(Duration::from_millis(250))
                .session_retry_limit(0)
        })
        .await;
    let event_loop_task = event_loop.spawn();

    tokio::time::timeout(Duration::from_secs(5), session.wait_for_connection())
        .await
        .expect("session should connect through counting proxy");

    let initial = tokio::time::timeout(
        Duration::from_secs(3),
        session.read(&[current_time_read()], TimestampsToReturn::Both, 0.0),
    )
    .await
    .expect("initial read should not hang")
    .expect("initial read should succeed");
    assert_eq!(initial.len(), 1);

    let open_secure_channel_count_before = proxy.open_secure_channel_requests();

    tokio::time::sleep(Duration::from_millis(
        u64::from(CHANNEL_LIFETIME_MS) * 4 / 5,
    ))
    .await;

    let renewing_session = Arc::clone(&session);
    let cancelled_waiter = tokio::spawn(async move {
        renewing_session
            .read(&[current_time_read()], TimestampsToReturn::Both, 0.0)
            .await
    });

    proxy
        .wait_for_open_secure_channel_requests(open_secure_channel_count_before + 1)
        .await;
    cancelled_waiter.abort();
    assert!(
        cancelled_waiter.await.unwrap_err().is_cancelled(),
        "renewal waiter should be cancelled while its renewal response is delayed"
    );

    let later_read = tokio::time::timeout(
        Duration::from_secs(8),
        session.read(&[current_time_read()], TimestampsToReturn::Both, 0.0),
    )
    .await
    .expect("later read after cancelled renewal waiter should not hang");
    if let Ok(values) = later_read {
        assert_eq!(values.len(), 1);
    }

    event_loop_task.abort();
}

/// OPC-10000-6 6.7.4: a failed SecureChannel renewal must not install a
/// renewed token or leave the triggering caller waiting indefinitely.
#[tokio::test]
async fn secure_channel_renewal_singleflight_opc10000_6_6_7_4_renewal_failure_closes_boundedly() {
    const CHANNEL_LIFETIME_MS: u32 = 1_200;

    let proxy = CountingRenewalServer::start_with_renewal_behavior(
        RenewalResponseBehavior::CloseConnectionOnRenewal,
    )
    .await;
    let (session, event_loop) = proxy
        .connect_with(|builder| {
            builder
                .channel_lifetime(CHANNEL_LIFETIME_MS)
                .keep_alive_interval(Duration::from_millis(250))
                .session_retry_limit(0)
        })
        .await;
    let event_loop_task = event_loop.spawn();

    tokio::time::timeout(Duration::from_secs(5), session.wait_for_connection())
        .await
        .expect("session should connect through renewal-failure proxy");

    let initial = tokio::time::timeout(
        Duration::from_secs(3),
        session.read(&[current_time_read()], TimestampsToReturn::Both, 0.0),
    )
    .await
    .expect("initial read should not hang")
    .expect("initial read should succeed before renewal failure");
    assert_eq!(initial.len(), 1);

    let open_secure_channel_count_before = proxy.open_secure_channel_requests();

    tokio::time::sleep(Duration::from_millis(
        u64::from(CHANNEL_LIFETIME_MS) * 4 / 5,
    ))
    .await;

    let failed_renewal_read = tokio::time::timeout(
        Duration::from_secs(5),
        session.read(&[current_time_read()], TimestampsToReturn::Both, 0.0),
    )
    .await
    .expect("renewal-triggering read should fail or close without hanging");
    assert!(
        failed_renewal_read.is_err(),
        "renewal failure must not produce a successful read on an invalid renewed state"
    );

    proxy
        .wait_for_open_secure_channel_requests(open_secure_channel_count_before + 1)
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        proxy.forwarded_renewal_responses(),
        0,
        "the proxy closed the renewal path before forwarding a renewed SecureChannel state"
    );

    event_loop_task.abort();
}

/// OPC-10000-6 6.7.2.4: Renew OpenSecureChannel request/response ordering and
/// request-id correlation must remain intact before normal messages continue.
#[tokio::test]
async fn secure_channel_renewal_singleflight_opc10000_6_6_7_2_4_renewal_request_ordering_is_preserved(
) {
    const CHANNEL_LIFETIME_MS: u32 = 1_200;
    const WAITER_COUNT: usize = 8;

    let proxy =
        CountingRenewalServer::start_with_renewal_response_delay(Duration::from_millis(450)).await;
    let (session, event_loop) = proxy
        .connect_with(|builder| {
            builder
                .channel_lifetime(CHANNEL_LIFETIME_MS)
                .keep_alive_interval(Duration::from_millis(250))
                .session_retry_limit(0)
        })
        .await;
    let event_loop_task = event_loop.spawn();

    tokio::time::timeout(Duration::from_secs(5), session.wait_for_connection())
        .await
        .expect("session should connect through ordering proxy");

    let initial = tokio::time::timeout(
        Duration::from_secs(3),
        session.read(&[current_time_read()], TimestampsToReturn::Both, 0.0),
    )
    .await
    .expect("initial read should not hang")
    .expect("initial read should succeed");
    assert_eq!(initial.len(), 1);

    let open_secure_channel_count_before = proxy.open_secure_channel_requests();
    let events_before_renewal = proxy.observed_events().len();

    tokio::time::sleep(Duration::from_millis(
        u64::from(CHANNEL_LIFETIME_MS) * 4 / 5,
    ))
    .await;

    let first_waiter_session = Arc::clone(&session);
    let first_waiter = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(5),
            first_waiter_session.read(&[current_time_read()], TimestampsToReturn::Both, 0.0),
        )
        .await
        .expect("renewal-triggering read should not hang")
        .expect("renewal-triggering read should succeed")
    });

    proxy
        .wait_for_open_secure_channel_requests(open_secure_channel_count_before + 1)
        .await;

    let mut waiters = Vec::with_capacity(WAITER_COUNT);
    for _ in 0..WAITER_COUNT {
        let session = Arc::clone(&session);
        waiters.push(tokio::spawn(async move {
            tokio::time::timeout(
                Duration::from_secs(5),
                session.read(&[current_time_read()], TimestampsToReturn::Both, 0.0),
            )
            .await
            .expect("post-renewal read should not hang")
            .expect("post-renewal read should succeed")
        }));
    }

    proxy.wait_for_forwarded_renewal_responses(1).await;

    let values = first_waiter.await.expect("renewal waiter should not panic");
    assert_eq!(values.len(), 1);
    for waiter in waiters {
        let values = waiter.await.expect("read task should not panic");
        assert_eq!(values.len(), 1);
    }

    let events = proxy.observed_events();
    let renewal_open_index = events
        .iter()
        .enumerate()
        .find_map(|(index, event)| {
            (index >= events_before_renewal
                && matches!(event, ObservedProxyEvent::ClientOpenSecureChannel { .. }))
            .then_some(index)
        })
        .expect("proxy should observe the Renew OpenSecureChannel request");
    let renewal_request_id = match events[renewal_open_index] {
        ObservedProxyEvent::ClientOpenSecureChannel { request_id, .. } => request_id,
        _ => unreachable!("renewal_open_index points at a ClientOpenSecureChannel event"),
    };
    let renewal_response_index = events
        .iter()
        .position(|event| {
            matches!(
                event,
                ObservedProxyEvent::RenewalResponseForwarded { request_id }
                    if *request_id == renewal_request_id
            )
        })
        .expect("proxy should observe the correlated Renew OpenSecureChannel response");

    assert!(
        events[renewal_open_index + 1..renewal_response_index]
            .iter()
            .all(|event| !matches!(event, ObservedProxyEvent::ClientMessage { .. })),
        "normal service messages must not be sent before the Renew OpenSecureChannel response is forwarded: {events:?}"
    );
    assert!(
        events[renewal_response_index + 1..]
            .iter()
            .any(|event| matches!(event, ObservedProxyEvent::ClientMessage { .. })),
        "normal service messages should resume after the Renew OpenSecureChannel response is correlated: {events:?}"
    );

    event_loop_task.abort();
}

struct CountingRenewalServer {
    endpoint_url: String,
    open_secure_channel_requests: Arc<AtomicUsize>,
    forwarded_renewal_responses: Arc<AtomicUsize>,
    observed_events: Arc<Mutex<Vec<ObservedProxyEvent>>>,
    server_handle: ServerHandle,
    server_task: JoinHandle<()>,
    proxy_task: JoinHandle<()>,
    _temp_dir: TempDir,
}

impl CountingRenewalServer {
    async fn start() -> Self {
        Self::start_with_renewal_response_delay(Duration::from_millis(150)).await
    }

    async fn start_with_renewal_response_delay(renewal_response_delay: Duration) -> Self {
        Self::start_with_renewal_behavior(RenewalResponseBehavior::Delay(renewal_response_delay))
            .await
    }

    async fn start_with_renewal_behavior(
        renewal_response_behavior: RenewalResponseBehavior,
    ) -> Self {
        let temp_dir = TempDir::new("secure-channel-renewal-singleflight");
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
            .application_name("secure_channel_renewal_singleflight_server")
            .application_uri("urn:async-opcua:secure-channel-renewal-singleflight-server")
            .product_uri("urn:async-opcua:secure-channel-renewal-singleflight-server")
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
            .expect("test server should build");

        let server_task = tokio::spawn(async move {
            server
                .run_with(real_listener)
                .await
                .expect("test server should run");
        });

        let open_secure_channel_requests = Arc::new(AtomicUsize::new(0));
        let forwarded_renewal_responses = Arc::new(AtomicUsize::new(0));
        let observed_events = Arc::new(Mutex::new(Vec::new()));
        let proxy_task = tokio::spawn(run_counting_proxy(
            proxy_listener,
            real_addr,
            endpoint_url.clone(),
            Arc::clone(&open_secure_channel_requests),
            Arc::clone(&forwarded_renewal_responses),
            Arc::clone(&observed_events),
            renewal_response_behavior,
        ));

        Self {
            endpoint_url,
            open_secure_channel_requests,
            forwarded_renewal_responses,
            observed_events,
            server_handle,
            server_task,
            proxy_task,
            _temp_dir: temp_dir,
        }
    }

    fn open_secure_channel_requests(&self) -> usize {
        self.open_secure_channel_requests.load(Ordering::SeqCst)
    }

    fn forwarded_renewal_responses(&self) -> usize {
        self.forwarded_renewal_responses.load(Ordering::SeqCst)
    }

    fn observed_events(&self) -> Vec<ObservedProxyEvent> {
        self.observed_events
            .lock()
            .expect("proxy event log should not be poisoned")
            .clone()
    }

    async fn wait_for_open_secure_channel_requests(&self, expected: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.open_secure_channel_requests() < expected {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("proxy should observe expected OpenSecureChannel request count");
    }

    async fn wait_for_forwarded_renewal_responses(&self, expected: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.forwarded_renewal_responses() < expected {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("proxy should forward expected Renew OpenSecureChannel response count");
    }

    async fn connect_with(
        &self,
        customize: impl FnOnce(ClientBuilder) -> ClientBuilder,
    ) -> (Arc<Session>, SessionEventLoop<DefaultConnector>) {
        let builder = ClientBuilder::new()
            .application_name("secure_channel_renewal_singleflight_client")
            .application_uri("urn:async-opcua:secure-channel-renewal-singleflight-client")
            .product_uri("urn:async-opcua:secure-channel-renewal-singleflight-client")
            .pki_dir(self._temp_dir.path.join("client-pki"))
            .create_sample_keypair(true)
            .trust_server_certs(true);
        let mut client = customize(builder)
            .client()
            .expect("test client should build");

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
            .expect("test client should connect")
    }
}

impl Drop for CountingRenewalServer {
    fn drop(&mut self) {
        self.server_handle.cancel();
        self.server_task.abort();
        self.proxy_task.abort();
    }
}

async fn run_counting_proxy(
    listener: TcpListener,
    real_addr: SocketAddr,
    advertised_endpoint_url: String,
    open_secure_channel_requests: Arc<AtomicUsize>,
    forwarded_renewal_responses: Arc<AtomicUsize>,
    observed_events: Arc<Mutex<Vec<ObservedProxyEvent>>>,
    renewal_response_behavior: RenewalResponseBehavior,
) {
    while let Ok((client, _)) = listener.accept().await {
        let advertised_endpoint_url = advertised_endpoint_url.clone();
        let open_secure_channel_requests = Arc::clone(&open_secure_channel_requests);
        let forwarded_renewal_responses = Arc::clone(&forwarded_renewal_responses);
        let observed_events = Arc::clone(&observed_events);
        tokio::spawn(async move {
            if let Err(err) = proxy_connection(
                client,
                real_addr,
                &advertised_endpoint_url,
                open_secure_channel_requests,
                forwarded_renewal_responses,
                observed_events,
                renewal_response_behavior,
            )
            .await
            {
                tracing::debug!("counting renewal proxy connection ended: {err}");
            }
        });
    }
}

async fn proxy_connection(
    mut client: TcpStream,
    real_addr: SocketAddr,
    advertised_endpoint_url: &str,
    open_secure_channel_requests: Arc<AtomicUsize>,
    forwarded_renewal_responses: Arc<AtomicUsize>,
    observed_events: Arc<Mutex<Vec<ObservedProxyEvent>>>,
    renewal_response_behavior: RenewalResponseBehavior,
) -> io::Result<()> {
    let mut server = TcpStream::connect(real_addr).await?;
    let mut connection_open_secure_channel_requests = 0usize;

    loop {
        tokio::select! {
            frame = read_uacp_frame(&mut client) => {
                let Some(frame) = frame? else {
                    return Ok(());
                };
                if frame_chunk_type(&frame)? == Some(MessageChunkType::OpenSecureChannel) {
                    connection_open_secure_channel_requests += 1;
                    open_secure_channel_requests.fetch_add(1, Ordering::SeqCst);
                    record_proxy_event(
                        &observed_events,
                        ObservedProxyEvent::ClientOpenSecureChannel {
                            ordinal: connection_open_secure_channel_requests,
                            request_id: frame_sequence_header(&frame)?
                                .map(|header| header.request_id)
                                .unwrap_or(0),
                        },
                    );
                } else if frame_chunk_type(&frame)? == Some(MessageChunkType::Message) {
                    record_proxy_event(
                        &observed_events,
                        ObservedProxyEvent::ClientMessage {
                            request_id: frame_sequence_header(&frame)?
                                .map(|header| header.request_id)
                                .unwrap_or(0),
                        },
                    );
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
                if connection_open_secure_channel_requests >= 2
                    && frame_chunk_type(&frame)? == Some(MessageChunkType::OpenSecureChannel)
                {
                    match renewal_response_behavior {
                        RenewalResponseBehavior::Delay(delay) => {
                            delay_renewal_response_while_observing_client(
                                &mut client,
                                &mut server,
                                delay,
                                &observed_events,
                            )
                            .await?;
                            forwarded_renewal_responses.fetch_add(1, Ordering::SeqCst);
                            record_proxy_event(
                                &observed_events,
                                ObservedProxyEvent::RenewalResponseForwarded {
                                    request_id: frame_sequence_header(&frame)?
                                        .map(|header| header.request_id)
                                        .unwrap_or(0),
                                },
                            );
                        }
                        RenewalResponseBehavior::CloseConnectionOnRenewal => return Ok(()),
                    }
                }
                client.write_all(&frame).await?;
            }
        }
    }
}

async fn delay_renewal_response_while_observing_client(
    client: &mut TcpStream,
    server: &mut TcpStream,
    delay: Duration,
    observed_events: &Arc<Mutex<Vec<ObservedProxyEvent>>>,
) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + delay;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => return Ok(()),
            frame = read_uacp_frame(client) => {
                let Some(frame) = frame? else {
                    return Ok(());
                };
                if frame_chunk_type(&frame)? == Some(MessageChunkType::OpenSecureChannel) {
                    record_proxy_event(
                        observed_events,
                        ObservedProxyEvent::ClientOpenSecureChannel {
                            ordinal: 0,
                            request_id: frame_sequence_header(&frame)?
                                .map(|header| header.request_id)
                                .unwrap_or(0),
                        },
                    );
                } else if frame_chunk_type(&frame)? == Some(MessageChunkType::Message) {
                    record_proxy_event(
                        observed_events,
                        ObservedProxyEvent::ClientMessage {
                            request_id: frame_sequence_header(&frame)?
                                .map(|header| header.request_id)
                                .unwrap_or(0),
                        },
                    );
                }
                server.write_all(&frame).await?;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObservedProxyEvent {
    ClientOpenSecureChannel { ordinal: usize, request_id: u32 },
    ClientMessage { request_id: u32 },
    RenewalResponseForwarded { request_id: u32 },
}

fn record_proxy_event(
    observed_events: &Arc<Mutex<Vec<ObservedProxyEvent>>>,
    event: ObservedProxyEvent,
) {
    observed_events
        .lock()
        .expect("proxy event log should not be poisoned")
        .push(event);
}

#[derive(Clone, Copy)]
enum RenewalResponseBehavior {
    Delay(Duration),
    CloseConnectionOnRenewal,
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

fn rewrite_get_endpoints_urls(
    frame: &[u8],
    advertised_endpoint_url: &str,
) -> io::Result<Option<Vec<u8>>> {
    if frame_header(frame)?.message_type != MessageType::Chunk {
        return Ok(None);
    }
    if frame_chunk_type(frame)? != Some(MessageChunkType::Message) {
        return Ok(None);
    }

    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    let mut cursor = Cursor::new(frame);
    let chunk_header =
        <MessageChunkHeader as SimpleBinaryDecodable>::decode(&mut cursor, &Default::default())?;
    let body_offset = cursor.position() as usize;
    let type_id = NodeId::decode(&mut cursor, &ctx)?;
    if type_id.as_object_id().ok() != Some(ObjectId::GetEndpointsResponse_Encoding_DefaultBinary) {
        return Ok(None);
    }

    let mut response = GetEndpointsResponse::decode(&mut cursor, &ctx)?;
    if let Some(endpoints) = response.endpoints.as_mut() {
        for endpoint in endpoints {
            endpoint.endpoint_url = UAString::from(advertised_endpoint_url);
        }
    }

    let mut body = Vec::with_capacity(type_id.byte_len(&ctx) + response.byte_len(&ctx));
    type_id.encode(&mut body, &ctx)?;
    response.encode(&mut body, &ctx)?;

    let mut out = Vec::with_capacity(body_offset + body.len());
    out.extend_from_slice(&frame[..body_offset]);
    out.extend_from_slice(&body);
    let message_size = u32::try_from(out.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "mutated OPC UA frame exceeds u32 message size",
        )
    })?;
    out[4..8].copy_from_slice(&message_size.to_le_bytes());
    debug_assert_eq!(
        chunk_header.message_type,
        MessageChunkType::Message,
        "decoded chunk type is guarded above"
    );
    Ok(Some(out))
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

fn frame_sequence_header(frame: &[u8]) -> io::Result<Option<SequenceHeader>> {
    if frame_header(frame)?.message_type != MessageType::Chunk {
        return Ok(None);
    }

    let mut cursor = Cursor::new(frame);
    let chunk_header =
        <MessageChunkHeader as SimpleBinaryDecodable>::decode(&mut cursor, &Default::default())?;
    let _security_header = SecurityHeader::decode_from_stream(
        &mut cursor,
        chunk_header.message_type.is_open_secure_channel(),
        &Default::default(),
    )?;
    Ok(Some(<SequenceHeader as SimpleBinaryDecodable>::decode(
        &mut cursor,
        &Default::default(),
    )?))
}

fn current_time_read() -> ReadValueId {
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
            .join("secure_channel_renewal_singleflight_tests")
            .join(format!("{test_name}-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temporary test dir should be created");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
