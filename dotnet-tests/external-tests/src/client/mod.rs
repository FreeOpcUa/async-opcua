use std::{
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};

use opcua::{
    client::{ClientBuilder, Session},
    types::{NodeId, Variant},
};

use crate::common::{spawn_proc, InMessage, ProcessWrapper, UpdateValueMessage};

pub struct ClientTestState {
    pub server: ProcessWrapper,
    pub handle: tokio::task::JoinHandle<()>,
}

impl ClientTestState {
    pub async fn new() -> Self {
        let (server, server_loop) = spawn_proc(
            "dotnet-tests/TestServer/bin/Debug/net8.0/TestServer",
            "dotnet-tests/TestServer.Config.xml",
        );
        let handle = tokio::task::spawn(server_loop.run());

        Self { server, handle }
    }

    pub async fn send_change_message(&self, session: &Session, node_id: NodeId, value: Variant) {
        let msg = {
            let context = session.context();
            let ctx_r = context.read();
            InMessage::ChangeValue(UpdateValueMessage::new(node_id, value, &ctx_r.context()))
        };

        self.server.send_message(msg).await;
    }
}

pub static TEST_COUNTER: AtomicU16 = AtomicU16::new(0);

pub fn make_client(quick_timeout: bool) -> ClientBuilder {
    let test_id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);

    let client = ClientBuilder::new()
        .application_name("external_test_client")
        .application_uri("x")
        .pki_dir(format!("./pki-ext-client/{test_id}"))
        .create_sample_keypair(true)
        .trust_server_certs(true)
        .session_retry_initial(Duration::from_millis(200))
        .max_array_length(1024 * 1024 * 64)
        .max_chunk_count(64);

    if quick_timeout {
        client.session_retry_limit(1)
    } else {
        client
    }
}
