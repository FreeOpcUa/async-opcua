use opcua::server::ServerBuilder;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let (server, handle) = ServerBuilder::new_anonymous("async-opcua minimal server").build()?;

    let shutdown = handle.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            shutdown.cancel();
        }
    });

    server.run().await
}
