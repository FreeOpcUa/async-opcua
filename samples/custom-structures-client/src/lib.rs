use std::sync::Arc;

use opcua::{
    client::{ClientBuilder, IdentityToken, Session},
    crypto::SecurityPolicy,
    types::{MessageSecurityMode, StatusCode, UserTokenPolicy},
};
use tokio::task::JoinHandle;

pub const NAMESPACE_URI: &str = "urn:DemoServer";

struct Args {
    help: bool,
    url: String,
}

impl Args {
    pub fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
        let mut args = pico_args::Arguments::from_env();
        Ok(Args {
            help: args.contains(["-h", "--help"]),
            url: args
                .opt_value_from_str("--url")?
                .unwrap_or_else(|| String::from(DEFAULT_URL)),
        })
    }

    pub fn usage() {
        println!(
            r#"Simple Client
Usage:
  -h, --help   Show help
  --url [url]  Url to connect to (default: {DEFAULT_URL})"#
        );
    }
}

pub const DEFAULT_URL: &str = "opc.tcp://localhost:4855";

pub async fn client_connect(
) -> Result<(Arc<Session>, JoinHandle<StatusCode>, u16), Box<dyn std::error::Error>> {
    // Read command line arguments
    let args = Args::parse_args()?;
    if args.help {
        Args::usage();
        return Err("Help requested, exiting".into());
    }
    // Optional - enable OPC UA logging
    env_logger::init();

    // Make the client configuration
    let mut client = ClientBuilder::new()
        .application_name("Simple Client")
        .application_uri("urn:SimpleClient")
        .product_uri("urn:SimpleClient")
        .trust_server_certs(true)
        .create_sample_keypair(true)
        .session_retry_limit(3)
        .client()
        .unwrap();

    let (session, event_loop) = client
        .connect_to_matching_endpoint(
            (
                args.url.as_ref(),
                SecurityPolicy::None.to_str(),
                MessageSecurityMode::None,
                UserTokenPolicy::anonymous(),
            ),
            IdentityToken::Anonymous,
        )
        .await
        .unwrap();

    let handle = event_loop.spawn();
    session.wait_for_connection().await;

    let ns = session
        .get_namespace_index(NAMESPACE_URI)
        .await
        .map_err(|e| format!("Error getting namespace index {e:?}"))?;

    Ok((session, handle, ns))
}
