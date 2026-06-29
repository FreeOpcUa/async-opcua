use std::path::PathBuf;

use opcua::crypto::SecurityPolicy;
use opcua::server::{
    Limits, OperationalLimits, ServerBuilder, SubscriptionLimits, ANONYMOUS_USER_TOKEN_ID,
};
use opcua::types::MessageSecurityMode;

const PROFILE_KEY: &str = "embedded";
const PROFILE_DISPLAY_NAME: &str = "Embedded 2017 UA Server Profile benchmark";
const PROFILE_TARGET_URI: &str = "http://opcfoundation.org/UA-Profile/Server/EmbeddedUA2017";
const PROFILE_SURFACE: &str = "Micro benchmark surface plus Basic256Sha256 secure endpoints";

fn profile_limits() -> Limits {
    Limits {
        max_sessions: 4,
        max_inflight_requests_per_connection: 64,
        subscriptions: SubscriptionLimits {
            max_subscriptions_per_session: 4,
            max_pending_publish_requests: 4,
            max_publish_requests_per_subscription: 2,
            max_monitored_items_per_sub: 100,
            max_notifications_per_publish: 100,
            ..Default::default()
        },
        operational: OperationalLimits {
            max_nodes_per_read: 256,
            max_nodes_per_write: 256,
            max_nodes_per_browse: 256,
            max_monitored_items_per_call: 100,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn build_server(pki_dir: impl Into<PathBuf>) -> ServerBuilder {
    let user_token_ids = [ANONYMOUS_USER_TOKEN_ID];

    ServerBuilder::new()
        .application_name(format!("async-opcua {PROFILE_DISPLAY_NAME}"))
        .application_uri(format!(
            "urn:async-opcua:foundation-profile-benchmark:{PROFILE_KEY}",
        ))
        .product_uri("https://github.com/freeopcua/async-opcua")
        .pki_dir(pki_dir)
        .limits(profile_limits())
        .add_endpoint(
            "none",
            (
                "/",
                SecurityPolicy::None,
                MessageSecurityMode::None,
                &user_token_ids as &[&str],
            ),
        )
        .add_endpoint(
            "basic256sha256_sign",
            (
                "/",
                SecurityPolicy::Basic256Sha256,
                MessageSecurityMode::Sign,
                &user_token_ids as &[&str],
            ),
        )
        .add_endpoint(
            "basic256sha256_sign_encrypt",
            (
                "/",
                SecurityPolicy::Basic256Sha256,
                MessageSecurityMode::SignAndEncrypt,
                &user_token_ids as &[&str],
            ),
        )
        .create_sample_keypair(true)
        .certificate_path("own/cert.der")
        .private_key_path("private/private.pem")
        .discovery_urls(vec!["/".to_owned()])
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    println!("Starting {PROFILE_DISPLAY_NAME} targeting {PROFILE_TARGET_URI} ({PROFILE_SURFACE})");

    let (server, handle) =
        build_server(format!("pki/foundation-profile-benchmark-{PROFILE_KEY}")).build()?;

    let shutdown = handle.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            shutdown.cancel();
        }
    });

    server.run().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, fs, time::SystemTime};

    #[test]
    fn benchmark_targets_expected_uri() {
        assert_eq!(
            PROFILE_TARGET_URI,
            "http://opcfoundation.org/UA-Profile/Server/EmbeddedUA2017"
        );
    }

    #[tokio::test]
    async fn benchmark_server_does_not_advertise_profile_conformance() {
        let pki_dir = unique_pki_dir();
        let (_server, handle) = build_server(&pki_dir)
            .build()
            .expect("profile benchmark server should build");

        assert!(handle.info().capabilities.profiles.is_empty());

        let _ = fs::remove_dir_all(pki_dir);
    }

    fn unique_pki_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        env::temp_dir().join(format!(
            "async-opcua-foundation-profile-benchmark-{PROFILE_KEY}-{}-{nonce}",
            std::process::id()
        ))
    }
}
