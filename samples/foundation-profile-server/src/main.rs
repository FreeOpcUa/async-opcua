#[cfg(not(any(feature = "nano", feature = "micro", feature = "embedded")))]
compile_error!(
    "select exactly one OPC Foundation profile benchmark feature: nano, micro, or embedded"
);

#[cfg(any(
    all(feature = "nano", feature = "micro"),
    all(feature = "nano", feature = "embedded"),
    all(feature = "micro", feature = "embedded")
))]
compile_error!(
    "select exactly one OPC Foundation profile benchmark feature: nano, micro, or embedded"
);

use std::path::PathBuf;

use opcua::crypto::SecurityPolicy;
use opcua::server::{Limits, ServerBuilder, ANONYMOUS_USER_TOKEN_ID};
use opcua::types::MessageSecurityMode;

#[cfg(feature = "nano")]
const NANO_PROFILE_URI: &str = "http://opcfoundation.org/UA-Profile/Server/NanoEmbeddedDevice2017";
#[cfg(feature = "micro")]
const MICRO_PROFILE_URI: &str =
    "http://opcfoundation.org/UA-Profile/Server/MicroEmbeddedDevice2017";
#[cfg(feature = "embedded")]
const EMBEDDED_PROFILE_URI: &str = "http://opcfoundation.org/UA-Profile/Server/EmbeddedUA2017";

#[derive(Clone, Copy, Debug)]
struct FoundationProfileBenchmark {
    key: &'static str,
    display_name: &'static str,
    target_uri: &'static str,
    surface: &'static str,
}

#[cfg(all(feature = "nano", not(any(feature = "micro", feature = "embedded"))))]
fn selected_profile() -> FoundationProfileBenchmark {
    FoundationProfileBenchmark {
        key: "nano",
        display_name: "Nano Embedded Device 2017 Server Profile benchmark",
        target_uri: NANO_PROFILE_URI,
        surface: "OPC UA TCP, SecurityPolicy None, Anonymous identity, sessions, read, and view",
    }
}

#[cfg(all(feature = "micro", not(any(feature = "nano", feature = "embedded"))))]
fn selected_profile() -> FoundationProfileBenchmark {
    FoundationProfileBenchmark {
        key: "micro",
        display_name: "Micro Embedded Device 2017 Server Profile benchmark",
        target_uri: MICRO_PROFILE_URI,
        surface: "Nano benchmark surface plus bounded subscription capacity",
    }
}

#[cfg(all(feature = "embedded", not(any(feature = "nano", feature = "micro"))))]
fn selected_profile() -> FoundationProfileBenchmark {
    FoundationProfileBenchmark {
        key: "embedded",
        display_name: "Embedded 2017 UA Server Profile benchmark",
        target_uri: EMBEDDED_PROFILE_URI,
        surface: "Micro benchmark surface plus Basic256Sha256 secure endpoints",
    }
}

#[cfg(any(
    not(any(feature = "nano", feature = "micro", feature = "embedded")),
    all(feature = "nano", feature = "micro"),
    all(feature = "nano", feature = "embedded"),
    all(feature = "micro", feature = "embedded")
))]
fn selected_profile() -> FoundationProfileBenchmark {
    unreachable!("profile feature selection is checked by compile_error")
}

fn profile_limits(profile: FoundationProfileBenchmark) -> Limits {
    let mut limits = Limits::default();

    match profile.key {
        "nano" => {
            limits.max_sessions = 1;
            limits.max_inflight_requests_per_connection = 16;
            limits.subscriptions.max_subscriptions_per_session = 0;
            limits.subscriptions.max_pending_publish_requests = 0;
            limits.subscriptions.max_publish_requests_per_subscription = 0;
            limits.subscriptions.max_monitored_items_per_sub = 1;
            limits.subscriptions.max_notifications_per_publish = 1;
            limits.operational.max_nodes_per_read = 64;
            limits.operational.max_nodes_per_write = 64;
            limits.operational.max_nodes_per_browse = 64;
            limits.operational.max_monitored_items_per_call = 1;
        }
        "micro" => {
            limits.max_sessions = 2;
            limits.max_inflight_requests_per_connection = 32;
            limits.subscriptions.max_subscriptions_per_session = 2;
            limits.subscriptions.max_pending_publish_requests = 2;
            limits.subscriptions.max_publish_requests_per_subscription = 1;
            limits.subscriptions.max_monitored_items_per_sub = 10;
            limits.subscriptions.max_notifications_per_publish = 10;
            limits.operational.max_nodes_per_read = 128;
            limits.operational.max_nodes_per_write = 128;
            limits.operational.max_nodes_per_browse = 128;
            limits.operational.max_monitored_items_per_call = 10;
        }
        "embedded" => {
            limits.max_sessions = 4;
            limits.max_inflight_requests_per_connection = 64;
            limits.subscriptions.max_subscriptions_per_session = 4;
            limits.subscriptions.max_pending_publish_requests = 4;
            limits.subscriptions.max_publish_requests_per_subscription = 2;
            limits.subscriptions.max_monitored_items_per_sub = 100;
            limits.subscriptions.max_notifications_per_publish = 100;
            limits.operational.max_nodes_per_read = 256;
            limits.operational.max_nodes_per_write = 256;
            limits.operational.max_nodes_per_browse = 256;
            limits.operational.max_monitored_items_per_call = 100;
        }
        _ => unreachable!("profile feature selection is compile-time checked"),
    }

    limits
}

fn build_server(profile: FoundationProfileBenchmark, pki_dir: impl Into<PathBuf>) -> ServerBuilder {
    let user_token_ids = [ANONYMOUS_USER_TOKEN_ID];

    let mut builder = ServerBuilder::new()
        .application_name(format!("async-opcua {}", profile.display_name))
        .application_uri(format!(
            "urn:async-opcua:foundation-profile-benchmark:{}",
            profile.key
        ))
        .product_uri("https://github.com/freeopcua/async-opcua")
        .pki_dir(pki_dir)
        .limits(profile_limits(profile))
        .add_endpoint(
            "none",
            (
                "/",
                SecurityPolicy::None,
                MessageSecurityMode::None,
                &user_token_ids as &[&str],
            ),
        )
        .discovery_urls(vec!["/".to_owned()]);

    if profile.key == "embedded" {
        builder = builder
            .create_sample_keypair(true)
            .certificate_path("own/cert.der")
            .private_key_path("private/private.pem")
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
            );
    }

    builder
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let profile = selected_profile();
    println!(
        "Starting {} targeting {} ({})",
        profile.display_name, profile.target_uri, profile.surface
    );

    let (server, handle) = build_server(
        profile,
        format!("pki/foundation-profile-benchmark-{}", profile.key),
    )
    .build()?;

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
    fn selected_profile_targets_expected_uri() {
        let profile = selected_profile();

        #[cfg(feature = "nano")]
        assert_eq!(profile.target_uri, NANO_PROFILE_URI);
        #[cfg(feature = "micro")]
        assert_eq!(profile.target_uri, MICRO_PROFILE_URI);
        #[cfg(feature = "embedded")]
        assert_eq!(profile.target_uri, EMBEDDED_PROFILE_URI);
    }

    #[tokio::test]
    async fn benchmark_server_does_not_advertise_profile_conformance() {
        let profile = selected_profile();
        let pki_dir = unique_pki_dir(profile.key);
        let (_server, handle) = build_server(profile, &pki_dir)
            .build()
            .expect("profile benchmark server should build");

        assert!(handle.info().capabilities.profiles.is_empty());

        let _ = fs::remove_dir_all(pki_dir);
    }

    fn unique_pki_dir(profile: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        env::temp_dir().join(format!(
            "async-opcua-foundation-profile-benchmark-{profile}-{}-{nonce}",
            std::process::id()
        ))
    }
}
