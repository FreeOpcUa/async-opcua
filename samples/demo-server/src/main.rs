// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! This is a demo server for OPC UA. It demonstrates most of the features of OPC UA for Rust.
//!
//! * Variables for each type
//! * Variables with arrays of types
//! * Stress variables that change rapidly
//! * Method
//! * Events
//! * Http server with metrics (http://localhost:8585)
//!
//! If you want a simpler`simple-server`
//!
//! Use simple-server to understand a terse and simple example.

#[macro_use]
extern crate log;

use std::{fs, path::PathBuf, sync::Arc};

use opcua::core::config::Config;
use opcua::crypto::ecc::EccCurve as CryptoEccCurve;
use opcua::crypto::{X509Data, X509};
use opcua::server::{
    diagnostics::NamespaceMetadata,
    node_manager::memory::{simple_node_manager, CoreNodeManager, SimpleNodeManager},
    Server, ServerBuilder, ServerConfig, ServerHandle,
};

mod alarms;
mod control;
mod customs;
mod history;
mod machine;
mod methods;
mod scalar;

const NAMESPACE_URI: &str = "urn:DemoServer";

#[derive(Clone, Copy)]
enum EccCurve {
    P256,
    P384,
}

struct Args {
    help: bool,
    raise_events: bool,
    config_path: PathBuf,
    content_path: PathBuf,
    ecc: Option<EccCurve>,
}

impl Default for Args {
    fn default() -> Self {
        let mut raise_events = false;

        let mut config_path = PathBuf::from("../server.test.conf");
        if !config_path.exists() {
            raise_events = true;
            config_path = PathBuf::from("server.conf");
            if !config_path.exists() {
                config_path = PathBuf::from("../server.conf");
            }
        }

        let content_path = if PathBuf::from("./index.html").exists() {
            // For docker image or custom deployment
            PathBuf::from(".")
        } else {
            // Server src dir
            PathBuf::from("../../async-opcua/src/server/html")
        };

        Self {
            help: false,
            raise_events,
            config_path,
            content_path,
            ecc: None,
        }
    }
}

fn parse_curve(value: &str) -> Result<EccCurve, &'static str> {
    match value.to_ascii_lowercase().as_str() {
        "p256" | "nistp256" => Ok(EccCurve::P256),
        "p384" | "nistp384" => Ok(EccCurve::P384),
        _ => Err("curve must be p256 or p384"),
    }
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "localhost".into())
}

fn provision_ecc_certificate(curve: EccCurve, config: &ServerConfig) {
    let own_dir = config.pki_dir.join("own");
    let private_dir = config.pki_dir.join("private");
    fs::create_dir_all(&own_dir).unwrap();
    fs::create_dir_all(&private_dir).unwrap();

    let crypto_curve = match curve {
        EccCurve::P256 => CryptoEccCurve::P256,
        EccCurve::P384 => CryptoEccCurve::P384,
    };
    let data = X509Data {
        key_size: 256,
        common_name: "demo-ecc-server".to_string(),
        organization: "async-opcua demo".to_string(),
        organizational_unit: "demo ops".to_string(),
        country: "EN".to_string(),
        state: "London".to_string(),
        alt_host_names: vec![config.application_uri.clone(), hostname()].into(),
        certificate_duration_days: 365,
    };
    let (cert, key) = X509::cert_and_pkey_ecc(crypto_curve, &data).unwrap();
    fs::write(own_dir.join("cert.der"), cert.to_der().unwrap()).unwrap();
    fs::write(private_dir.join("private.pem"), key.to_pem().unwrap()).unwrap();
}

fn build_server(args: &Args) -> (Server, ServerHandle) {
    let builder = ServerBuilder::new()
        .with_node_manager(simple_node_manager(
            NamespaceMetadata {
                namespace_uri: "urn:DemoServer".to_owned(),
                ..Default::default()
            },
            "demo",
        ))
        .with_type_loader(Arc::new(customs::CustomTypeLoader));

    match args.ecc {
        Some(curve) => {
            let config = ServerConfig::load(&args.config_path).unwrap();
            provision_ecc_certificate(curve, &config);
            builder.with_config(config)
        }
        None => builder.with_config_from(&args.config_path),
    }
    .build()
    .unwrap()
}

impl Args {
    pub fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
        let mut args = pico_args::Arguments::from_env();

        let default = Args::default();
        let config_path: PathBuf = args
            .value_from_str(["-c", "--config"])
            .unwrap_or(default.config_path.clone());
        let raise_events = if args.contains(["-r", "--raise-events"]) {
            true
        } else {
            (config_path == default.config_path) && default.raise_events
        };
        let ecc = args.opt_value_from_fn("--ecc", parse_curve)?;
        let content_path = default.content_path;

        Ok(Args {
            help: args.contains(["-h", "--help"]),
            raise_events,
            config_path,
            content_path,
            ecc,
        })
    }

    pub fn usage() {
        let args = Args::default();
        println!(
            r#"Demo Server
Usage:
  -h, --help                 Show help
  -r, --raise-events         Raise events on a timer (default: {:?})"
  -c, --config [config-file] Path to a configuration file (default: {})
      --ecc [p256|p384]      Provision an EC application certificate before startup"#,
            args.raise_events,
            args.config_path.to_str().as_ref().unwrap()
        );
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse_args().unwrap();
    if args.help {
        Args::usage();
    } else {
        // More powerful logging than a console logger
        log4rs::init_file("log4rs.yaml", Default::default()).unwrap();

        // Create an OPC UA server with sample configuration and default node set
        let (server, handle) = build_server(&args);

        let node_manager = handle
            .node_managers()
            .get_of_type::<SimpleNodeManager>()
            .unwrap();
        let core_node_manager = handle
            .node_managers()
            .get_of_type::<CoreNodeManager>()
            .unwrap();
        let ns = handle.get_namespace_index(NAMESPACE_URI).unwrap();

        let token = handle.token();

        // Define some custom types
        customs::add_custom_types(node_manager.clone(), ns);

        // Add some objects representing machinery
        machine::add_machinery(
            ns,
            node_manager.clone(),
            handle.subscriptions().clone(),
            args.raise_events,
            token.clone(),
        );

        // Add some scalar variables
        scalar::add_scalar_variables(node_manager.clone(), handle.subscriptions().clone(), ns);

        // Add some rapidly changing values
        scalar::add_stress_variables(node_manager.clone(), handle.subscriptions().clone(), ns);

        // Add some control switches, e.g. abort flag
        control::add_control_switches(
            ns,
            node_manager.clone(),
            handle.subscriptions().clone(),
            token.clone(),
        );

        // Add an Alarms & Conditions demo condition with Ack/Confirm and ConditionRefresh methods.
        alarms::add_alarm_demo(
            ns,
            node_manager.clone(),
            core_node_manager,
            handle.subscriptions().clone(),
            token.clone(),
        );

        // Add some methods
        methods::add_methods(node_manager.clone(), ns);

        // Add a historizing variable backed by in-memory SQLite, seeded with sample values, so
        // HistoryRead returns real data (exercised by the interop harness).
        let history_backend =
            Arc::new(opcua_history_sqlite::SqliteHistoryBackend::new_in_memory().unwrap());
        history::add_history(node_manager, history_backend, ns).await;

        server.run().await.unwrap();
    }
}

#[cfg(test)]
mod conformance_profile_tests {
    //! Feature 020 (US2) verification: both demo-server profiles parse, expose the
    //! policy/mode/token matrix the CTT exercises, and the ECC profile actually
    //! builds a server from a freshly provisioned EC certificate.
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn load(name: &str) -> ServerConfig {
        // The sample configs use `${computername}`. With the `env_expansion` feature on (e.g. the
        // CI `--all-features` build), an unset var expands to null and the config fails to parse;
        // set a deterministic value so the test is hermetic regardless of the build's feature set.
        INIT.call_once(|| std::env::set_var("computername", "localhost"));
        ServerConfig::load(&PathBuf::from(name))
            .unwrap_or_else(|e| panic!("config {name} must parse: {e:?}"))
    }

    /// Every endpoint must offer all three identity-token types the CTT exercises.
    fn assert_all_token_types(cfg: &ServerConfig) {
        let required: BTreeSet<&str> = ["ANONYMOUS", "sample_password_user1", "sample_x509_user"]
            .into_iter()
            .collect();
        for (name, ep) in &cfg.endpoints {
            for tok in &required {
                assert!(
                    ep.user_token_ids.iter().any(|t| t == tok),
                    "endpoint {name} is missing token {tok}"
                );
            }
        }
    }

    /// FR-005: the RSA profile has a None endpoint + the full RSA policy matrix, all token types.
    #[test]
    fn rsa_profile_full_matrix() {
        let cfg = load("sample.server.test.conf");
        let policies: BTreeSet<&str> = cfg
            .endpoints
            .values()
            .map(|e| e.security_policy.as_str())
            .collect();
        for expected in [
            "None",
            "Basic128Rsa15",
            "Basic256",
            "Basic256Sha256",
            "Aes128-Sha256-RsaOaep",
        ] {
            assert!(
                policies.contains(expected),
                "RSA profile missing policy {expected}; found {policies:?}"
            );
        }
        assert_all_token_types(&cfg);
    }

    /// FR-004: the ECC profile advertises P256/P384 (Sign + SignAndEncrypt), no sample keypair,
    /// all token types.
    #[test]
    fn ecc_profile_advertises_ecc_matrix() {
        let cfg = load("sample.server.ecc.conf");
        assert!(
            !cfg.create_sample_keypair,
            "ECC profile must not generate the RSA sample keypair"
        );
        let cells: BTreeSet<(String, String)> = cfg
            .endpoints
            .values()
            .map(|e| (e.security_policy.clone(), e.security_mode.clone()))
            .collect();
        for policy in ["ECC_nistP256", "ECC_nistP384"] {
            for mode in ["Sign", "SignAndEncrypt"] {
                assert!(
                    cells.contains(&(policy.to_string(), mode.to_string())),
                    "ECC profile missing {policy}/{mode}; found {cells:?}"
                );
            }
        }
        assert_all_token_types(&cfg);
    }

    /// FR-004: `--ecc` provisions a loadable EC ApplicationInstance cert — proven by building a
    /// server from the ECC profile with the provisioned cert (build reads + validates own/cert.der
    /// and private/private.pem).
    #[tokio::test]
    async fn ecc_profile_builds_with_provisioned_cert() {
        for curve in [EccCurve::P256, EccCurve::P384] {
            let mut cfg = load("sample.server.ecc.conf");
            let tmp = std::env::temp_dir().join(format!(
                "demo-ecc-{}-{:?}",
                std::process::id(),
                curve as u8
            ));
            let _ = std::fs::remove_dir_all(&tmp);
            cfg.pki_dir = tmp.clone();

            // This test proves the provisioned EC cert/key load into a built server; identity-token
            // validation is orthogonal (and the `env_expansion` build mangles the sample argon2
            // password hashes, which contain `$`). Reduce to anonymous-only so the assertion stays
            // focused on cert loading. The full token matrix is covered by the parse tests above.
            cfg.user_tokens.clear();
            for ep in cfg.endpoints.values_mut() {
                ep.user_token_ids.clear();
                ep.user_token_ids.insert("ANONYMOUS".to_string());
            }

            provision_ecc_certificate(curve, &cfg);
            assert!(tmp.join("own/cert.der").is_file(), "cert.der not written");
            assert!(
                tmp.join("private/private.pem").is_file(),
                "private.pem not written"
            );

            let result = ServerBuilder::new()
                .with_config(cfg)
                .with_node_manager(simple_node_manager(
                    NamespaceMetadata {
                        namespace_uri: NAMESPACE_URI.to_owned(),
                        ..Default::default()
                    },
                    "demo",
                ))
                .build();
            assert!(
                result.is_ok(),
                "ECC profile must build with the provisioned EC cert: {:?}",
                result.err()
            );
            let _ = std::fs::remove_dir_all(&tmp);
        }
    }
}
