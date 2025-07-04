// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! This is a sample that calls find servers on a OPC UA discovery server

use std::str::FromStr;

use opcua::{
    client::{Client, ClientConfig},
    core::comms::url::is_opc_ua_binary_url,
    crypto::SecurityPolicy,
};

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
                .unwrap_or_else(|| String::from(DEFAULT_DISCOVERY_URL)),
        })
    }

    pub fn usage() {
        println!(
            r#"OPC UA Discovery client
Usage:
  -h, --help  Show help
  --url       The url for the discovery server (default: {DEFAULT_DISCOVERY_URL})"#
        );
    }
}

const DEFAULT_DISCOVERY_URL: &str = "opc.tcp://localhost:4840/";

#[tokio::main]
async fn main() -> Result<(), ()> {
    let args = Args::parse_args().map_err(|_| Args::usage())?;
    if args.help {
        Args::usage();
    } else {
        // Read the argument
        let url = args.url;

        println!("Attempting to connect to discovery server {url} ...");
        // Optional - enable OPC UA logging
        env_logger::init();

        // The client API has a simple `find_servers` function that connects and returns servers for us.
        let client = Client::new(ClientConfig::new("DiscoveryClient", "urn:DiscoveryClient"));
        match client.find_servers(url, None, None).await {
            Ok(servers) => {
                println!("Discovery server responded with {} servers:", servers.len());
                for server in servers {
                    // Each server is an `ApplicationDescription`
                    println!("Server : {}", server.application_name);
                    if let Some(ref discovery_urls) = server.discovery_urls {
                        for discovery_url in discovery_urls {
                            print_server_endpoints(discovery_url.as_ref()).await
                        }
                    } else {
                        println!("  No discovery urls for this server");
                    }
                }
            }
            Err(err) => {
                println!(
                    "ERROR: Cannot find servers on discovery server - check this error - {err:?}"
                );
            }
        }
    }
    Ok(())
}

async fn print_server_endpoints(discovery_url: &str) {
    println!("  {discovery_url}");
    if is_opc_ua_binary_url(discovery_url) {
        // Try to talk with it and get some endpoints
        let client_config = ClientConfig::new("discovery-client", "urn:discovery-client");
        let client = Client::new(client_config);

        // Ask the server associated with the default endpoint for its list of endpoints
        match client.get_server_endpoints_from_url(discovery_url).await {
            Result::Ok(endpoints) => {
                println!("    Server has these endpoints:");
                endpoints.iter().for_each(|e| {
                    println!(
                        "      {} - {:?} / {:?}",
                        e.endpoint_url,
                        SecurityPolicy::from_str(e.security_policy_uri.as_ref()).unwrap(),
                        e.security_mode
                    );
                });
            }
            Result::Err(status_code) => {
                println!(
                    "    ERROR: Cannot get endpoints for this server url, error - {status_code}"
                );
            }
        }
    }
}
