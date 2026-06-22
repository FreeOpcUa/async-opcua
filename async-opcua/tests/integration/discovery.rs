//! Feature 024 — RegisterServer (LDS registration) end-to-end via the existing client
//! register_server() / find_servers(). Anchored to OPC UA Part 4 §5.4.5.

use super::utils::Tester;
use opcua::types::{
    ApplicationType, ExtensionObject, LocalizedText, MdnsDiscoveryConfiguration, RegisteredServer,
    StatusCode, UAString,
};

const REG_URI: &str = "urn:registered-test-server";

fn registered_server(is_online: bool) -> RegisteredServer {
    RegisteredServer {
        server_uri: REG_URI.into(),
        product_uri: "urn:registered-test-product".into(),
        server_names: Some(vec![LocalizedText::new("en", "Registered Test Server")]),
        server_type: ApplicationType::Server,
        gateway_server_uri: UAString::null(),
        discovery_urls: Some(vec!["opc.tcp://registered-host:4840/".into()]),
        semaphore_file_path: UAString::null(),
        is_online,
    }
}

#[tokio::test]
async fn register_server_appears_in_find_servers() {
    let tester = Tester::new_default_server(true).await;
    let url = tester.endpoint();

    // Baseline: only the server's own description.
    let before = tester
        .client
        .find_servers(url.clone(), None, None)
        .await
        .unwrap();
    let baseline = before.len();
    assert!(
        !before.iter().any(|s| s.application_uri.as_ref() == REG_URI),
        "registered server must not be present before registration"
    );

    // An endpoint to register over.
    let endpoints = tester
        .client
        .get_endpoints(url.clone(), &[], &[])
        .await
        .unwrap();
    let endpoint = endpoints.first().expect("at least one endpoint").clone();

    // Register (online).
    tester
        .client
        .register_server(url.clone(), &endpoint, registered_server(true))
        .await
        .unwrap();

    // FindServers now includes it, with the mapped ApplicationDescription fields.
    let after = tester
        .client
        .find_servers(url.clone(), None, None)
        .await
        .unwrap();
    assert_eq!(after.len(), baseline + 1);
    let reg = after
        .iter()
        .find(|s| s.application_uri.as_ref() == REG_URI)
        .expect("registered server must appear in FindServers");
    assert_eq!(reg.application_type, ApplicationType::Server);
    assert_eq!(reg.application_name.text.as_ref(), "Registered Test Server");
    assert_eq!(reg.product_uri.as_ref(), "urn:registered-test-product");
    assert!(reg
        .discovery_urls
        .as_ref()
        .map(|u| u
            .iter()
            .any(|d| d.as_ref() == "opc.tcp://registered-host:4840/"))
        .unwrap_or(false));

    // Unregister (offline).
    tester
        .client
        .register_server(url.clone(), &endpoint, registered_server(false))
        .await
        .unwrap();
    let after_unreg = tester
        .client
        .find_servers(url.clone(), None, None)
        .await
        .unwrap();
    assert_eq!(after_unreg.len(), baseline);
    assert!(!after_unreg
        .iter()
        .any(|s| s.application_uri.as_ref() == REG_URI));
}

#[tokio::test]
async fn register_server_update_is_idempotent() {
    let tester = Tester::new_default_server(true).await;
    let url = tester.endpoint();
    let endpoint = tester
        .client
        .get_endpoints(url.clone(), &[], &[])
        .await
        .unwrap()
        .first()
        .expect("endpoint")
        .clone();

    // Register twice with the same server_uri → single entry, updated (no duplicate).
    tester
        .client
        .register_server(url.clone(), &endpoint, registered_server(true))
        .await
        .unwrap();
    let mut updated = registered_server(true);
    updated.server_names = Some(vec![LocalizedText::new("en", "Renamed Server")]);
    tester
        .client
        .register_server(url.clone(), &endpoint, updated)
        .await
        .unwrap();

    let servers = tester
        .client
        .find_servers(url.clone(), None, None)
        .await
        .unwrap();
    let matches: Vec<_> = servers
        .iter()
        .filter(|s| s.application_uri.as_ref() == REG_URI)
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "re-registration must not duplicate the entry"
    );
    assert_eq!(matches[0].application_name.text.as_ref(), "Renamed Server");
}

#[tokio::test]
async fn register_server2_mdns_config_unsupported_but_registers() {
    let tester = Tester::new_default_server(true).await;
    let url = tester.endpoint();
    let endpoint = tester
        .client
        .get_endpoints(url.clone(), &[], &[])
        .await
        .unwrap()
        .first()
        .expect("endpoint")
        .clone();

    // RegisterServer2 with an mDNS discovery configuration: the per-config result is "not supported",
    // but the server is still registered (Part 4 §5.4.6).
    let mdns = ExtensionObject::from_message(MdnsDiscoveryConfiguration {
        mdns_server_name: "registered-test".into(),
        server_capabilities: Some(vec!["DA".into()]),
    });
    let results = tester
        .client
        .register_server2(
            url.clone(),
            &endpoint,
            registered_server(true),
            Some(vec![mdns]),
        )
        .await
        .unwrap();
    assert_eq!(results, vec![StatusCode::BadNotSupported]);

    // ...yet the server is registered and discoverable.
    let servers = tester
        .client
        .find_servers(url.clone(), None, None)
        .await
        .unwrap();
    assert!(
        servers
            .iter()
            .any(|s| s.application_uri.as_ref() == REG_URI),
        "RegisterServer2 must still register the server despite the unsupported mdns config"
    );

    // RegisterServer2 updates the same registry: unregister via is_online=false.
    tester
        .client
        .register_server2(url.clone(), &endpoint, registered_server(false), None)
        .await
        .unwrap();
    let servers = tester
        .client
        .find_servers(url.clone(), None, None)
        .await
        .unwrap();
    assert!(!servers
        .iter()
        .any(|s| s.application_uri.as_ref() == REG_URI));
}

#[tokio::test]
async fn find_servers_on_network_is_unsupported() {
    let tester = Tester::new_default_server(true).await;
    // mDNS / multicast discovery is intentionally out of scope.
    let res = tester
        .client
        .find_servers_on_network(tester.endpoint(), 0, 0, None)
        .await;
    let status = res.err().map(|e| e.status());
    assert_eq!(status, Some(StatusCode::BadServiceUnsupported));
}
