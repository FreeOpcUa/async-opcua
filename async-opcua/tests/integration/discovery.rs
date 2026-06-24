//! Feature 024 — RegisterServer (LDS registration) end-to-end via the existing client
//! register_server() / find_servers(). Anchored to OPC UA Part 4 §5.5.5 / Part 12 §7.5.

use super::utils::Tester;
use opcua::types::{
    ApplicationType, EndpointDescription, ExtensionObject, LocalizedText,
    MdnsDiscoveryConfiguration, MessageSecurityMode, RegisteredServer, StatusCode, UAString,
};

// Part 12 §7.5: a server may only register itself — the registration's serverUri must match the
// applicationUri in the SecureChannel client certificate. The integration client's certificate
// uses "urn:integration_server", so that is the URI a registration is allowed to use. The
// registered entry is told apart from the server's own FindServers description by its productUri.
const REGISTERING_URI: &str = "urn:integration_server";
const REG_PRODUCT: &str = "urn:registered-test-product";

fn registered_server(is_online: bool) -> RegisteredServer {
    RegisteredServer {
        server_uri: REGISTERING_URI.into(),
        product_uri: REG_PRODUCT.into(),
        server_names: Some(vec![LocalizedText::new("en", "Registered Test Server")]),
        server_type: ApplicationType::Server,
        gateway_server_uri: UAString::null(),
        discovery_urls: Some(vec!["opc.tcp://registered-host:4840/".into()]),
        semaphore_file_path: UAString::null(),
        is_online,
    }
}

/// RegisterServer must run over a secured channel (Part 12 §7.5), so pick a SignAndEncrypt
/// endpoint to register over.
async fn secured_endpoint(tester: &Tester) -> EndpointDescription {
    tester
        .client
        .get_endpoints(tester.endpoint(), &[], &[])
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.security_mode == MessageSecurityMode::SignAndEncrypt)
        .expect("the test server should offer a SignAndEncrypt endpoint")
}

#[tokio::test]
async fn register_server_appears_in_find_servers() {
    let tester = Tester::new_default_server(true).await;
    let url = tester.endpoint();
    let endpoint = secured_endpoint(&tester).await;

    // Baseline: the registered entry (identified by its productUri) is not present yet.
    let before = tester
        .client
        .find_servers(url.clone(), None, None)
        .await
        .unwrap();
    let baseline = before.len();
    assert!(
        !before.iter().any(|s| s.product_uri.as_ref() == REG_PRODUCT),
        "registered server must not be present before registration"
    );

    // Register (online) over the secured channel.
    tester
        .client
        .register_server(url.clone(), &endpoint, registered_server(true))
        .await
        .unwrap();

    // FindServers now includes it (it shares the applicationUri with the server's own
    // description, so it is identified by its productUri / name).
    let after = tester
        .client
        .find_servers(url.clone(), None, None)
        .await
        .unwrap();
    assert_eq!(after.len(), baseline + 1);
    let reg = after
        .iter()
        .find(|s| s.product_uri.as_ref() == REG_PRODUCT)
        .expect("registered server must appear in FindServers");
    assert_eq!(reg.application_uri.as_ref(), REGISTERING_URI);
    assert_eq!(reg.application_type, ApplicationType::Server);
    assert_eq!(reg.application_name.text.as_ref(), "Registered Test Server");
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
        .any(|s| s.product_uri.as_ref() == REG_PRODUCT));
}

#[tokio::test]
async fn register_server_update_is_idempotent() {
    let tester = Tester::new_default_server(true).await;
    let url = tester.endpoint();
    let endpoint = secured_endpoint(&tester).await;

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
        .filter(|s| s.product_uri.as_ref() == REG_PRODUCT)
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
    let endpoint = secured_endpoint(&tester).await;

    // RegisterServer2 with an mDNS discovery configuration: the per-config result is "not supported",
    // but the server is still registered (Part 4 §5.5.6).
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
            .any(|s| s.product_uri.as_ref() == REG_PRODUCT),
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
        .any(|s| s.product_uri.as_ref() == REG_PRODUCT));
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

#[tokio::test]
async fn register_server_missing_name_or_url_is_rejected() {
    // P4-DISC-01 — OPC UA Part 4 §5.5.5: an online RegisterServer with no ServerName must return
    // Bad_ServerNameMissing, and with no discoveryUrl, Bad_DiscoveryUrlMissing. Registered over a
    // secured channel with a matching URI so it reaches the field validation (Part 12 §7.5).
    let tester = Tester::new_default_server(true).await;
    let url = tester.endpoint();
    let endpoint = secured_endpoint(&tester).await;

    let mut no_name = registered_server(true);
    no_name.server_names = None;
    let e = tester
        .client
        .register_server(url.clone(), &endpoint, no_name)
        .await
        .unwrap_err();
    assert_eq!(e.status(), StatusCode::BadServerNameMissing);

    let mut no_url = registered_server(true);
    no_url.discovery_urls = None;
    let e = tester
        .client
        .register_server(url.clone(), &endpoint, no_url)
        .await
        .unwrap_err();
    assert_eq!(e.status(), StatusCode::BadDiscoveryUrlMissing);
}

#[tokio::test]
async fn register_server_rejects_uri_not_bound_to_caller_certificate() {
    // P4-DISC-03 — OPC UA Part 12 §7.5: a RegisterServer call must be authenticated. The
    // registration's serverUri must match the applicationUri in the SecureChannel client
    // certificate, and the channel must be secured. Otherwise any client could register or
    // (worse) unregister arbitrary servers.
    let tester = Tester::new_default_server(true).await;
    let url = tester.endpoint();

    // A registration whose serverUri does not belong to the caller's certificate is rejected.
    let secured = secured_endpoint(&tester).await;
    let mut spoofed = registered_server(true);
    spoofed.server_uri = "urn:some-other-server".into();
    let e = tester
        .client
        .register_server(url.clone(), &secured, spoofed)
        .await
        .unwrap_err();
    assert_eq!(e.status(), StatusCode::BadServerUriInvalid);

    // A registration over an unsecured (None) channel is rejected, even with a matching URI.
    let endpoints = tester
        .client
        .get_endpoints(url.clone(), &[], &[])
        .await
        .unwrap();
    let none_endpoint = endpoints
        .iter()
        .find(|e| e.security_mode == MessageSecurityMode::None)
        .expect("the test server should offer a None endpoint")
        .clone();
    let e = tester
        .client
        .register_server(url.clone(), &none_endpoint, registered_server(true))
        .await
        .unwrap_err();
    assert_eq!(e.status(), StatusCode::BadSecurityChecksFailed);
}
