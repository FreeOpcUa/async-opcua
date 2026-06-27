//! OPC UA Part 12 multicast discovery (LDS-ME / FindServersOnNetwork over mDNS).
//!
//! Feature 036. All contents are gated by the off-by-default `discovery-mdns` feature.

use std::{
    collections::HashMap,
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

use futures::never::Never;
use opcua_core::sync::RwLock;

/// Maximum number of capability identifiers accepted from a DNS-SD TXT record.
pub(crate) const MAX_CAPS: usize = 64;

/// Maximum byte length accepted for a single capability identifier.
pub(crate) const MAX_CAP_LEN: usize = 64;

/// Maximum byte length accepted for attacker-controlled string fields.
pub(crate) const MAX_STR: usize = 256;

const DEFAULT_TTL_SECS: u64 = 120;
const MAX_TXT_VALUE_LEN: usize = MAX_CAPS * (MAX_CAP_LEN + 1);
const MAX_CACHE: usize = 4096;
const OPCUA_MDNS_SERVICE_TYPE: &str = "_opcua-tcp._tcp.local.";

/// Running mDNS responder registration.
pub(crate) struct MdnsResponder {
    daemon: mdns_sd::ServiceDaemon,
    fullname: String,
}

/// Builds the OPC UA mDNS service record without starting a daemon.
pub(crate) fn build_service_info(
    mdns_name: &str,
    host_name: &str,
    port: u16,
    path: &str,
    caps: &[String],
) -> Result<mdns_sd::ServiceInfo, mdns_sd::Error> {
    let host_name = host_name_dot_local(host_name);

    mdns_sd::ServiceInfo::new(
        OPCUA_MDNS_SERVICE_TYPE,
        mdns_name,
        &host_name,
        (),
        port,
        Some(encode_txt(path, caps)),
    )
    .map(mdns_sd::ServiceInfo::enable_addr_auto)
}

/// Starts advertising an OPC UA TCP endpoint via mDNS.
pub(crate) fn start_responder(
    mdns_name: &str,
    host_name: &str,
    port: u16,
    path: &str,
    caps: &[String],
) -> Result<MdnsResponder, mdns_sd::Error> {
    let info = build_service_info(mdns_name, host_name, port, path, caps)?;
    let fullname = info.get_fullname().to_owned();
    let daemon = mdns_sd::ServiceDaemon::new()?;
    daemon.register(info)?;

    Ok(MdnsResponder { daemon, fullname })
}

impl MdnsResponder {
    pub(crate) fn daemon(&self) -> &mdns_sd::ServiceDaemon {
        &self.daemon
    }

    pub(crate) fn shutdown(&self) {
        let _ = self.daemon.unregister(&self.fullname);
    }
}

impl Drop for MdnsResponder {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Runs mDNS advertisement and browsing for the server lifetime.
pub(crate) async fn run_mdns_discovery(info: Arc<crate::ServerInfo>) -> Never {
    let config = &info.config.multicast_discovery;
    if !config.enabled {
        return futures::future::pending().await;
    }

    let mdns_name = config
        .mdns_server_name
        .clone()
        .unwrap_or_else(|| info.config.application_name.clone());
    let port = info.port.load(Ordering::Relaxed);
    let host_name = local_hostname();
    let path = discovery_path(info.config.discovery_urls.first().map(String::as_str));
    let caps = if config.capabilities.is_empty() {
        vec!["NA".to_owned()]
    } else {
        config.capabilities.clone()
    };

    let responder = match start_responder(&mdns_name, &host_name, port, &path, &caps) {
        Ok(responder) => responder,
        Err(e) => {
            tracing::warn!("mDNS discovery unavailable: {e}");
            return futures::future::pending().await;
        }
    };

    if let Some(discovery) = &info.mdns {
        if let Err(e) = run_browser(responder.daemon(), discovery.clone()).await {
            tracing::warn!("mDNS browser unavailable: {e}");
        }
    }

    let _responder = responder;
    futures::future::pending().await
}

/// A decoded OPC UA mDNS discovery record.
#[derive(Clone, Debug)]
pub(crate) struct DiscoveredServer {
    /// DNS-SD service instance name.
    pub instance_name: String,

    /// OPC UA discovery URL reconstructed from the SRV address, port and TXT path.
    pub discovery_url: String,

    /// OPC UA server name associated with the service instance.
    pub server_name: String,

    /// Parsed OPC UA capability identifiers from the TXT `caps` value.
    pub capabilities: Vec<String>,

    /// Time at which this decoded record should be considered expired.
    pub expires_at: Instant,
}

/// Shared cache of OPC UA servers discovered via mDNS.
pub(crate) struct MdnsDiscovery {
    own_instance: String,
    cache: RwLock<HashMap<String, DiscoveredServer>>,
}

impl MdnsDiscovery {
    /// Creates an empty mDNS discovery cache.
    pub(crate) fn new(own_instance: String) -> Self {
        Self {
            own_instance,
            cache: RwLock::new(HashMap::new()),
        }
    }

    pub(crate) fn insert(&self, d: DiscoveredServer) {
        if d.instance_name == self.own_instance {
            return;
        }

        let mut cache = self.cache.write();
        if cache.len() >= MAX_CACHE && !cache.contains_key(&d.instance_name) {
            return;
        }

        cache.insert(d.instance_name.clone(), d);
    }

    fn remove(&self, instance_name: &str) {
        self.cache.write().remove(instance_name);
    }

    /// Returns the currently non-expired discovered servers.
    pub(crate) fn snapshot(&self) -> Vec<DiscoveredServer> {
        let now = Instant::now();
        self.cache
            .read()
            .values()
            .filter(|d| d.expires_at > now)
            .cloned()
            .collect()
    }
}

/// Runs the mDNS browser loop and keeps the shared discovery cache current.
pub(crate) async fn run_browser(
    daemon: &mdns_sd::ServiceDaemon,
    discovery: Arc<MdnsDiscovery>,
) -> Result<(), mdns_sd::Error> {
    let rx = daemon.browse(OPCUA_MDNS_SERVICE_TYPE)?;

    if let Err(e) = tokio::task::spawn_blocking(move || loop {
        match rx.recv() {
            Ok(mdns_sd::ServiceEvent::ServiceResolved(svc)) => {
                if let Some(d) = from_resolved_service(svc.as_ref()) {
                    discovery.insert(d);
                }
            }
            Ok(mdns_sd::ServiceEvent::ServiceRemoved(_, fullname)) => {
                discovery.remove(&service_name_from_fullname(&fullname, ""));
            }
            Ok(_) => {}
            Err(_) => break,
        }
    })
    .await
    {
        tracing::warn!("mDNS browser task stopped unexpectedly: {e}");
    }

    Ok(())
}

/// Encodes the OPC UA DNS-SD TXT fields for a path and capability list.
pub(crate) fn encode_txt(path: &str, caps: &[String]) -> HashMap<String, String> {
    let mut txt = HashMap::with_capacity(2);

    if !path.is_empty() {
        txt.insert("path".to_owned(), path.to_owned());
    }

    let caps = caps.join(",");
    if !caps.is_empty() {
        txt.insert("caps".to_owned(), caps);
    }

    txt
}

/// Decodes an OPC UA DNS-SD record from explicit SRV/TXT parts.
pub(crate) fn decode_from_parts(
    instance_name: &str,
    server_name: &str,
    host: &str,
    port: u16,
    txt: &HashMap<String, String>,
    expires_at: Instant,
) -> Option<DiscoveredServer> {
    if host.is_empty() || port == 0 {
        return None;
    }

    let host = truncate_str(host, MAX_STR);
    let instance_name = truncate_str(instance_name, MAX_STR);
    let server_name = truncate_str(server_name, MAX_STR);
    let path = normalize_path(txt.get("path").map(String::as_str));
    let capabilities = decode_caps(txt.get("caps").map(String::as_str));
    let discovery_url = format!("opc.tcp://{host}:{port}{path}");

    Some(DiscoveredServer {
        instance_name,
        discovery_url,
        server_name,
        capabilities,
        expires_at,
    })
}

/// Decodes an OPC UA mDNS discovery record from a browse-resolved `mdns-sd` service.
///
/// In mdns-sd 0.20 the `ServiceResolved` browse event carries a `ResolvedService` (public fields),
/// not a `ServiceInfo` — this is the querier's mapping. All fields are treated as untrusted.
pub(crate) fn from_resolved_service(svc: &mdns_sd::ResolvedService) -> Option<DiscoveredServer> {
    // Prefer a plain IPv4 address (min orders V4 before V6); strip any IPv6 scope.
    let host = svc
        .addresses
        .iter()
        .map(mdns_sd::ScopedIp::to_ip_addr)
        .min()
        .map(|ip| ip.to_string())?;

    let instance_name = service_name_from_fullname(&svc.fullname, &svc.host);
    let server_name = instance_name.clone();

    let mut txt = HashMap::with_capacity(2);
    for property in svc.txt_properties.iter() {
        match property.key() {
            "path" => {
                txt.insert("path".to_owned(), truncate_str(property.val_str(), MAX_STR));
            }
            "caps" => {
                txt.insert(
                    "caps".to_owned(),
                    truncate_str(property.val_str(), MAX_TXT_VALUE_LEN),
                );
            }
            _ => {}
        }
    }

    let now = Instant::now();
    let expires_at = now
        .checked_add(Duration::from_secs(DEFAULT_TTL_SECS))
        .unwrap_or(now);

    decode_from_parts(
        &instance_name,
        &server_name,
        &host,
        svc.port,
        &txt,
        expires_at,
    )
}

fn service_name_from_fullname(fullname: &str, hostname: &str) -> String {
    let source = if fullname.is_empty() {
        hostname
    } else {
        fullname
    };
    let instance_name = source
        .split_once("._opcua-tcp._tcp")
        .map_or(source, |(instance_name, _)| instance_name);

    if instance_name.is_empty() {
        truncate_str(hostname, MAX_STR)
    } else {
        truncate_str(instance_name, MAX_STR)
    }
}

fn decode_caps(caps: Option<&str>) -> Vec<String> {
    let Some(caps) = caps else {
        return Vec::new();
    };

    caps.split(',')
        .map(str::trim)
        .filter(|cap| !cap.is_empty())
        .take(MAX_CAPS)
        .map(|cap| truncate_str(cap, MAX_CAP_LEN))
        .collect()
}

fn normalize_path(path: Option<&str>) -> String {
    let Some(path) = path else {
        return "/".to_owned();
    };

    if path.is_empty() {
        return "/".to_owned();
    }

    if path.starts_with('/') {
        return truncate_str(path, MAX_STR);
    }

    let mut normalized = String::with_capacity(path.len().saturating_add(1).min(MAX_STR));
    normalized.push('/');
    push_str_bounded(&mut normalized, path, MAX_STR);
    normalized
}

fn truncate_str(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        return value.to_owned();
    }

    let mut truncated = String::with_capacity(max_len);
    push_str_bounded(&mut truncated, value, max_len);
    truncated
}

fn push_str_bounded(output: &mut String, value: &str, max_len: usize) {
    for ch in value.chars() {
        let next_len = output.len().saturating_add(ch.len_utf8());
        if next_len > max_len {
            break;
        }
        output.push(ch);
    }
}

fn host_name_dot_local(host_name: &str) -> String {
    let host_name = host_name.trim_end_matches('.');

    if host_name.ends_with(".local") {
        format!("{host_name}.")
    } else {
        format!("{host_name}.local.")
    }
}

fn local_hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
        .map(|host| host.trim().trim_end_matches('.').to_owned())
        .filter(|host| !host.is_empty())
        .unwrap_or_else(|| "localhost".to_owned())
}

fn discovery_path(discovery_url: Option<&str>) -> String {
    let Some(discovery_url) = discovery_url else {
        return "/".to_owned();
    };

    let path = if let Some((_, remainder)) = discovery_url.split_once("://") {
        remainder.find('/').map_or("/", |index| &remainder[index..])
    } else if discovery_url.is_empty() {
        "/"
    } else {
        discovery_url
    };

    normalize_path(Some(strip_query_fragment(path)))
}

fn strip_query_fragment(path: &str) -> &str {
    let query = path.find('?').unwrap_or(path.len());
    let fragment = path.find('#').unwrap_or(path.len());

    &path[..query.min(fragment)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ttl() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    #[test]
    fn encode_txt_emits_path_and_comma_joined_caps() {
        let txt = encode_txt("/UADiscovery", &["LDS".to_owned(), "DA".to_owned()]);
        assert_eq!(txt.get("path").map(String::as_str), Some("/UADiscovery"));
        assert_eq!(txt.get("caps").map(String::as_str), Some("LDS,DA"));
        // Empty caps / empty path omit the key entirely.
        let none = encode_txt("", &[]);
        assert!(none.is_empty());
    }

    #[test]
    fn decode_round_trips_url_and_caps() {
        let txt = encode_txt("/p", &["DA".to_owned(), "HD".to_owned()]);
        let d = decode_from_parts("Inst", "Srv", "192.168.1.5", 4840, &txt, ttl()).unwrap();
        assert_eq!(d.discovery_url, "opc.tcp://192.168.1.5:4840/p");
        assert_eq!(d.capabilities, vec!["DA".to_owned(), "HD".to_owned()]);
        assert_eq!(d.instance_name, "Inst");
    }

    #[test]
    fn decode_defaults_and_normalizes_path() {
        // Absent path → "/".
        let d = decode_from_parts("i", "s", "h", 1, &HashMap::new(), ttl()).unwrap();
        assert_eq!(d.discovery_url, "opc.tcp://h:1/");
        // Path without a leading slash gets one.
        let mut txt = HashMap::new();
        txt.insert("path".to_owned(), "rel".to_owned());
        let d = decode_from_parts("i", "s", "h", 1, &txt, ttl()).unwrap();
        assert_eq!(d.discovery_url, "opc.tcp://h:1/rel");
    }

    #[test]
    fn decode_rejects_missing_host_or_port_without_panic() {
        assert!(decode_from_parts("i", "s", "", 4840, &HashMap::new(), ttl()).is_none());
        assert!(decode_from_parts("i", "s", "h", 0, &HashMap::new(), ttl()).is_none());
    }

    #[test]
    fn decode_bounds_hostile_inputs() {
        // 10_000 caps + an over-long cap → bounded to MAX_CAPS, each ≤ MAX_CAP_LEN bytes; no OOM/panic.
        let huge = (0..10_000)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",")
            + &format!(",{}", "x".repeat(10_000));
        let mut txt = HashMap::new();
        txt.insert("caps".to_owned(), huge);
        txt.insert("path".to_owned(), "/".to_owned() + &"p".repeat(10_000));
        let d = decode_from_parts(&"i".repeat(10_000), "s", "h", 1, &txt, ttl()).unwrap();
        assert!(d.capabilities.len() <= MAX_CAPS, "caps bounded");
        assert!(
            d.capabilities.iter().all(|c| c.len() <= MAX_CAP_LEN),
            "each cap bounded"
        );
        assert!(d.instance_name.len() <= MAX_STR, "instance bounded");
        // discovery_url stays bounded (host:port + bounded path).
        assert!(d.discovery_url.len() <= MAX_STR + 64);
    }

    #[test]
    fn build_service_info_carries_part12_txt() {
        // SC-001 / FR-012: the advertised ServiceInfo carries `path=` and comma-joined `caps=`
        // under the OPC UA `_opcua-tcp._tcp` service type (Part 12 Annex C) — no network needed.
        let info = build_service_info(
            "MyServer",
            "myhost",
            4840,
            "/UADiscovery",
            &["LDS".to_owned(), "DA".to_owned()],
        )
        .expect("service info builds");
        assert_eq!(info.get_type(), OPCUA_MDNS_SERVICE_TYPE);
        let props = info.get_properties();
        assert_eq!(
            props.get_property_val_str("path"),
            Some("/UADiscovery"),
            "TXT path"
        );
        assert_eq!(
            props.get_property_val_str("caps"),
            Some("LDS,DA"),
            "TXT caps"
        );
        assert_eq!(info.get_port(), 4840);
    }

    // Multicast-TOLERANT: exercises the real advertise→discover loop, but self-skips when
    // ServiceDaemon/multicast is unavailable (CI, containers, sandboxes block 224.0.0.251:5353).
    #[test]
    fn responder_is_discoverable_when_multicast_available() {
        let Ok(responder) = start_responder(
            "ITSrv036",
            "ithost036",
            4840,
            "/disc",
            &["LDS".to_owned(), "DA".to_owned()],
        ) else {
            eprintln!("mDNS responder unavailable — skipping multicast test");
            return;
        };
        let Ok(browser) = mdns_sd::ServiceDaemon::new() else {
            return;
        };
        let Ok(rx) = browser.browse(OPCUA_MDNS_SERVICE_TYPE) else {
            return;
        };

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut found = None;
        while Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(400)) {
                Ok(mdns_sd::ServiceEvent::ServiceResolved(svc)) => {
                    if let Some(d) = from_resolved_service(&svc) {
                        if d.instance_name.contains("ITSrv036") {
                            found = Some(d);
                            break;
                        }
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        drop(responder);

        let Some(d) = found else {
            eprintln!("no mDNS resolution (multicast likely blocked) — skipping assertions");
            return;
        };
        assert!(
            d.discovery_url.contains(":4840/disc"),
            "url: {}",
            d.discovery_url
        );
        assert!(
            d.capabilities.contains(&"LDS".to_owned()),
            "caps: {:?}",
            d.capabilities
        );
    }

    #[test]
    fn truncation_is_utf8_safe() {
        // A multi-byte char straddling the bound must not panic or split a code point.
        let s = "é".repeat(MAX_STR); // 2 bytes each
        let t = truncate_str(&s, MAX_STR + 1);
        assert!(t.len() <= MAX_STR + 1);
        assert!(t.chars().all(|c| c == 'é'));
    }

    // FR-008 / SC-006 / Part 2 §8.3: the discovery path is unauthenticated and DoS-exposed. A flood of
    // hostile announcements must not panic or grow the cache without bound, and decode must stay total.
    #[test]
    fn cache_is_bounded_and_decode_never_panics_under_flood() {
        let discovery = MdnsDiscovery::new("self".to_owned());
        let future = Instant::now() + Duration::from_secs(300);
        // Flood with far more than MAX_CACHE distinct hostile records.
        for i in 0..(MAX_CACHE * 3) {
            let mut txt = HashMap::new();
            txt.insert("caps".to_owned(), "X,".repeat(10_000));
            txt.insert("path".to_owned(), "p".repeat(10_000));
            if let Some(d) = decode_from_parts(
                &"i".repeat(5_000),
                "s",
                &format!("10.0.{}.{}", i / 256, i % 256),
                4840,
                &txt,
                future,
            ) {
                discovery.insert(d);
            }
        }
        // Bounded — never grows past MAX_CACHE despite 3× the inserts.
        assert!(
            discovery.snapshot().len() <= MAX_CACHE,
            "cache bounded under flood"
        );
        // Self-announcement is never cached.
        discovery.insert(DiscoveredServer {
            instance_name: "self".to_owned(),
            discovery_url: "opc.tcp://1.2.3.4:4840/".to_owned(),
            server_name: "self".to_owned(),
            capabilities: vec![],
            expires_at: future,
        });
        assert!(
            discovery
                .snapshot()
                .iter()
                .all(|d| d.instance_name != "self"),
            "self excluded"
        );
    }
}
