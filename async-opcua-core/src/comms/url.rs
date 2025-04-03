// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Provides functions for parsing Urls from strings.

use tracing::error;
use url::Url;

use opcua_types::status_code::StatusCode;

/// Scheme for OPC-UA TCP.
pub const OPC_TCP_SCHEME: &str = "opc.tcp";

/// Creates a `Url` from the input string, supplying a default port if necessary.
fn opc_url_from_str(s: &str) -> Result<Url, url::ParseError> {
    Url::parse(s)
        .map(|mut url| {
            if url.port().is_none() {
                // If no port is supplied, then treat it as the default port 4840
                let _ = url.set_port(Some(crate::constants::DEFAULT_OPC_UA_SERVER_PORT));
            }
            url
        })
        .inspect_err(|err| {
            error!("Cannot parse url \"{}\", error = {:?}", s, err);
        })
}

/// Replace the hostname in the supplied url and return a new url
pub fn url_with_replaced_hostname(url: &str, hostname: &str) -> Result<String, url::ParseError> {
    let mut url = opc_url_from_str(url)?;
    let _ = url.set_host(Some(hostname));
    Ok(url.into())
}

/// Test if the two urls match except for the hostname. Can be used by a server whose endpoint doesn't
/// exactly match the incoming connection, e.g. 127.0.0.1 vs localhost.
pub fn url_matches_except_host(url1: &str, url2: &str) -> bool {
    if let Ok(mut url1) = opc_url_from_str(url1) {
        if let Ok(mut url2) = opc_url_from_str(url2) {
            // Both hostnames are set to xxxx so the comparison should come out as the same url
            // if they actually match one another.
            if url1.set_host(Some("xxxx")).is_ok() && url2.set_host(Some("xxxx")).is_ok() {
                return url1.as_str().trim_end_matches("/") == url2.as_str().trim_end_matches("/");
            }
        } else {
            error!("Cannot parse url \"{}\"", url2);
        }
    } else {
        error!("Cannot parse url \"{}\"", url1);
    }
    false
}

/// Takes an endpoint url and strips off the path and args to leave just the protocol, host & port.
pub fn server_url_from_endpoint_url(
    endpoint_url: &str,
) -> std::result::Result<String, url::ParseError> {
    opc_url_from_str(endpoint_url).map(|mut url| {
        url.set_query(None);
        if let Some(port) = url.port() {
            // If the port is the default, strip it so the url string omits it.
            if port == crate::constants::DEFAULT_OPC_UA_SERVER_PORT {
                let _ = url.set_port(None);
            }
        }
        url.into()
    })
}

/// Check if this is a valid OPC-UA TCP URL.
pub fn is_valid_opc_ua_url(url: &str) -> bool {
    is_opc_ua_binary_url(url)
}

/// Check if this is an OPC-UA TCP URL.
pub fn is_opc_ua_binary_url(url: &str) -> bool {
    if let Ok(url) = opc_url_from_str(url) {
        url.scheme() == OPC_TCP_SCHEME
    } else {
        false
    }
}

/// Error returned when getting host name from URL.
pub enum HostnameFromUrlError {
    /// URL failed to parse.
    Parse(url::ParseError),
    /// Host is not present in URL.
    MissingHost,
}

impl From<url::ParseError> for HostnameFromUrlError {
    fn from(value: url::ParseError) -> Self {
        Self::Parse(value)
    }
}

/// Get the hostname from the given URL.
pub fn hostname_from_url(url: &str) -> Result<String, HostnameFromUrlError> {
    // Validate and split out the endpoint we have
    let url = Url::parse(url)?;
    if let Some(host) = url.host_str() {
        Ok(host.to_string())
    } else {
        Err(HostnameFromUrlError::MissingHost)
    }
}

/// Get the hostname and port from the given URL, defaulting to `default_port`.
pub fn hostname_port_from_url(url: &str, default_port: u16) -> Result<(String, u16), StatusCode> {
    // Validate and split out the endpoint we have
    let url = Url::parse(url).map_err(|_| StatusCode::BadTcpEndpointUrlInvalid)?;

    if url.scheme() != OPC_TCP_SCHEME || !url.has_host() {
        Err(StatusCode::BadTcpEndpointUrlInvalid)
    } else {
        let host = url.host_str().unwrap();
        let port = url.port().unwrap_or(default_port);
        Ok((host.to_string(), port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_scheme() {
        assert!(is_opc_ua_binary_url("opc.tcp://foo/xyz"));
        assert!(is_opc_ua_binary_url(
            "opc.tcp://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:80/xyz"
        ));
        assert!(!is_opc_ua_binary_url("http://foo/xyz"));
    }

    #[test]
    fn url_matches_test() {
        assert!(url_matches_except_host(
            "opc.tcp://localhost/xyz",
            "opc.tcp://127.0.0.1/xyz"
        ));
        assert!(!url_matches_except_host(
            "opc.tcp://localhost/xyz",
            "opc.tcp://127.0.0.1/abc"
        ));
    }

    #[test]
    fn server_url_from_endpoint_url_test() {
        assert_eq!(
            "opc.tcp://localhost",
            server_url_from_endpoint_url("opc.tcp://localhost").unwrap()
        );
        assert_eq!(
            "opc.tcp://localhost",
            server_url_from_endpoint_url("opc.tcp://localhost:4840").unwrap()
        );
        assert_eq!(
            "opc.tcp://localhost:4841",
            server_url_from_endpoint_url("opc.tcp://localhost:4841").unwrap()
        );
        assert_eq!(
            "opc.tcp://localhost/xyz/abc",
            server_url_from_endpoint_url("opc.tcp://localhost/xyz/abc?1").unwrap()
        );
        assert_eq!(
            "opc.tcp://localhost:999/xyz/abc",
            server_url_from_endpoint_url("opc.tcp://localhost:999/xyz/abc?1").unwrap()
        );
    }

    #[test]
    fn url_with_replaced_hostname_test() {
        assert_eq!(
            url_with_replaced_hostname("opc.tcp://foo:123/x", "foo").unwrap(),
            "opc.tcp://foo:123/x"
        );
        assert_eq!(
            url_with_replaced_hostname("opc.tcp://foo:123/x", "bar").unwrap(),
            "opc.tcp://bar:123/x"
        );
        assert_eq!(
            url_with_replaced_hostname("opc.tcp://localhost:123/x", "127.0.0.1").unwrap(),
            "opc.tcp://127.0.0.1:123/x"
        );
    }
}
