//! Regression tests for certificate-store lock mode in client channel setup.

use std::{fs, path::Path};

#[test]
fn certificate_store_connect_path_uses_read_access_for_cert_and_key_reads() {
    // OPC-10000-6 6.7.7 defines SecureChannel message security processing; the
    // connect path only needs to read local certificate material before applying
    // it to the channel state.
    let channel_rs = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/transport/channel.rs");
    let source = fs::read_to_string(&channel_rs)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", channel_rs.display()));
    let create_transport = extract_function_body(&source, "async fn create_transport")
        .unwrap_or_else(|| {
            panic!(
                "create_transport function not found in {}",
                channel_rs.display()
            )
        });

    let cert_read = create_transport
        .find("read_own_cert")
        .unwrap_or_else(|| panic!("create_transport no longer reads the own certificate"));
    let key_read = create_transport
        .find("read_own_pkey")
        .unwrap_or_else(|| panic!("create_transport no longer reads the own private key"));
    let first_material_read = cert_read.min(key_read);

    let material_read_prefix = &create_transport[..first_material_read];
    assert!(
        !material_read_prefix.contains("trace_write_lock!(self.certificate_store)"),
        "connect/create_transport still takes a certificate-store write lock before reading \
         certificate material; use read access for read_own_cert/read_own_pkey"
    );
    assert!(
        material_read_prefix.contains("trace_read_lock!(self.certificate_store)"),
        "connect/create_transport should take a certificate-store read lock before reading \
         certificate material"
    );
}

fn extract_function_body<'a>(source: &'a str, signature: &str) -> Option<&'a str> {
    let signature_start = source.find(signature)?;
    let after_signature = &source[signature_start..];
    let body_open_relative = after_signature.find('{')?;
    let body_open = signature_start + body_open_relative;
    let body_close = matching_brace(source, body_open)?;
    source.get(body_open + 1..body_close)
}

fn matching_brace(source: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;

    for (idx, byte) in source.as_bytes().iter().enumerate().skip(open) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }

    None
}
