// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0

//! Independent tests for the ECC token EphemeralKey AdditionalHeader codec (OPC UA Part 6 §6.8.2,
//! Table 70): the request carries `ECDHPolicyUri` (String) and the response carries `ECDHKey`
//! (`EphemeralKeyType`) in an `AdditionalParametersType` name-value list inside the header
//! `ExtensionObject`. Authored separately from the production code (verification division).

use crate::ecc::{
    build_ecdh_key_response, build_ecdh_policy_request, read_ecdh_key, read_ecdh_policy_uri,
};
use opcua_types::{ByteString, EphemeralKeyType, ExtensionObject};

const ECC_P256: &str = "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256";

#[test]
fn ecdh_policy_uri_request_roundtrips() {
    let header = build_ecdh_policy_request(ECC_P256);
    assert_eq!(read_ecdh_policy_uri(&header).as_deref(), Some(ECC_P256));
    // Absent / null header -> None, no panic.
    assert_eq!(read_ecdh_policy_uri(&ExtensionObject::null()), None);
}

#[test]
fn ecdh_key_response_roundtrips() {
    let key = EphemeralKeyType {
        public_key: ByteString::from(vec![0x04, 0x01, 0x02, 0x03]),
        signature: ByteString::from(vec![0xAA, 0xBB, 0xCC]),
    };
    let header = build_ecdh_key_response(key.clone());
    let got = read_ecdh_key(&header).expect("ECDHKey must be present and parse");
    assert_eq!(got.public_key, key.public_key);
    assert_eq!(got.signature, key.signature);
    // Absent / null header -> None, no panic.
    assert!(read_ecdh_key(&ExtensionObject::null()).is_none());
}

#[test]
fn wrong_param_yields_none_without_panic() {
    // A response header (ECDHKey) does not contain an ECDHPolicyUri, and vice-versa.
    let key = EphemeralKeyType {
        public_key: ByteString::from(vec![0x04, 0x09]),
        signature: ByteString::from(vec![0x01]),
    };
    let response = build_ecdh_key_response(key);
    assert_eq!(read_ecdh_policy_uri(&response), None);

    let request = build_ecdh_policy_request(ECC_P256);
    assert!(read_ecdh_key(&request).is_none());
}
