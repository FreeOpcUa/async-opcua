//! These tests are specifically testing secure channel behaviour of signing, encrypting, decrypting and verifying
//! chunks containing messages

#[cfg(feature = "ecc")]
use opcua_crypto::ecc::{EccCurve, EphemeralPrivateKey};
use opcua_crypto::SecurityPolicy;
#[cfg(feature = "ecc")]
use opcua_crypto::{PrivateKey, X509Data, X509};
use tracing::{error, trace};

use crate::{
    comms::{chunker::*, secure_channel::*, sequence_number::SequenceNumberHandle},
    tests::*,
    Message,
};

fn test_symmetric_encrypt_decrypt(
    message: impl Message + PartialEq + Debug,
    security_mode: MessageSecurityMode,
    security_policy: SecurityPolicy,
) {
    let (secure_channel1, secure_channel2) = make_secure_channels(security_mode, security_policy);

    let mut chunks = Chunker::encode(
        SequenceNumberHandle::new(true),
        1,
        0,
        0,
        &secure_channel1,
        &message,
    )
    .unwrap();
    assert_eq!(chunks.len(), 1);

    {
        let chunk = &mut chunks[0];

        let mut encrypted_data = vec![0u8; chunk.data.len() + 4096];
        let encrypted_size = secure_channel1
            .apply_security(chunk, &mut encrypted_data[..])
            .unwrap();
        trace!("Result of applying security = {}", encrypted_size);

        // Decrypted message should identical to original with same length and
        // no signature or padding
        let mut decrypted_data = DecryptedChunkStorage::new();
        let chunk2 = secure_channel2
            .verify_and_remove_security(
                encrypted_data[..encrypted_size].to_vec().into(),
                &mut decrypted_data,
            )
            .unwrap();

        assert_eq!(&chunk.data, &chunk2.data);
    }

    let message2 = Chunker::decode(&chunks, &secure_channel2, None).unwrap();
    assert_eq!(message, message2);
}

fn test_asymmetric_encrypt_decrypt(
    message: impl Message + PartialEq + Debug,
    security_mode: MessageSecurityMode,
    security_policy: SecurityPolicy,
) {
    // Do the test twice using a large key to a small key and vice versa so any issues with padding,
    // extra padding are caught in both directions.
    for i in 0..2 {
        // Create a cert and private key pretending to be us and them. Keysizes are different to shake out issues with
        // signature lengths. Encrypting key will be 4096 bits to test extra padding functionality.
        let (our_cert, our_key) = if i == 0 {
            make_test_cert_4096()
        } else {
            make_test_cert_2048()
        };
        //    let (our_cert, our_key) = make_test_cert_1024();
        let (their_cert, their_key) = if i == 0 {
            make_test_cert_2048()
        } else {
            make_test_cert_4096()
        };

        let mut secure_channel = SecureChannel::new_no_certificate_store();
        secure_channel.set_security_mode(security_mode);
        secure_channel.set_security_policy(security_policy);
        // These tests deliberately exercise deprecated policies (Basic128Rsa15/Basic256),
        // so opt in explicitly now that allow_deprecated defaults to false (L2).
        secure_channel.set_allow_deprecated(true);

        // First we shall sign with our private key and encrypt with their public.
        secure_channel.set_cert(Some(our_cert));
        secure_channel.set_remote_cert(Some(their_cert));
        secure_channel.set_private_key(Some(our_key));

        let mut chunks = Chunker::encode(
            SequenceNumberHandle::new(true),
            1,
            0,
            0,
            &secure_channel,
            &message,
        )
        .unwrap();
        assert_eq!(chunks.len(), 1);

        let chunk = &mut chunks[0];

        let mut encrypted_data = vec![0u8; chunk.data.len() + 4096];
        let encrypted_size = secure_channel
            .apply_security(chunk, &mut encrypted_data[..])
            .unwrap();
        trace!("Result of applying security = {}", encrypted_size);

        // Now we shall try to decrypt what has been encrypted by flipping the keys around
        let tmp = secure_channel.cert();
        let remote_cert = secure_channel.remote_cert();
        secure_channel.set_cert(remote_cert);
        secure_channel.set_remote_cert(tmp);
        secure_channel.set_private_key(Some(their_key));

        // Compare up to original length
        let mut decrypted_data = DecryptedChunkStorage::new();
        let chunk2 = secure_channel
            .verify_and_remove_security(
                encrypted_data[..encrypted_size].to_vec().into(),
                &mut decrypted_data,
            )
            .unwrap();
        assert_eq!(chunk.data.len(), chunk2.data.len());
        assert_eq!(&chunk.data, &chunk2.data);
    }
}

//

#[test]
#[cfg(not(coverage))]
fn asymmetric_sign_and_encrypt_message_chunk_basic128rsa15() {
    use crate::ResponseMessage;

    let _ = Test::setup();
    error!("asymmetric_sign_and_encrypt_message_chunk_basic128rsa15");
    let m: ResponseMessage = make_open_secure_channel_response().into();
    test_asymmetric_encrypt_decrypt(
        m,
        MessageSecurityMode::SignAndEncrypt,
        SecurityPolicy::Basic128Rsa15,
    );
}

#[test]
#[cfg(not(coverage))]
fn asymmetric_sign_and_encrypt_message_chunk_basic256() {
    use crate::ResponseMessage;

    let _ = Test::setup();
    error!("asymmetric_sign_and_encrypt_message_chunk_basic256");
    let m: ResponseMessage = make_open_secure_channel_response().into();
    test_asymmetric_encrypt_decrypt(
        m,
        MessageSecurityMode::SignAndEncrypt,
        SecurityPolicy::Basic256,
    );
}

#[test]
#[cfg(not(coverage))]
fn asymmetric_sign_and_encrypt_message_chunk_basic256sha256() {
    use crate::ResponseMessage;

    let _ = Test::setup();
    error!("asymmetric_sign_and_encrypt_message_chunk_basic256sha256");
    let m: ResponseMessage = make_open_secure_channel_response().into();
    test_asymmetric_encrypt_decrypt(
        m,
        MessageSecurityMode::SignAndEncrypt,
        SecurityPolicy::Basic256Sha256,
    );
}

/// Create a message, encode it to a chunk, sign the chunk, verify the signature and decode back to message
#[test]
fn symmetric_sign_message_chunk_basic128rsa15() {
    let _ = Test::setup();
    error!("symmetric_sign_message_chunk_basic128rsa15");
    test_symmetric_encrypt_decrypt(
        make_sample_message(),
        MessageSecurityMode::Sign,
        SecurityPolicy::Basic128Rsa15,
    );
}

#[test]
fn symmetric_sign_message_chunk_basic256() {
    let _ = Test::setup();
    error!("symmetric_sign_message_chunk_basic256");
    test_symmetric_encrypt_decrypt(
        make_sample_message(),
        MessageSecurityMode::Sign,
        SecurityPolicy::Basic256,
    );
}

#[test]
fn symmetric_sign_message_chunk_basic256sha256() {
    let _ = Test::setup();
    error!("symmetric_sign_message_chunk_basic256sha256");
    test_symmetric_encrypt_decrypt(
        make_sample_message(),
        MessageSecurityMode::Sign,
        SecurityPolicy::Basic256Sha256,
    );
}

/// Create a message, encode it to a chunk, sign the chunk, encrypt, decrypt, verify the signature and decode back to message
#[test]
fn symmetric_sign_and_encrypt_message_chunk_basic128rsa15() {
    let _ = Test::setup();
    error!("symmetric_sign_and_encrypt_message_chunk_basic128rsa15");
    test_symmetric_encrypt_decrypt(
        make_sample_message(),
        MessageSecurityMode::SignAndEncrypt,
        SecurityPolicy::Basic128Rsa15,
    );
}

/// Create a message, encode it to a chunk, sign the chunk, encrypt, decrypt, verify the signature and decode back to message
#[test]
fn symmetric_sign_and_encrypt_message_chunk_basic256() {
    let _ = Test::setup();
    error!("symmetric_sign_and_encrypt_message_chunk_basic256");
    test_symmetric_encrypt_decrypt(
        make_sample_message(),
        MessageSecurityMode::SignAndEncrypt,
        SecurityPolicy::Basic256,
    );
}

/// Create a message, encode it to a chunk, sign the chunk, encrypt, decrypt, verify the signature and decode back to message
#[test]
fn symmetric_sign_and_encrypt_message_chunk_basic256sha256() {
    let _ = Test::setup();
    error!("symmetric_sign_and_encrypt_message_chunk_basic256sha256");
    test_symmetric_encrypt_decrypt(
        make_sample_message(),
        MessageSecurityMode::SignAndEncrypt,
        SecurityPolicy::Basic256Sha256,
    );
}

// ---------------------------------------------------------------------------
// ECC secure-channel key agreement (feature 012, US3).
//
// Independent verification of the ECC channel core authored by Claude (NOT the
// implementer). For ECC the nonces ARE the ephemeral EC public keys; the
// channel must run ECDH against the peer's nonce, derive keys via HKDF, map the
// client/server key sets by role, and reuse the existing AES-CBC + HMAC
// symmetric layer. A correct implementation produces interoperable keys such
// that a signed/encrypted chunk round-trips in BOTH directions — a role or
// salt-direction swap breaks exactly one direction.
//
// Ephemeral scalars are the deterministic RFC 5903 §8.1/§8.2 private keys so the
// handshake is reproducible.
// ---------------------------------------------------------------------------

#[cfg(feature = "ecc")]
fn ecc_hex(s: &str) -> Vec<u8> {
    let cleaned: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    cleaned
        .chunks_exact(2)
        .map(|p| {
            let hi = (p[0] as char).to_digit(16).unwrap();
            let lo = (p[1] as char).to_digit(16).unwrap();
            ((hi << 4) | lo) as u8
        })
        .collect()
}

#[cfg(feature = "ecc")]
fn make_ecc_channel(
    role: Role,
    security_mode: MessageSecurityMode,
    security_policy: SecurityPolicy,
    local_ephemeral: EphemeralPrivateKey,
    remote_public_xy: &[u8],
) -> SecureChannel {
    let local_public = local_ephemeral
        .public_key()
        .expect("derive local ephemeral public key")
        .encoded()
        .to_vec();
    let mut secure_channel = SecureChannel::new_no_certificate_store();
    secure_channel.set_role(role);
    secure_channel.set_security_mode(security_mode);
    secure_channel.set_security_policy(security_policy);
    // The ephemeral private key is installed by the OpenSecureChannel flow; the
    // matching public key travels in the local nonce, the peer's in the remote.
    secure_channel.set_local_ephemeral_key(local_ephemeral);
    secure_channel.set_local_nonce(&local_public);
    secure_channel.set_remote_nonce(remote_public_xy);
    secure_channel.derive_keys();
    secure_channel
}

#[cfg(feature = "ecc")]
fn ecc_send_and_verify(from: &SecureChannel, to: &SecureChannel) {
    let message = make_sample_message();
    let mut chunks =
        Chunker::encode(SequenceNumberHandle::new(true), 1, 0, 0, from, &message).unwrap();
    assert_eq!(chunks.len(), 1);

    let chunk = &mut chunks[0];
    let mut encrypted = vec![0u8; chunk.data.len() + 4096];
    let encrypted_size = from.apply_security(chunk, &mut encrypted[..]).unwrap();

    let mut decrypted = DecryptedChunkStorage::new();
    let chunk2 = to
        .verify_and_remove_security(encrypted[..encrypted_size].to_vec().into(), &mut decrypted)
        .unwrap();
    assert_eq!(&chunk.data, &chunk2.data);

    let message2 = Chunker::decode(&chunks, to, None).unwrap();
    assert_eq!(message, message2);
}

#[cfg(feature = "ecc")]
fn test_ecc_symmetric_roundtrip(
    security_mode: MessageSecurityMode,
    security_policy: SecurityPolicy,
    curve: EccCurve,
    client_scalar_hex: &str,
    server_scalar_hex: &str,
) {
    let _ = Test::setup();

    let client_scalar = ecc_hex(client_scalar_hex);
    let server_scalar = ecc_hex(server_scalar_hex);

    let client_eph = EphemeralPrivateKey::from_scalar_bytes(curve, &client_scalar).unwrap();
    let server_eph = EphemeralPrivateKey::from_scalar_bytes(curve, &server_scalar).unwrap();
    let client_public = client_eph.public_key().unwrap().encoded().to_vec();
    let server_public = server_eph.public_key().unwrap().encoded().to_vec();

    let client_channel = make_ecc_channel(
        Role::Client,
        security_mode,
        security_policy,
        EphemeralPrivateKey::from_scalar_bytes(curve, &client_scalar).unwrap(),
        &server_public,
    );
    let server_channel = make_ecc_channel(
        Role::Server,
        security_mode,
        security_policy,
        EphemeralPrivateKey::from_scalar_bytes(curve, &server_scalar).unwrap(),
        &client_public,
    );

    // Both directions must round-trip: the two sides derived interoperable keys
    // and mapped client/server key sets to local/remote correctly by role.
    ecc_send_and_verify(&client_channel, &server_channel);
    ecc_send_and_verify(&server_channel, &client_channel);
}

// RFC 5903 §8.1 P-256 initiator/responder private keys.
#[cfg(feature = "ecc")]
const RFC5903_P256_I: &str = "C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433";
#[cfg(feature = "ecc")]
const RFC5903_P256_R: &str = "C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53";
// RFC 5903 §8.2 P-384 initiator/responder private keys.
#[cfg(feature = "ecc")]
const RFC5903_P384_I: &str =
    "099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655E35B538041E649EE3FAEF896783AB194";
#[cfg(feature = "ecc")]
const RFC5903_P384_R: &str =
    "41CB0779B4BDB85D47846725FBEC3C9430FAB46CC8DC5060855CC9BDA0AA2942E0308312916B8ED2960E4BD55A7448FC";

#[cfg(feature = "ecc")]
#[test]
fn ecc_nistp256_symmetric_sign_roundtrip() {
    test_ecc_symmetric_roundtrip(
        MessageSecurityMode::Sign,
        SecurityPolicy::EccNistP256,
        EccCurve::P256,
        RFC5903_P256_I,
        RFC5903_P256_R,
    );
}

#[cfg(feature = "ecc")]
#[test]
fn ecc_nistp256_symmetric_sign_and_encrypt_roundtrip() {
    test_ecc_symmetric_roundtrip(
        MessageSecurityMode::SignAndEncrypt,
        SecurityPolicy::EccNistP256,
        EccCurve::P256,
        RFC5903_P256_I,
        RFC5903_P256_R,
    );
}

#[cfg(feature = "ecc")]
#[test]
fn ecc_nistp384_symmetric_sign_roundtrip() {
    test_ecc_symmetric_roundtrip(
        MessageSecurityMode::Sign,
        SecurityPolicy::EccNistP384,
        EccCurve::P384,
        RFC5903_P384_I,
        RFC5903_P384_R,
    );
}

#[cfg(feature = "ecc")]
#[test]
fn ecc_nistp384_symmetric_sign_and_encrypt_roundtrip() {
    test_ecc_symmetric_roundtrip(
        MessageSecurityMode::SignAndEncrypt,
        SecurityPolicy::EccNistP384,
        EccCurve::P384,
        RFC5903_P384_I,
        RFC5903_P384_R,
    );
}

// ---------------------------------------------------------------------------
// ECC OpenSecureChannel ASYMMETRIC layer (feature 012, US3 / T014-T015).
//
// For ECC the OpenSecureChannel message is ECDSA-SIGNED with the application's
// EC private key (verified against the peer's EC application certificate) and
// is NOT asymmetrically encrypted — confidentiality comes from the ECDH-derived
// symmetric keys. So a `SignAndEncrypt` ECC OSC chunk must sign-only at the
// asymmetric layer, exactly like `Sign`. This Claude-authored test pins that:
// an OSC chunk produced by one side verifies on the other (signature checked
// against the sender's EC cert) and a tampered signature is rejected.
// ---------------------------------------------------------------------------

#[cfg(feature = "ecc")]
fn make_test_ecc_cert(curve: EccCurve) -> (X509, PrivateKey) {
    let args = X509Data {
        // key_size is irrelevant for EC keys; the curve fixes the key.
        key_size: 256,
        common_name: "ecc".to_string(),
        organization: "ecc.org".to_string(),
        organizational_unit: "ecc.org ops".to_string(),
        country: "EN".to_string(),
        state: "London".to_string(),
        alt_host_names: vec!["urn:testapplication".to_string(), "testhost".to_string()].into(),
        certificate_duration_days: 60,
    };
    X509::cert_and_pkey_ecc(curve, &args).expect("create self-signed EC cert + key")
}

#[cfg(feature = "ecc")]
fn test_ecc_asymmetric_sign(
    security_mode: MessageSecurityMode,
    security_policy: SecurityPolicy,
    curve: EccCurve,
) {
    use crate::ResponseMessage;

    let _ = Test::setup();

    let (our_cert, our_key) = make_test_ecc_cert(curve);
    let (their_cert, their_key) = make_test_ecc_cert(curve);

    let mut secure_channel = SecureChannel::new_no_certificate_store();
    secure_channel.set_security_mode(security_mode);
    secure_channel.set_security_policy(security_policy);
    secure_channel.set_cert(Some(our_cert));
    secure_channel.set_remote_cert(Some(their_cert));
    secure_channel.set_private_key(Some(our_key));

    let message: ResponseMessage = make_open_secure_channel_response().into();
    let mut chunks = Chunker::encode(
        SequenceNumberHandle::new(true),
        1,
        0,
        0,
        &secure_channel,
        &message,
    )
    .unwrap();
    assert_eq!(chunks.len(), 1);

    let chunk = &mut chunks[0];
    let mut encrypted = vec![0u8; chunk.data.len() + 4096];
    let encrypted_size = secure_channel
        .apply_security(chunk, &mut encrypted[..])
        .unwrap();

    // Flip roles: the verifier checks the ECDSA signature against the SENDER's
    // EC application certificate (now our remote_cert).
    let tmp = secure_channel.cert();
    let remote_cert = secure_channel.remote_cert();
    secure_channel.set_cert(remote_cert);
    secure_channel.set_remote_cert(tmp);
    secure_channel.set_private_key(Some(their_key));

    let mut decrypted = DecryptedChunkStorage::new();
    let chunk2 = secure_channel
        .verify_and_remove_security(encrypted[..encrypted_size].to_vec().into(), &mut decrypted)
        .unwrap();
    assert_eq!(&chunk.data, &chunk2.data);

    // A flipped bit in the encoded chunk must be rejected (no panic).
    let mut corrupted = encrypted[..encrypted_size].to_vec();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0x01;
    let mut decrypted2 = DecryptedChunkStorage::new();
    assert!(
        secure_channel
            .verify_and_remove_security(corrupted.into(), &mut decrypted2)
            .is_err(),
        "tampered ECC OSC chunk must be rejected"
    );
}

#[cfg(feature = "ecc")]
#[test]
fn ecc_nistp256_asymmetric_open_secure_channel_sign() {
    test_ecc_asymmetric_sign(
        MessageSecurityMode::Sign,
        SecurityPolicy::EccNistP256,
        EccCurve::P256,
    );
}

#[cfg(feature = "ecc")]
#[test]
fn ecc_nistp256_asymmetric_open_secure_channel_sign_and_encrypt() {
    test_ecc_asymmetric_sign(
        MessageSecurityMode::SignAndEncrypt,
        SecurityPolicy::EccNistP256,
        EccCurve::P256,
    );
}

#[cfg(feature = "ecc")]
#[test]
fn ecc_nistp384_asymmetric_open_secure_channel_sign() {
    test_ecc_asymmetric_sign(
        MessageSecurityMode::Sign,
        SecurityPolicy::EccNistP384,
        EccCurve::P384,
    );
}

#[cfg(feature = "ecc")]
#[test]
fn ecc_nistp384_asymmetric_open_secure_channel_sign_and_encrypt() {
    test_ecc_asymmetric_sign(
        MessageSecurityMode::SignAndEncrypt,
        SecurityPolicy::EccNistP384,
        EccCurve::P384,
    );
}
