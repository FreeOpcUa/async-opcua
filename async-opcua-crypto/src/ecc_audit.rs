//! Independent retro-audit of the ECC primitives (`crate::ecc`).
//!
//! Authored separately from the implementation and from the implementation's
//! own `#[cfg(test)] mod tests`. The goal is to break the self-verification
//! loop: the implementation must satisfy tests it did not write, anchored to
//! ground truth its author never produced.
//!
//! Independence anchors used here:
//!  * ECDSA / ECDH known-answer vectors transcribed *directly* from the RFC
//!    text (RFC 6979 Appendix A.2.5/A.2.6, RFC 5903 §8.1/§8.2), not copied from
//!    the implementation's test module.
//!  * A from-scratch HKDF (HMAC-Extract + RFC 5869 Expand) and OPC UA Part 6
//!    §6.8.1 salt construction implemented here with `hmac`/`sha2` directly,
//!    *not* reusing the implementation's `hkdf`-crate code path. Two independent
//!    implementations of the same spec must agree on the real key schedule.
//!
//! Residual gap (honestly recorded): the OPC UA salt/label construction is not
//! covered by any published RFC vector. These tests prove the implementation
//! agrees with an independent reading of OPC UA Part 6 §6.8.1; they do NOT
//! prove that reading is spec-correct. Only interop against a third-party ECC
//! peer (UA-.NETStandard / open62541) closes that gap.

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384};

use crate::ecc::{
    decode_public_key, derive_keys, ecdh_shared_secret, ecdsa_verify, generate_ephemeral_keypair,
    EccCurve, EccPrivateKey, EccPublicKey, EphemeralPrivateKey,
};
use crate::{KeySize, PrivateKey, SecurityPolicy, X509Data, X509};

/// Independent hex decoder (whitespace-tolerant), written for this module so
/// the vectors do not share decoding code with the implementation's tests.
fn h(s: &str) -> Vec<u8> {
    let cleaned: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert!(cleaned.len().is_multiple_of(2), "odd-length hex literal");
    cleaned
        .chunks_exact(2)
        .map(|p| {
            let hi = (p[0] as char).to_digit(16).expect("hex digit");
            let lo = (p[1] as char).to_digit(16).expect("hex digit");
            ((hi << 4) | lo) as u8
        })
        .collect()
}

/// `0x04 || X || Y` uncompressed SEC1 encoding from coordinate hex strings.
fn sec1(x: &str, y: &str) -> Vec<u8> {
    let mut v = vec![0x04u8];
    v.extend_from_slice(&h(x));
    v.extend_from_slice(&h(y));
    v
}

// --------------------------------------------------------------------------
// Independent HKDF + OPC UA Part 6 §6.8.1 key schedule (reference impl).
// --------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Prf {
    Sha256,
    Sha384,
}

impl Prf {
    fn len(self) -> usize {
        match self {
            Prf::Sha256 => 32,
            Prf::Sha384 => 48,
        }
    }

    fn mac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Prf::Sha256 => {
                let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            Prf::Sha384 => {
                let mut m = <Hmac<Sha384> as Mac>::new_from_slice(key).expect("hmac key");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
        }
    }
}

/// RFC 5869 HKDF-Extract then HKDF-Expand, from scratch.
fn hkdf(prf: Prf, salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let prk = prf.mac(salt, ikm); // Extract
    let hash_len = prf.len();
    let n = length.div_ceil(hash_len);
    let mut okm = Vec::with_capacity(n * hash_len);
    let mut t: Vec<u8> = Vec::new();
    for i in 1..=n {
        let mut input = Vec::with_capacity(t.len() + info.len() + 1);
        input.extend_from_slice(&t);
        input.extend_from_slice(info);
        input.push(i as u8);
        t = prf.mac(&prk, &input);
        okm.extend_from_slice(&t);
    }
    okm.truncate(length);
    okm
}

/// OPC UA Part 6 §6.8.1 Step 1 salt: `L(u16 LE) || label || nonce_a || nonce_b`.
fn opc_salt(key_material_len: usize, label: &[u8], nonce_a: &[u8], nonce_b: &[u8]) -> Vec<u8> {
    let l = u16::try_from(key_material_len).expect("L fits u16");
    let mut s = Vec::new();
    s.extend_from_slice(&l.to_le_bytes());
    s.extend_from_slice(label);
    s.extend_from_slice(nonce_a);
    s.extend_from_slice(nonce_b);
    s
}

/// One direction's (signing, encrypting, iv) lengths for a curve.
fn key_lens(curve: EccCurve) -> (usize, usize, usize) {
    match curve {
        EccCurve::P256 => (32, 16, 16),
        EccCurve::P384 => (48, 32, 16),
    }
}

/// Independent reference derivation: returns (signing, encrypting, iv) bytes.
fn reference_direction(
    curve: EccCurve,
    label: &[u8],
    secret: &[u8],
    nonce_a: &[u8],
    nonce_b: &[u8],
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (sig, enc, iv) = key_lens(curve);
    let total = sig + enc + iv;
    let salt = opc_salt(total, label, nonce_a, nonce_b);
    let prf = match curve {
        EccCurve::P256 => Prf::Sha256,
        EccCurve::P384 => Prf::Sha384,
    };
    // Per §6.8.1: IKM = shared secret, Salt = Info = the direction's salt.
    let okm = hkdf(prf, &salt, secret, &salt, total);
    (
        okm[..sig].to_vec(),
        okm[sig..sig + enc].to_vec(),
        okm[sig + enc..].to_vec(),
    )
}

// --------------------------------------------------------------------------
// ECDSA — RFC 6979 deterministic signatures verify; keygen matches.
// --------------------------------------------------------------------------

#[test]
fn ecdsa_p256_rfc6979_keygen_and_verify() {
    // RFC 6979 Appendix A.2.5 (NIST P-256, SHA-256, message "sample").
    let priv_x = h("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    let ux = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
    let uy = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
    let mut sig = h("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716");
    sig.extend_from_slice(&h(
        "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
    ));

    // Public key derived from the RFC private scalar must equal the RFC point.
    let sk = EccPrivateKey::from_scalar_bytes(EccCurve::P256, &priv_x).expect("priv scalar");
    let pk = sk.public_key().expect("derive public key");
    let mut expect_pub = h(ux);
    expect_pub.extend_from_slice(&h(uy));
    assert_eq!(
        pk.encoded(),
        expect_pub.as_slice(),
        "keygen != RFC public key"
    );

    // The externally-produced (deterministic) signature must verify.
    let vk = EccPublicKey::from_sec1_bytes(EccCurve::P256, &sec1(ux, uy)).expect("pubkey");
    ecdsa_verify(&vk, b"sample", &sig).expect("RFC 6979 P-256 signature must verify");
    // And verify against the key we derived ourselves from the private scalar.
    ecdsa_verify(&pk, b"sample", &sig).expect("verify against derived key");

    // Tamper and length checks (fail-closed).
    let mut bad = sig.clone();
    bad[0] ^= 0x01;
    assert!(
        ecdsa_verify(&vk, b"sample", &bad).is_err(),
        "tampered sig accepted"
    );
    assert!(
        ecdsa_verify(&vk, b"sample", &sig[..63]).is_err(),
        "short sig accepted"
    );
    assert!(
        ecdsa_verify(&vk, b"other message", &sig).is_err(),
        "wrong message accepted"
    );
}

#[test]
fn ecdsa_p384_rfc6979_keygen_and_verify() {
    // RFC 6979 Appendix A.2.6 (NIST P-384, SHA-384, message "sample").
    let priv_x = h(
        "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8\
                    96D5724E4C70A825F872C9EA60D2EDF5",
    );
    let ux = "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64\
              DEF8F0EA9055866064A254515480BC13";
    let uy = "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1\
              288B231C3AE0D4FE7344FD2533264720";
    let mut sig = h(
        "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C\
                     81A648152E44ACF96E36DD1E80FABE46",
    );
    sig.extend_from_slice(&h(
        "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F\
         A329C145786E679E7B82C71A38628AC8",
    ));

    let sk = EccPrivateKey::from_scalar_bytes(EccCurve::P384, &priv_x).expect("priv scalar");
    let pk = sk.public_key().expect("derive public key");
    let mut expect_pub = h(ux);
    expect_pub.extend_from_slice(&h(uy));
    assert_eq!(
        pk.encoded(),
        expect_pub.as_slice(),
        "keygen != RFC public key"
    );

    let vk = EccPublicKey::from_sec1_bytes(EccCurve::P384, &sec1(ux, uy)).expect("pubkey");
    ecdsa_verify(&vk, b"sample", &sig).expect("RFC 6979 P-384 signature must verify");
    ecdsa_verify(&pk, b"sample", &sig).expect("verify against derived key");

    let mut bad = sig.clone();
    bad[95] ^= 0x01;
    assert!(
        ecdsa_verify(&vk, b"sample", &bad).is_err(),
        "tampered sig accepted"
    );
    assert!(
        ecdsa_verify(&vk, b"sample", &sig[..95]).is_err(),
        "short sig accepted"
    );
}

// --------------------------------------------------------------------------
// ECDH — RFC 5903 vectors, checked in BOTH directions, with keygen.
// --------------------------------------------------------------------------

#[test]
fn ecdh_p256_rfc5903_both_directions() {
    // RFC 5903 §8.1 (256-bit Random ECP Group).
    let i = h("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433");
    let gix = "DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180";
    let giy = "5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3";
    let r = h("C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53");
    let grx = "D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63";
    let gry = "56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB";
    let shared = h("D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE");

    let i_priv = EphemeralPrivateKey::from_scalar_bytes(EccCurve::P256, &i).expect("i");
    let r_priv = EphemeralPrivateKey::from_scalar_bytes(EccCurve::P256, &r).expect("r");
    let i_pub = i_priv.public_key().expect("gi");
    let r_pub = r_priv.public_key().expect("gr");

    let mut expect_i = h(gix);
    expect_i.extend_from_slice(&h(giy));
    let mut expect_r = h(grx);
    expect_r.extend_from_slice(&h(gry));
    assert_eq!(
        i_pub.encoded(),
        expect_i.as_slice(),
        "initiator keygen != RFC"
    );
    assert_eq!(
        r_pub.encoded(),
        expect_r.as_slice(),
        "responder keygen != RFC"
    );

    let s1 = ecdh_shared_secret(&i_priv, &r_pub).expect("ECDH i*gr");
    let s2 = ecdh_shared_secret(&r_priv, &i_pub).expect("ECDH r*gi");
    assert_eq!(&s1[..], shared.as_slice(), "i*gr != RFC shared secret");
    assert_eq!(&s2[..], shared.as_slice(), "r*gi != RFC shared secret");
}

#[test]
fn ecdh_p384_rfc5903_both_directions() {
    // RFC 5903 §8.2 (384-bit Random ECP Group).
    let i = h(
        "099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655\
               E35B538041E649EE3FAEF896783AB194",
    );
    let gix = "667842D7D180AC2CDE6F74F37551F55755C7645C20EF73E31634FE72B4C55EE6\
               DE3AC808ACB4BDB4C88732AEE95F41AA";
    let giy = "9482ED1FC0EEB9CAFC4984625CCFC23F65032149E0E144ADA024181535A0F38E\
               EB9FCFF3C2C947DAE69B4C634573A81C";
    let r = h(
        "41CB0779B4BDB85D47846725FBEC3C9430FAB46CC8DC5060855CC9BDA0AA2942\
               E0308312916B8ED2960E4BD55A7448FC",
    );
    let grx = "E558DBEF53EECDE3D3FCCFC1AEA08A89A987475D12FD950D83CFA41732BC509D\
               0D1AC43A0336DEF96FDA41D0774A3571";
    let gry = "DCFBEC7AACF3196472169E838430367F66EEBE3C6E70C416DD5F0C68759DD1FF\
               F83FA40142209DFF5EAAD96DB9E6386C";
    let shared = h(
        "11187331C279962D93D604243FD592CB9D0A926F422E47187521287E7156C5C4\
                    D603135569B9E9D09CF5D4A270F59746",
    );

    let i_priv = EphemeralPrivateKey::from_scalar_bytes(EccCurve::P384, &i).expect("i");
    let r_priv = EphemeralPrivateKey::from_scalar_bytes(EccCurve::P384, &r).expect("r");
    let i_pub = i_priv.public_key().expect("gi");
    let r_pub = r_priv.public_key().expect("gr");

    let mut expect_i = h(gix);
    expect_i.extend_from_slice(&h(giy));
    let mut expect_r = h(grx);
    expect_r.extend_from_slice(&h(gry));
    assert_eq!(
        i_pub.encoded(),
        expect_i.as_slice(),
        "initiator keygen != RFC"
    );
    assert_eq!(
        r_pub.encoded(),
        expect_r.as_slice(),
        "responder keygen != RFC"
    );

    let s1 = ecdh_shared_secret(&i_priv, &r_pub).expect("ECDH i*gr");
    let s2 = ecdh_shared_secret(&r_priv, &i_pub).expect("ECDH r*gi");
    assert_eq!(&s1[..], shared.as_slice(), "i*gr != RFC shared secret");
    assert_eq!(&s2[..], shared.as_slice(), "r*gi != RFC shared secret");
}

// --------------------------------------------------------------------------
// OPC UA key schedule — cross-check the REAL production path against an
// independent reimplementation (the path codex's own tests never exercise).
// --------------------------------------------------------------------------

fn assert_derive_matches_reference(policy: SecurityPolicy, curve: EccCurve, secret_len: usize) {
    // Deterministic, distinct, realistically-sized inputs.
    let secret: Vec<u8> = (0..secret_len).map(|n| (0x40 + n) as u8).collect();
    let client_nonce: Vec<u8> = (0..curve.encoded_public_key_len())
        .map(|n| (0x01 + n) as u8)
        .collect();
    let server_nonce: Vec<u8> = (0..curve.encoded_public_key_len())
        .map(|n| (0x80 + n) as u8)
        .collect();

    let keys = derive_keys(policy, &secret, &client_nonce, &server_nonce)
        .expect("production derive_keys on a correctly-sized shared secret");

    let (c_sig, c_enc, c_iv) = reference_direction(
        curve,
        b"opcua-client",
        &secret,
        &client_nonce,
        &server_nonce,
    );
    let (s_sig, s_enc, s_iv) = reference_direction(
        curve,
        b"opcua-server",
        &secret,
        &server_nonce,
        &client_nonce,
    );

    assert_eq!(
        keys.client.signing_key(),
        c_sig.as_slice(),
        "client signing key"
    );
    assert_eq!(
        keys.client.encryption_key().value(),
        c_enc.as_slice(),
        "client encrypting key"
    );
    assert_eq!(
        keys.client.initialization_vector(),
        c_iv.as_slice(),
        "client IV"
    );
    assert_eq!(
        keys.server.signing_key(),
        s_sig.as_slice(),
        "server signing key"
    );
    assert_eq!(
        keys.server.encryption_key().value(),
        s_enc.as_slice(),
        "server encrypting key"
    );
    assert_eq!(
        keys.server.initialization_vector(),
        s_iv.as_slice(),
        "server IV"
    );
}

#[test]
fn opcua_derive_keys_p256_matches_independent_schedule() {
    assert_derive_matches_reference(SecurityPolicy::EccNistP256, EccCurve::P256, 32);
}

#[test]
fn opcua_derive_keys_p384_matches_independent_schedule() {
    assert_derive_matches_reference(SecurityPolicy::EccNistP384, EccCurve::P384, 48);
}

/// Regression guard for the fail-closed IKM-size check.
///
/// `derive_keys` must reject any shared secret that is not the curve's
/// field-element size (the only valid IKM is the ECDH x-coordinate: 32 B P-256
/// / 48 B P-384). This audit originally caught the implementation *silently
/// switching to a different HKDF schedule* (`split_direct_hkdf_self_test_keys`)
/// for off-size inputs — scaffolding that let the RFC 5869 "known-answer test"
/// pass without ever exercising the real OPC UA key schedule. That branch was
/// removed; this test ensures it does not come back.
#[test]
fn opcua_derive_keys_rejects_wrong_size_shared_secret() {
    // 22 bytes: the RFC 5869 IKM length the rigged branch was built to accept.
    let bad_secret = h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let client_nonce = h("000102030405060708090a0b0c");
    let server_nonce = h("f0f1f2f3f4f5f6f7f8f9");

    let result = derive_keys(
        SecurityPolicy::EccNistP256,
        &bad_secret,
        &client_nonce,
        &server_nonce,
    );
    assert!(
        result.is_err(),
        "derive_keys accepted a {}-byte shared secret for P-256 (expected 32) and \
         silently ran the test-only HKDF branch instead of failing closed",
        bad_secret.len()
    );
}

// --------------------------------------------------------------------------
// EC application key PKI round-trip (feature 012, US3 prerequisite).
//
// A real ECC deployment loads its EC application key from a PEM file in the PKI
// directory. This Claude-authored test pins that an EC private key survives a
// to_pem -> from_pem round-trip and still signs OpenSecureChannel data that
// verifies against the matching certificate's EC public key.
// --------------------------------------------------------------------------

#[cfg(feature = "ecc")]
fn ecc_test_x509_data() -> X509Data {
    X509Data {
        key_size: 256,
        common_name: "ecc-pki".to_string(),
        organization: "ecc.org".to_string(),
        organizational_unit: "ecc.org ops".to_string(),
        country: "EN".to_string(),
        state: "London".to_string(),
        alt_host_names: vec!["urn:ecc-pki".to_string(), "ecc-host".to_string()].into(),
        certificate_duration_days: 60,
    }
}

#[test]
fn ec_application_key_pem_roundtrip_signs_and_verifies() {
    for (curve, policy) in [
        (EccCurve::P256, SecurityPolicy::EccNistP256),
        (EccCurve::P384, SecurityPolicy::EccNistP384),
    ] {
        let (cert, key) = X509::cert_and_pkey_ecc(curve, &ecc_test_x509_data())
            .expect("create self-signed EC cert + key");

        // Round-trip the private key through PEM, as the PKI loader does.
        let pem = key.to_pem().expect("serialize EC private key to PEM");
        let reloaded = PrivateKey::from_pem(pem.as_bytes()).expect("load EC private key from PEM");
        assert_eq!(reloaded.size(), curve.raw_signature_len());

        // The reloaded key must produce a signature that verifies against the
        // certificate's public key.
        let data = b"OPC UA ECC OpenSecureChannel PEM round-trip";
        let mut signature = vec![0u8; reloaded.size()];
        policy
            .asymmetric_sign(&reloaded, data, &mut signature)
            .expect("ECDSA sign with reloaded EC key");
        let public_key = cert.public_key().expect("certificate EC public key");
        policy
            .asymmetric_verify_signature(&public_key, data, &signature)
            .expect("signature from reloaded key must verify against the cert");
    }
}

// --------------------------------------------------------------------------
// Fail-closed negatives (feature 012, US3 / SC-004).
//
// Attacker-controlled handshake inputs must be rejected with an error, never a
// panic, and a key from the wrong algorithm/curve must not be accepted. These
// are the security negatives an honest interop peer can never trigger but a
// hostile one will, authored independently by Claude.
// --------------------------------------------------------------------------

#[test]
fn malformed_ephemeral_public_keys_are_rejected_without_panic() {
    // Wrong length (too short / too long for the curve).
    assert!(decode_public_key(EccCurve::P256, &[0u8; 10]).is_err());
    assert!(decode_public_key(EccCurve::P256, &[0u8; 96]).is_err());
    assert!(decode_public_key(EccCurve::P384, &[0u8; 64]).is_err());
    // Correct length but not a valid curve point (all-zero X||Y is not on the curve).
    assert!(decode_public_key(EccCurve::P256, &[0u8; 64]).is_err());
    assert!(decode_public_key(EccCurve::P384, &[0u8; 96]).is_err());
}

#[test]
fn ecdh_across_mismatched_curves_is_rejected() {
    let p256_private = EphemeralPrivateKey::generate(EccCurve::P256).expect("p256 ephemeral");
    let p384_public = generate_ephemeral_keypair(EccCurve::P384)
        .expect("p384 ephemeral")
        .public_key()
        .clone();
    // A P-256 private key must not perform ECDH against a P-384 public key.
    assert!(ecdh_shared_secret(&p256_private, &p384_public).is_err());
}

#[test]
fn rsa_public_key_is_rejected_for_an_ecc_policy() {
    // An RSA application certificate must not be usable as an EC verifying key
    // (the "RSA cert on an ECC policy" case).
    let rsa = PrivateKey::new(2048).expect("generate RSA key");
    let spki = rsa.public_key_to_info().expect("RSA SubjectPublicKeyInfo");
    assert!(EccPublicKey::from_subject_public_key_info(EccCurve::P256, &spki).is_err());
    assert!(EccPublicKey::from_subject_public_key_info(EccCurve::P384, &spki).is_err());
}

#[test]
fn ecdsa_verify_rejects_wrong_curve_key_length() {
    // A P-256 verifying key must reject a P-384-length (96-byte) signature, and
    // vice versa — no out-of-bounds, no panic, just a clean error.
    let p256 = EccPrivateKey::generate(EccCurve::P256)
        .expect("p256 key")
        .public_key()
        .expect("p256 public");
    let p384 = EccPrivateKey::generate(EccCurve::P384)
        .expect("p384 key")
        .public_key()
        .expect("p384 public");
    assert!(ecdsa_verify(&p256, b"msg", &[0u8; 96]).is_err());
    assert!(ecdsa_verify(&p384, b"msg", &[0u8; 64]).is_err());
}
