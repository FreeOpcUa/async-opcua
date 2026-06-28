// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0

//! Independent tests for the Part 4 §6.1.3 (Table 100) certificate-chain validation engine.
//!
//! These tests are authored separately from the production implementation (verification
//! division): they build real RSA PKI fixtures (root CA → intermediate CA → leaf) with the
//! `x509-cert` builder and the in-tree RSA keys, then assert the EXACT OPC UA status code each
//! Table 100 step must produce. US1 covers: certificate structure, build-chain, signature
//! verification, trust-list anchoring, and per-certificate validity period.

use chrono::{DateTime, TimeZone, Utc};
use rsa::pkcs1v15::{Signature, SigningKey};
use rsa::signature::{SignatureEncoding, Signer};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::{Duration as StdDuration, UNIX_EPOCH};

use const_oid::db::rfc5280::{ID_KP_CLIENT_AUTH, ID_KP_SERVER_AUTH};
use const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
use x509_cert::der::asn1::{Any, BitString, Null, OctetString};
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
    SubjectKeyIdentifier,
};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};
use x509_cert::Version;

use std::path::Path;

use opcua_types::status_code::StatusCode;
use tempfile::TempDir;

use crate::{
    validate_certificate_chain, CertificatePurpose, CertificateStore, ChainValidationContext,
    PrivateKey, RevocationMode, SecurityPolicy, SuppressibleStep, ValidationOptions, X509,
};

// --- shared key pool (RSA-2048 keygen is the slow part; generate once) ---------------------

struct KeyPool {
    root: PrivateKey,
    intermediate: PrivateKey,
    leaf: PrivateKey,
    // an unrelated CA key used to forge signatures / build untrusted roots
    rogue: PrivateKey,
}

fn keys() -> &'static KeyPool {
    static POOL: OnceLock<KeyPool> = OnceLock::new();
    POOL.get_or_init(|| KeyPool {
        root: PrivateKey::new(2048).expect("root key"),
        intermediate: PrivateKey::new(2048).expect("intermediate key"),
        leaf: PrivateKey::new(2048).expect("leaf key"),
        rogue: PrivateKey::new(2048).expect("rogue key"),
    })
}

// --- fixture builder -----------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Eku {
    None,
    ServerAuth,
    ClientAuth,
    /// Both serverAuth and clientAuth, as real OPC UA application instance certs carry.
    Both,
}

/// How a fixture sets the KeyUsage extension.
#[derive(Clone)]
enum KuChoice {
    /// digitalSignature+keyEncipherment for leaves, keyCertSign+cRLSign for CAs.
    Default,
    /// An explicit KeyUsage extension (for negative tests).
    Custom(KeyUsage),
    /// Omit the KeyUsage extension entirely.
    Omit,
}

/// Specification for one fixture certificate. `issuer_key` provides the issuer identity (its
/// public key's SHA-1 SKI is written as this cert's AuthorityKeyIdentifier), while `signer_key`
/// is the key that actually signs the TBS — normally the same as `issuer_key`, but set to a
/// different key to forge an invalid signature without disturbing chain matching.
struct CertSpec<'a> {
    subject_cn: &'a str,
    subject_key: &'a PrivateKey,
    issuer_cn: &'a str,
    issuer_key: &'a PrivateKey,
    signer_key: &'a PrivateKey,
    is_ca: bool,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    eku: Eku,
    key_usage: KuChoice,
    serial: u32,
}

fn ski_of(spki: &SubjectPublicKeyInfoOwned) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(spki.subject_public_key.raw_bytes());
    hasher.finalize().to_vec()
}

fn to_time(dt: DateTime<Utc>) -> Time {
    let secs = u64::try_from(dt.timestamp()).expect("non-negative timestamp");
    Time::try_from(UNIX_EPOCH + StdDuration::from_secs(secs)).expect("valid x509 time")
}

fn issue(spec: &CertSpec<'_>) -> X509 {
    let subject_spki = spec.subject_key.public_key_to_info().expect("subject spki");
    let issuer_spki = spec.issuer_key.public_key_to_info().expect("issuer spki");
    let signing_rsa = spec
        .signer_key
        .rsa_key_for_x509()
        .expect("signer rsa key")
        .clone();
    let signing_key = SigningKey::<Sha256>::new(signing_rsa);

    let subject = Name::from_str(&format!("CN={}", spec.subject_cn)).expect("subject name");
    let issuer = Name::from_str(&format!("CN={}", spec.issuer_cn)).expect("issuer name");
    let validity = Validity {
        not_before: to_time(spec.not_before),
        not_after: to_time(spec.not_after),
    };

    let profile = Profile::Manual {
        issuer: Some(issuer),
    };
    let mut builder = CertificateBuilder::new(
        profile,
        SerialNumber::from(spec.serial),
        validity,
        subject,
        subject_spki.clone(),
        &signing_key,
    )
    .expect("certificate builder");

    let ski = ski_of(&subject_spki);
    builder
        .add_extension(&SubjectKeyIdentifier(
            OctetString::new(ski).expect("ski octets"),
        ))
        .expect("add ski");
    let aki = ski_of(&issuer_spki);
    builder
        .add_extension(&AuthorityKeyIdentifier {
            authority_cert_issuer: None,
            key_identifier: Some(OctetString::new(aki).expect("aki octets")),
            authority_cert_serial_number: None,
        })
        .expect("add aki");
    builder
        .add_extension(&BasicConstraints {
            ca: spec.is_ca,
            path_len_constraint: None,
        })
        .expect("add basic constraints");

    let key_usage = match &spec.key_usage {
        KuChoice::Default if spec.is_ca => {
            Some(KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign))
        }
        KuChoice::Default => Some(KeyUsage(
            KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment,
        )),
        KuChoice::Custom(ku) => Some(*ku),
        KuChoice::Omit => None,
    };
    if let Some(key_usage) = key_usage {
        builder.add_extension(&key_usage).expect("add key usage");
    }

    match spec.eku {
        Eku::None => {}
        Eku::ServerAuth => builder
            .add_extension(&ExtendedKeyUsage(vec![ID_KP_SERVER_AUTH]))
            .expect("add eku"),
        Eku::ClientAuth => builder
            .add_extension(&ExtendedKeyUsage(vec![ID_KP_CLIENT_AUTH]))
            .expect("add eku"),
        Eku::Both => builder
            .add_extension(&ExtendedKeyUsage(vec![
                ID_KP_SERVER_AUTH,
                ID_KP_CLIENT_AUTH,
            ]))
            .expect("add eku"),
    }

    let cert = builder.build::<Signature>().expect("build cert");
    let der = cert.to_der().expect("cert der");
    X509::from_der(&der).expect("parse fixture cert")
}

// --- convenient time helpers ---------------------------------------------------------------

fn t(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap()
}

fn now_valid() -> DateTime<Utc> {
    t(2025, 6, 1)
}

const ROOT_CN: &str = "async-opcua test root ca";
const INT_CN: &str = "async-opcua test intermediate ca";
const LEAF_CN: &str = "async-opcua test leaf";

fn root_ca() -> X509 {
    let k = keys();
    issue(&CertSpec {
        subject_cn: ROOT_CN,
        subject_key: &k.root,
        issuer_cn: ROOT_CN,
        issuer_key: &k.root,
        signer_key: &k.root,
        is_ca: true,
        key_usage: KuChoice::Default,
        not_before: t(2020, 1, 1),
        not_after: t(2035, 1, 1),
        eku: Eku::None,
        serial: 1,
    })
}

fn intermediate_ca_with(not_after: DateTime<Utc>) -> X509 {
    let k = keys();
    issue(&CertSpec {
        subject_cn: INT_CN,
        subject_key: &k.intermediate,
        issuer_cn: ROOT_CN,
        issuer_key: &k.root,
        signer_key: &k.root,
        is_ca: true,
        key_usage: KuChoice::Default,
        not_before: t(2020, 1, 1),
        not_after,
        eku: Eku::None,
        serial: 2,
    })
}

fn intermediate_ca() -> X509 {
    intermediate_ca_with(t(2034, 1, 1))
}

/// A leaf signed by the intermediate CA, valid until `not_after`.
fn leaf_via_intermediate(not_after: DateTime<Utc>) -> X509 {
    let k = keys();
    issue(&CertSpec {
        subject_cn: LEAF_CN,
        subject_key: &k.leaf,
        issuer_cn: INT_CN,
        issuer_key: &k.intermediate,
        signer_key: &k.intermediate,
        is_ca: false,
        key_usage: KuChoice::Default,
        not_before: t(2020, 1, 1),
        not_after,
        eku: Eku::ServerAuth,
        serial: 3,
    })
}

fn empty_crls() -> Vec<CertificateList> {
    Vec::new()
}

fn server_ctx<'a>(
    trusted: &'a [X509],
    issuers: &'a [X509],
    crls: &'a [CertificateList],
    options: &'a ValidationOptions,
    now: &'a DateTime<Utc>,
) -> ChainValidationContext<'a> {
    ChainValidationContext {
        trusted_certs: trusted,
        issuer_certs: issuers,
        crls,
        ocsp_responses: &[],
        security_policy: SecurityPolicy::Basic256Sha256,
        purpose: CertificatePurpose::ServerApplication,
        options,
        now,
    }
}

/// Like `server_ctx` but with supplied OCSP responses (DER) for the revocation tests.
#[allow(clippy::too_many_arguments)]
fn server_ctx_ocsp<'a>(
    trusted: &'a [X509],
    issuers: &'a [X509],
    crls: &'a [CertificateList],
    ocsp_responses: &'a [Vec<u8>],
    options: &'a ValidationOptions,
    now: &'a DateTime<Utc>,
) -> ChainValidationContext<'a> {
    ChainValidationContext {
        trusted_certs: trusted,
        issuer_certs: issuers,
        crls,
        ocsp_responses,
        security_policy: SecurityPolicy::Basic256Sha256,
        purpose: CertificatePurpose::ServerApplication,
        options,
        now,
    }
}

// --- US1 tests -----------------------------------------------------------------------------

#[test]
fn valid_three_level_chain_is_accepted() {
    let root = root_ca();
    let intermediate = intermediate_ca();
    let leaf = leaf_via_intermediate(t(2030, 1, 1));

    let trusted = [root];
    let issuers = [intermediate];
    let crls = empty_crls();
    let options = ValidationOptions::default();
    let now = now_valid();

    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    validate_certificate_chain(&leaf, &ctx)
        .expect("leaf chaining to a trusted root via a known intermediate must validate");
}

#[test]
fn valid_two_level_chain_is_accepted() {
    // Leaf issued directly by the root, root trusted.
    let k = keys();
    let root = root_ca();
    let leaf = issue(&CertSpec {
        subject_cn: LEAF_CN,
        subject_key: &k.leaf,
        issuer_cn: ROOT_CN,
        issuer_key: &k.root,
        signer_key: &k.root,
        is_ca: false,
        key_usage: KuChoice::Default,
        not_before: t(2020, 1, 1),
        not_after: t(2030, 1, 1),
        eku: Eku::ServerAuth,
        serial: 10,
    });

    let trusted = [root];
    let issuers: [X509; 0] = [];
    let crls = empty_crls();
    let options = ValidationOptions::default();
    let now = now_valid();

    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    validate_certificate_chain(&leaf, &ctx)
        .expect("leaf signed directly by a trusted root must validate");
}

#[test]
fn self_signed_leaf_in_trusted_is_accepted() {
    // Backward compatibility: a self-signed application cert dropped into trusted/ is its own
    // issuer and must still validate.
    let k = keys();
    let leaf = issue(&CertSpec {
        subject_cn: LEAF_CN,
        subject_key: &k.leaf,
        issuer_cn: LEAF_CN,
        issuer_key: &k.leaf,
        signer_key: &k.leaf,
        is_ca: false,
        key_usage: KuChoice::Default,
        not_before: t(2020, 1, 1),
        not_after: t(2030, 1, 1),
        eku: Eku::ServerAuth,
        serial: 11,
    });

    let trusted = [leaf.clone()];
    let issuers: [X509; 0] = [];
    let crls = empty_crls();
    let options = ValidationOptions::default();
    let now = now_valid();

    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    validate_certificate_chain(&leaf, &ctx)
        .expect("a self-signed leaf placed in trusted/ must validate");
}

#[test]
fn missing_intermediate_is_chain_incomplete() {
    let root = root_ca();
    let leaf = leaf_via_intermediate(t(2030, 1, 1));

    // Intermediate deliberately absent from both trusted and issuer lists.
    let trusted = [root];
    let issuers: [X509; 0] = [];
    let crls = empty_crls();
    let options = ValidationOptions::default();
    let now = now_valid();

    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    let err = validate_certificate_chain(&leaf, &ctx)
        .expect_err("a leaf whose issuing CA is unavailable must be rejected");
    assert_eq!(err.status(), StatusCode::BadCertificateChainIncomplete);
}

#[test]
fn forged_leaf_signature_is_invalid() {
    // The leaf claims to be issued by the intermediate (matching issuer DN + AKI) but is signed
    // by an unrelated key, so its signature does not verify against the intermediate's key.
    let k = keys();
    let root = root_ca();
    let intermediate = intermediate_ca();
    let leaf = issue(&CertSpec {
        subject_cn: LEAF_CN,
        subject_key: &k.leaf,
        issuer_cn: INT_CN,
        issuer_key: &k.intermediate,
        signer_key: &k.rogue,
        is_ca: false,
        key_usage: KuChoice::Default,
        not_before: t(2020, 1, 1),
        not_after: t(2030, 1, 1),
        eku: Eku::ServerAuth,
        serial: 12,
    });

    let trusted = [root];
    let issuers = [intermediate];
    let crls = empty_crls();
    let options = ValidationOptions::default();
    let now = now_valid();

    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    let err = validate_certificate_chain(&leaf, &ctx)
        .expect_err("a leaf with a forged signature must be rejected");
    assert_eq!(err.status(), StatusCode::BadCertificateInvalid);
}

#[test]
fn chain_to_untrusted_root_is_untrusted() {
    // A complete, cryptographically valid chain whose root is NOT in the trusted list.
    let k = keys();
    // Build a self-contained chain anchored on the rogue key as a self-signed root.
    let rogue_root = issue(&CertSpec {
        subject_cn: "rogue root",
        subject_key: &k.rogue,
        issuer_cn: "rogue root",
        issuer_key: &k.rogue,
        signer_key: &k.rogue,
        is_ca: true,
        key_usage: KuChoice::Default,
        not_before: t(2020, 1, 1),
        not_after: t(2035, 1, 1),
        eku: Eku::None,
        serial: 20,
    });
    let rogue_leaf = issue(&CertSpec {
        subject_cn: LEAF_CN,
        subject_key: &k.leaf,
        issuer_cn: "rogue root",
        issuer_key: &k.rogue,
        signer_key: &k.rogue,
        is_ca: false,
        key_usage: KuChoice::Default,
        not_before: t(2020, 1, 1),
        not_after: t(2030, 1, 1),
        eku: Eku::ServerAuth,
        serial: 21,
    });

    // The genuine root is trusted; the rogue root is only an issuer (available but not trusted).
    let trusted = [root_ca()];
    let issuers = [rogue_root];
    let crls = empty_crls();
    let options = ValidationOptions::default();
    let now = now_valid();

    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    let err = validate_certificate_chain(&rogue_leaf, &ctx)
        .expect_err("a chain that does not reach a trusted anchor must be rejected");
    assert_eq!(err.status(), StatusCode::BadCertificateUntrusted);
}

#[test]
fn expired_leaf_is_time_invalid() {
    let root = root_ca();
    let intermediate = intermediate_ca();
    let leaf = leaf_via_intermediate(t(2021, 1, 1)); // expired well before now (2025)

    let trusted = [root];
    let issuers = [intermediate];
    let crls = empty_crls();
    let options = ValidationOptions::default();
    let now = now_valid();

    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    let err =
        validate_certificate_chain(&leaf, &ctx).expect_err("an expired leaf must be rejected");
    assert_eq!(err.status(), StatusCode::BadCertificateTimeInvalid);
}

#[test]
fn expired_intermediate_is_issuer_time_invalid() {
    let root = root_ca();
    let intermediate = intermediate_ca_with(t(2021, 1, 1)); // issuer expired before now
    let leaf = leaf_via_intermediate(t(2030, 1, 1)); // leaf itself still valid

    let trusted = [root];
    let issuers = [intermediate];
    let crls = empty_crls();
    let options = ValidationOptions::default();
    let now = now_valid();

    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    let err = validate_certificate_chain(&leaf, &ctx)
        .expect_err("an expired issuer in the chain must be rejected");
    assert_eq!(err.status(), StatusCode::BadCertificateIssuerTimeInvalid);
}

#[test]
fn valid_chain_validates_for_client_application_purpose() {
    // The same chain machinery validates a client-auth leaf under the ClientApplication purpose
    // (purpose only affects the US2 ExtendedKeyUsage check; the chain itself must still validate).
    let k = keys();
    let root = root_ca();
    let intermediate = intermediate_ca();
    let client_leaf = issue(&CertSpec {
        subject_cn: LEAF_CN,
        subject_key: &k.leaf,
        issuer_cn: INT_CN,
        issuer_key: &k.intermediate,
        signer_key: &k.intermediate,
        is_ca: false,
        key_usage: KuChoice::Default,
        not_before: t(2020, 1, 1),
        not_after: t(2030, 1, 1),
        eku: Eku::ClientAuth,
        serial: 30,
    });

    let trusted = [root];
    let issuers = [intermediate];
    let crls = empty_crls();
    let options = ValidationOptions::default();
    let now = now_valid();

    let ctx = ChainValidationContext {
        trusted_certs: &trusted,
        issuer_certs: &issuers,
        crls: &crls,
        ocsp_responses: &[],
        security_policy: SecurityPolicy::Basic256Sha256,
        purpose: CertificatePurpose::ClientApplication,
        options: &options,
        now: &now,
    };
    validate_certificate_chain(&client_leaf, &ctx)
        .expect("a valid client-auth leaf must validate under the ClientApplication purpose");
}

#[test]
fn malformed_certificate_der_is_rejected_without_panic() {
    // Structure step (FR-001): truncated / malformed DER must be rejected at parse time and
    // must never panic.
    let leaf = leaf_via_intermediate(t(2030, 1, 1));
    let mut der = leaf.to_der().expect("leaf der");
    der.truncate(der.len() / 2);
    assert!(
        X509::from_der(&der).is_err(),
        "a truncated certificate must fail to parse, not panic"
    );

    // A trailing-garbage CRL must also fail to parse without panicking.
    assert!(CertificateList::from_der(&[0x30, 0x03, 0x02, 0x01, 0x01, 0xff]).is_err());
}

// --- store-level wiring tests (T008) -------------------------------------------------------
//
// These drive the public `CertificateStore::validate_or_reject_application_instance_cert`, which
// the server (client-cert) and client (server-cert) call. They use the real wall-clock validity
// check inside the store, so all non-expired fixtures use 2020..2035 windows that include now.

fn write_cert_to(dir: &Path, cert: &X509) {
    let mut path = dir.to_path_buf();
    path.push(CertificateStore::cert_file_name(cert));
    std::fs::write(path, cert.to_der().expect("cert der")).expect("write fixture cert");
}

fn store_with(trusted: &[&X509], issuers: &[&X509]) -> (TempDir, CertificateStore) {
    let tmp = tempfile::Builder::new()
        .prefix("pki-chain")
        .tempdir()
        .expect("temp pki dir");
    let store = CertificateStore::new(tmp.path());
    store.ensure_pki_path().expect("ensure pki path");
    for cert in trusted {
        write_cert_to(&store.trusted_certs_dir(), cert);
    }
    for cert in issuers {
        write_cert_to(&store.issuer_certs_dir(), cert);
    }
    (tmp, store)
}

#[test]
fn store_accepts_self_signed_leaf_in_trusted() {
    // Backward compatibility: existing self-signed-in-trusted/ deployments keep working.
    let k = keys();
    let leaf = issue(&CertSpec {
        subject_cn: LEAF_CN,
        subject_key: &k.leaf,
        issuer_cn: LEAF_CN,
        issuer_key: &k.leaf,
        signer_key: &k.leaf,
        is_ca: false,
        key_usage: KuChoice::Default,
        not_before: t(2020, 1, 1),
        not_after: t(2035, 1, 1),
        eku: Eku::Both,
        serial: 100,
    });
    let (_tmp, store) = store_with(&[&leaf], &[]);
    store
        .validate_or_reject_application_instance_cert(
            &leaf,
            SecurityPolicy::Basic256Sha256,
            None,
            None,
        )
        .expect("a self-signed leaf in trusted/ must still validate through the store");
}

#[test]
fn store_accepts_ca_signed_leaf_chaining_to_trusted_root() {
    // The new capability: leaf is NOT in trusted/, but chains via issuer/ to a trusted root.
    let k = keys();
    let root = root_ca();
    let intermediate = issue(&CertSpec {
        subject_cn: INT_CN,
        subject_key: &k.intermediate,
        issuer_cn: ROOT_CN,
        issuer_key: &k.root,
        signer_key: &k.root,
        is_ca: true,
        key_usage: KuChoice::Default,
        not_before: t(2020, 1, 1),
        not_after: t(2034, 1, 1),
        eku: Eku::None,
        serial: 101,
    });
    let leaf = issue(&CertSpec {
        subject_cn: LEAF_CN,
        subject_key: &k.leaf,
        issuer_cn: INT_CN,
        issuer_key: &k.intermediate,
        signer_key: &k.intermediate,
        is_ca: false,
        key_usage: KuChoice::Default,
        not_before: t(2020, 1, 1),
        not_after: t(2035, 1, 1),
        eku: Eku::Both,
        serial: 102,
    });
    let (_tmp, store) = store_with(&[&root], &[&intermediate]);
    store
        .validate_or_reject_application_instance_cert(
            &leaf,
            SecurityPolicy::Basic256Sha256,
            None,
            None,
        )
        .expect("a CA-signed leaf chaining through issuer/ to a trusted root must validate");
}

#[test]
fn store_rejects_ca_signed_leaf_with_missing_intermediate() {
    let k = keys();
    let root = root_ca();
    let leaf = issue(&CertSpec {
        subject_cn: LEAF_CN,
        subject_key: &k.leaf,
        issuer_cn: INT_CN,
        issuer_key: &k.intermediate,
        signer_key: &k.intermediate,
        is_ca: false,
        key_usage: KuChoice::Default,
        not_before: t(2020, 1, 1),
        not_after: t(2035, 1, 1),
        eku: Eku::ServerAuth,
        serial: 103,
    });
    // intermediate deliberately absent from issuer/
    let (_tmp, store) = store_with(&[&root], &[]);
    let err = store
        .validate_or_reject_application_instance_cert(
            &leaf,
            SecurityPolicy::Basic256Sha256,
            None,
            None,
        )
        .expect_err("a leaf whose intermediate is missing must be rejected");
    assert_eq!(err.status(), StatusCode::BadCertificateChainIncomplete);
}

#[test]
fn store_rejects_untrusted_leaf_and_files_it_under_rejected() {
    let k = keys();
    let leaf = issue(&CertSpec {
        subject_cn: LEAF_CN,
        subject_key: &k.leaf,
        issuer_cn: LEAF_CN,
        issuer_key: &k.leaf,
        signer_key: &k.leaf,
        is_ca: false,
        key_usage: KuChoice::Default,
        not_before: t(2020, 1, 1),
        not_after: t(2035, 1, 1),
        eku: Eku::ServerAuth,
        serial: 104,
    });
    // Nothing trusted.
    let (_tmp, store) = store_with(&[], &[]);
    let err = store
        .validate_or_reject_application_instance_cert(
            &leaf,
            SecurityPolicy::Basic256Sha256,
            None,
            None,
        )
        .expect_err("an untrusted self-signed leaf must be rejected");
    assert_eq!(err.status(), StatusCode::BadCertificateUntrusted);

    // It should have been filed in rejected/ so an administrator can inspect/move it.
    let mut rejected = store.rejected_certs_dir();
    rejected.push(CertificateStore::cert_file_name(&leaf));
    assert!(
        rejected.exists(),
        "the rejected leaf must be written to the rejected/ directory"
    );
}

#[test]
fn store_rejects_expired_ca_signed_leaf() {
    let k = keys();
    let root = root_ca();
    let intermediate = issue(&CertSpec {
        subject_cn: INT_CN,
        subject_key: &k.intermediate,
        issuer_cn: ROOT_CN,
        issuer_key: &k.root,
        signer_key: &k.root,
        is_ca: true,
        key_usage: KuChoice::Default,
        not_before: t(2020, 1, 1),
        not_after: t(2034, 1, 1),
        eku: Eku::None,
        serial: 105,
    });
    let expired_leaf = issue(&CertSpec {
        subject_cn: LEAF_CN,
        subject_key: &k.leaf,
        issuer_cn: INT_CN,
        issuer_key: &k.intermediate,
        signer_key: &k.intermediate,
        is_ca: false,
        key_usage: KuChoice::Default,
        not_before: t(2020, 1, 1),
        not_after: t(2021, 1, 1), // expired before now
        eku: Eku::ServerAuth,
        serial: 106,
    });
    let (_tmp, store) = store_with(&[&root], &[&intermediate]);
    let err = store
        .validate_or_reject_application_instance_cert(
            &expired_leaf,
            SecurityPolicy::Basic256Sha256,
            None,
            None,
        )
        .expect_err("an expired CA-signed leaf must be rejected");
    assert_eq!(err.status(), StatusCode::BadCertificateTimeInvalid);
}

// --- US2 tests: certificate usage (KeyUsage / ExtendedKeyUsage) ----------------------------

#[test]
fn leaf_missing_digital_signature_is_use_not_allowed() {
    // An application leaf whose KeyUsage lacks digitalSignature cannot authenticate the channel.
    let k = keys();
    let root = root_ca();
    let intermediate = intermediate_ca();
    let leaf = issue(&CertSpec {
        subject_cn: LEAF_CN,
        subject_key: &k.leaf,
        issuer_cn: INT_CN,
        issuer_key: &k.intermediate,
        signer_key: &k.intermediate,
        is_ca: false,
        not_before: t(2020, 1, 1),
        not_after: t(2030, 1, 1),
        eku: Eku::ServerAuth,
        key_usage: KuChoice::Custom(KeyUsage(
            KeyUsages::KeyEncipherment | KeyUsages::DataEncipherment,
        )),
        serial: 200,
    });
    let trusted = [root];
    let issuers = [intermediate];
    let crls = empty_crls();
    let options = ValidationOptions::default();
    let now = now_valid();
    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    let err = validate_certificate_chain(&leaf, &ctx)
        .expect_err("a leaf without digitalSignature KeyUsage must be rejected");
    assert_eq!(err.status(), StatusCode::BadCertificateUseNotAllowed);
}

#[test]
fn leaf_with_wrong_eku_is_use_not_allowed() {
    // A client-auth-only leaf presented for server-application use must be rejected.
    let k = keys();
    let root = root_ca();
    let intermediate = intermediate_ca();
    let leaf = issue(&CertSpec {
        subject_cn: LEAF_CN,
        subject_key: &k.leaf,
        issuer_cn: INT_CN,
        issuer_key: &k.intermediate,
        signer_key: &k.intermediate,
        is_ca: false,
        not_before: t(2020, 1, 1),
        not_after: t(2030, 1, 1),
        eku: Eku::ClientAuth,
        key_usage: KuChoice::Default,
        serial: 201,
    });
    let trusted = [root];
    let issuers = [intermediate];
    let crls = empty_crls();
    let options = ValidationOptions::default();
    let now = now_valid();
    // server_ctx validates with CertificatePurpose::ServerApplication.
    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    let err = validate_certificate_chain(&leaf, &ctx)
        .expect_err("a client-auth EKU leaf must be rejected for server-application use");
    assert_eq!(err.status(), StatusCode::BadCertificateUseNotAllowed);
}

#[test]
fn non_ca_issuer_is_issuer_use_not_allowed() {
    // An intermediate that is not marked as a CA cannot issue certificates.
    let k = keys();
    let root = root_ca();
    let non_ca_intermediate = issue(&CertSpec {
        subject_cn: INT_CN,
        subject_key: &k.intermediate,
        issuer_cn: ROOT_CN,
        issuer_key: &k.root,
        signer_key: &k.root,
        is_ca: false, // not a CA
        not_before: t(2020, 1, 1),
        not_after: t(2034, 1, 1),
        eku: Eku::None,
        key_usage: KuChoice::Default,
        serial: 202,
    });
    let leaf = leaf_via_intermediate(t(2030, 1, 1));
    let trusted = [root];
    let issuers = [non_ca_intermediate];
    let crls = empty_crls();
    let options = ValidationOptions::default();
    let now = now_valid();
    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    let err = validate_certificate_chain(&leaf, &ctx)
        .expect_err("a non-CA issuer in the chain must be rejected");
    assert_eq!(err.status(), StatusCode::BadCertificateIssuerUseNotAllowed);
}

#[test]
fn ca_without_keycertsign_is_issuer_use_not_allowed() {
    // A CA whose KeyUsage lacks keyCertSign cannot sign certificates.
    let k = keys();
    let root = root_ca();
    let weak_intermediate = issue(&CertSpec {
        subject_cn: INT_CN,
        subject_key: &k.intermediate,
        issuer_cn: ROOT_CN,
        issuer_key: &k.root,
        signer_key: &k.root,
        is_ca: true,
        not_before: t(2020, 1, 1),
        not_after: t(2034, 1, 1),
        eku: Eku::None,
        key_usage: KuChoice::Custom(KeyUsage(KeyUsages::DigitalSignature | KeyUsages::CRLSign)), // CA flag set but no keyCertSign
        serial: 203,
    });
    let leaf = leaf_via_intermediate(t(2030, 1, 1));
    let trusted = [root];
    let issuers = [weak_intermediate];
    let crls = empty_crls();
    let options = ValidationOptions::default();
    let now = now_valid();
    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    let err = validate_certificate_chain(&leaf, &ctx)
        .expect_err("a CA without keyCertSign must be rejected");
    assert_eq!(err.status(), StatusCode::BadCertificateIssuerUseNotAllowed);
}

#[test]
fn leaf_without_key_usage_extension_is_accepted() {
    // KeyUsage is optional; when absent the leaf is leniently accepted (only its presence is
    // constrained). EKU is likewise absent here.
    let k = keys();
    let root = root_ca();
    let intermediate = intermediate_ca();
    let leaf = issue(&CertSpec {
        subject_cn: LEAF_CN,
        subject_key: &k.leaf,
        issuer_cn: INT_CN,
        issuer_key: &k.intermediate,
        signer_key: &k.intermediate,
        is_ca: false,
        not_before: t(2020, 1, 1),
        not_after: t(2030, 1, 1),
        eku: Eku::None,
        key_usage: KuChoice::Omit,
        serial: 204,
    });
    let trusted = [root];
    let issuers = [intermediate];
    let crls = empty_crls();
    let options = ValidationOptions::default();
    let now = now_valid();
    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    validate_certificate_chain(&leaf, &ctx)
        .expect("a leaf without KeyUsage/EKU extensions is leniently accepted");
}

// --- US3 helpers + tests: CRL revocation ---------------------------------------------------

/// Build a CA-signed CRL listing `revoked_serials`, signed by `issuer_key` (sha256WithRSA).
fn make_crl(
    issuer_cn: &str,
    issuer_key: &PrivateKey,
    revoked_serials: &[u32],
    this_update: DateTime<Utc>,
    next_update: DateTime<Utc>,
) -> CertificateList {
    let issuer = Name::from_str(&format!("CN={issuer_cn}")).expect("crl issuer name");
    let algorithm = AlgorithmIdentifierOwned {
        oid: SHA_256_WITH_RSA_ENCRYPTION,
        parameters: Some(Any::from(Null)),
    };
    let revoked_certificates = if revoked_serials.is_empty() {
        None
    } else {
        Some(
            revoked_serials
                .iter()
                .map(|s| RevokedCert {
                    serial_number: SerialNumber::from(*s),
                    revocation_date: to_time(this_update),
                    crl_entry_extensions: None,
                })
                .collect(),
        )
    };
    let tbs = TbsCertList {
        version: Version::V2,
        signature: algorithm.clone(),
        issuer,
        this_update: to_time(this_update),
        next_update: Some(to_time(next_update)),
        revoked_certificates,
        crl_extensions: None,
    };
    let tbs_der = tbs.to_der().expect("crl tbs der");
    let signing_key = SigningKey::<Sha256>::new(
        issuer_key
            .rsa_key_for_x509()
            .expect("crl signer key")
            .clone(),
    );
    let signature: Signature = signing_key.sign(&tbs_der);
    CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: algorithm,
        signature: BitString::from_bytes(&signature.to_vec()).expect("crl signature bits"),
    }
}

/// A leaf signed directly by the root (2-level chain) with the given serial.
fn leaf_signed_by_root(serial: u32, not_after: DateTime<Utc>) -> X509 {
    let k = keys();
    issue(&CertSpec {
        subject_cn: LEAF_CN,
        subject_key: &k.leaf,
        issuer_cn: ROOT_CN,
        issuer_key: &k.root,
        signer_key: &k.root,
        is_ca: false,
        not_before: t(2020, 1, 1),
        not_after,
        eku: Eku::Both,
        key_usage: KuChoice::Default,
        serial,
    })
}

#[test]
fn revoked_leaf_is_rejected() {
    let k = keys();
    let root = root_ca();
    let leaf = leaf_signed_by_root(300, t(2030, 1, 1));
    // CRL signed by the root (the leaf's issuer) listing the leaf's serial.
    let crl = make_crl(ROOT_CN, &k.root, &[300], t(2024, 1, 1), t(2030, 1, 1));

    let trusted = [root];
    let issuers: [X509; 0] = [];
    let crls = [crl];
    let options = ValidationOptions::default(); // Lenient: a present CRL is checked.
    let now = now_valid();
    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    let err = validate_certificate_chain(&leaf, &ctx)
        .expect_err("a leaf whose serial is on its CA's CRL must be rejected");
    assert_eq!(err.status(), StatusCode::BadCertificateRevoked);
}

#[test]
fn revoked_intermediate_is_issuer_revoked() {
    let k = keys();
    let root = root_ca();
    let intermediate = intermediate_ca(); // serial 2
    let leaf = leaf_via_intermediate(t(2030, 1, 1));
    // CRL signed by the root listing the intermediate's serial (2).
    let crl = make_crl(ROOT_CN, &k.root, &[2], t(2024, 1, 1), t(2030, 1, 1));

    let trusted = [root];
    let issuers = [intermediate];
    let crls = [crl];
    let options = ValidationOptions::default();
    let now = now_valid();
    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    let err = validate_certificate_chain(&leaf, &ctx)
        .expect_err("a revoked intermediate CA must be rejected");
    assert_eq!(err.status(), StatusCode::BadCertificateIssuerRevoked);
}

#[test]
fn required_revocation_without_crl_is_unknown() {
    let root = root_ca();
    let leaf = leaf_signed_by_root(301, t(2030, 1, 1));

    let trusted = [root];
    let issuers: [X509; 0] = [];
    let crls = empty_crls(); // none provided
    let options = ValidationOptions {
        revocation_mode: RevocationMode::Required,
        ..Default::default()
    };
    let now = now_valid();
    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    let err = validate_certificate_chain(&leaf, &ctx)
        .expect_err("required revocation with no CRL available must be RevocationUnknown");
    assert_eq!(err.status(), StatusCode::BadCertificateRevocationUnknown);
}

#[test]
fn unknown_issuer_revocation_status_returns_bad_certificate_issuer_revocation_unknown() {
    let k = keys();
    let root = root_ca();
    let intermediate = intermediate_ca();
    let leaf = leaf_via_intermediate(t(2030, 1, 1));
    let clean_leaf_issuer_crl =
        make_crl(INT_CN, &k.intermediate, &[], t(2024, 1, 1), t(2030, 1, 1));

    let trusted = [root];
    let issuers = [intermediate];
    let crls = [clean_leaf_issuer_crl];
    let options = ValidationOptions {
        revocation_mode: RevocationMode::Required,
        ..Default::default()
    };
    let now = now_valid();
    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    let err = validate_certificate_chain(&leaf, &ctx)
        .expect_err("missing issuer CRL in Required mode must report issuer revocation unknown");

    // OPC-10000-4 6.1.3: unknown issuer revocation status uses BadCertificateIssuerRevocationUnknown.
    assert_eq!(
        err.status(),
        StatusCode::BadCertificateIssuerRevocationUnknown
    );
}

#[test]
fn required_revocation_with_clean_crl_is_accepted() {
    let k = keys();
    let root = root_ca();
    let leaf = leaf_signed_by_root(302, t(2030, 1, 1));
    // A CRL from the root that does NOT list the leaf satisfies the Required mode.
    let crl = make_crl(ROOT_CN, &k.root, &[], t(2024, 1, 1), t(2030, 1, 1));

    let trusted = [root];
    let issuers: [X509; 0] = [];
    let crls = [crl];
    let options = ValidationOptions {
        revocation_mode: RevocationMode::Required,
        ..Default::default()
    };
    let now = now_valid();
    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    validate_certificate_chain(&leaf, &ctx)
        .expect("a present CRL that does not revoke the leaf satisfies Required revocation");
}

#[test]
fn disabled_revocation_ignores_revoking_crl() {
    let k = keys();
    let root = root_ca();
    let leaf = leaf_signed_by_root(303, t(2030, 1, 1));
    // Even with a CRL revoking the leaf, Disabled mode skips revocation entirely.
    let crl = make_crl(ROOT_CN, &k.root, &[303], t(2024, 1, 1), t(2030, 1, 1));

    let trusted = [root];
    let issuers: [X509; 0] = [];
    let crls = [crl];
    let options = ValidationOptions {
        revocation_mode: RevocationMode::Disabled,
        ..Default::default()
    };
    let now = now_valid();
    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    validate_certificate_chain(&leaf, &ctx).expect(
        "Disabled revocation mode must skip revocation even when a revoking CRL is present",
    );
}

#[test]
fn crl_with_forged_signature_is_not_trusted_for_revocation() {
    // A CRL claiming to be from the root but signed by an unrelated key must not cause a
    // revocation decision (its signature does not verify), so under Lenient the leaf is accepted.
    let k = keys();
    let root = root_ca();
    let leaf = leaf_signed_by_root(304, t(2030, 1, 1));
    let forged_crl = make_crl(ROOT_CN, &k.rogue, &[304], t(2024, 1, 1), t(2030, 1, 1));

    let trusted = [root];
    let issuers: [X509; 0] = [];
    let crls = [forged_crl];
    let options = ValidationOptions::default(); // Lenient
    let now = now_valid();
    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    validate_certificate_chain(&leaf, &ctx)
        .expect("a CRL with an invalid signature must be ignored, not used to revoke");
}

// --- US4 tests: security-policy check + suppression -----------------------------------------

fn suppress(steps: &[SuppressibleStep]) -> ValidationOptions {
    ValidationOptions {
        suppressed_steps: steps.iter().copied().collect(),
        ..Default::default()
    }
}

#[test]
fn leaf_key_too_short_is_policy_check_failed() {
    // A 1024-bit leaf violates Basic256Sha256's minimum asymmetric key length.
    let k = keys();
    let short_key = PrivateKey::new(1024).expect("1024-bit key");
    let root = root_ca();
    let leaf = issue(&CertSpec {
        subject_cn: LEAF_CN,
        subject_key: &short_key,
        issuer_cn: ROOT_CN,
        issuer_key: &k.root,
        signer_key: &k.root,
        is_ca: false,
        not_before: t(2020, 1, 1),
        not_after: t(2030, 1, 1),
        eku: Eku::Both,
        key_usage: KuChoice::Default,
        serial: 400,
    });
    let trusted = [root];
    let issuers: [X509; 0] = [];
    let crls = empty_crls();
    let options = ValidationOptions::default();
    let now = now_valid();
    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    let err = validate_certificate_chain(&leaf, &ctx).expect_err(
        "a leaf key length below the policy minimum must fail the security-policy check",
    );
    assert_eq!(err.status(), StatusCode::BadCertificatePolicyCheckFailed);
}

#[test]
fn suppressed_security_policy_passes_with_finding() {
    let k = keys();
    let short_key = PrivateKey::new(1024).expect("1024-bit key");
    let root = root_ca();
    let leaf = issue(&CertSpec {
        subject_cn: LEAF_CN,
        subject_key: &short_key,
        issuer_cn: ROOT_CN,
        issuer_key: &k.root,
        signer_key: &k.root,
        is_ca: false,
        not_before: t(2020, 1, 1),
        not_after: t(2030, 1, 1),
        eku: Eku::Both,
        key_usage: KuChoice::Default,
        serial: 401,
    });
    let trusted = [root];
    let issuers: [X509; 0] = [];
    let crls = empty_crls();
    let options = suppress(&[SuppressibleStep::SecurityPolicy]);
    let now = now_valid();
    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    let findings = validate_certificate_chain(&leaf, &ctx)
        .expect("suppressing the security-policy step lets validation pass");
    assert!(
        findings
            .iter()
            .any(|f| f.step == SuppressibleStep::SecurityPolicy
                && f.status == StatusCode::BadCertificatePolicyCheckFailed),
        "a suppressed security-policy failure must be recorded as an audit finding: {findings:?}"
    );
}

#[test]
fn suppressed_validity_passes_with_finding() {
    let root = root_ca();
    let intermediate = intermediate_ca();
    let expired_leaf = leaf_via_intermediate(t(2021, 1, 1)); // expired before now
    let trusted = [root];
    let issuers = [intermediate];
    let crls = empty_crls();
    let options = suppress(&[SuppressibleStep::Validity]);
    let now = now_valid();
    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    let findings = validate_certificate_chain(&expired_leaf, &ctx)
        .expect("suppressing validity lets an expired leaf pass");
    assert!(
        findings.iter().any(|f| f.step == SuppressibleStep::Validity
            && f.status == StatusCode::BadCertificateTimeInvalid),
        "a suppressed validity failure must be recorded as an audit finding: {findings:?}"
    );
}

#[test]
fn critical_untrusted_is_not_suppressible() {
    // Untrusted is a critical step: even suppressing every suppressible step cannot bypass it.
    let k = keys();
    let rogue_leaf = issue(&CertSpec {
        subject_cn: LEAF_CN,
        subject_key: &k.leaf,
        issuer_cn: LEAF_CN,
        issuer_key: &k.leaf,
        signer_key: &k.leaf,
        is_ca: false,
        not_before: t(2020, 1, 1),
        not_after: t(2030, 1, 1),
        eku: Eku::Both,
        key_usage: KuChoice::Default,
        serial: 402,
    });
    let trusted = [root_ca()]; // the rogue leaf is NOT trusted
    let issuers: [X509; 0] = [];
    let crls = empty_crls();
    let options = suppress(&[
        SuppressibleStep::SecurityPolicy,
        SuppressibleStep::Validity,
        SuppressibleStep::HostName,
        SuppressibleStep::CertificateUsage,
        SuppressibleStep::FindRevocationList,
    ]);
    let now = now_valid();
    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    let err = validate_certificate_chain(&rogue_leaf, &ctx)
        .expect_err("a critical untrusted failure must reject regardless of suppression");
    assert_eq!(err.status(), StatusCode::BadCertificateUntrusted);
}

#[test]
fn trust_list_check_precedes_validity_check() {
    // Ordering/precedence (SC-001 "in order"): an untrusted AND expired leaf must report the
    // earlier Table-100 step (trust-list / Untrusted), not the later validity (TimeInvalid).
    let k = keys();
    let rogue_expired_leaf = issue(&CertSpec {
        subject_cn: LEAF_CN,
        subject_key: &k.leaf,
        issuer_cn: LEAF_CN,
        issuer_key: &k.leaf,
        signer_key: &k.leaf,
        is_ca: false,
        not_before: t(2020, 1, 1),
        not_after: t(2021, 1, 1), // also expired
        eku: Eku::Both,
        key_usage: KuChoice::Default,
        serial: 403,
    });
    let trusted = [root_ca()];
    let issuers: [X509; 0] = [];
    let crls = empty_crls();
    let options = ValidationOptions::default();
    let now = now_valid();
    let ctx = server_ctx(&trusted, &issuers, &crls, &options, &now);
    let err = validate_certificate_chain(&rogue_expired_leaf, &ctx)
        .expect_err("an untrusted, expired leaf must be rejected");
    assert_eq!(
        err.status(),
        StatusCode::BadCertificateUntrusted,
        "trust-list check must take precedence over the later validity check"
    );
}

// --- US5 tests: configurable validation policy (store wiring) ------------------------------

#[test]
fn store_default_options_are_chain_on_lenient() {
    // The store's default validation policy is the safe, backward-compatible one.
    let options = ValidationOptions::default();
    assert!(options.validate_chain);
    assert_eq!(options.revocation_mode, RevocationMode::Lenient);
    assert!(options.suppressed_steps.is_empty());
}

#[test]
fn store_with_required_revocation_rejects_cert_without_crl() {
    // Configuring Required revocation through the store changes enforcement: a CA-signed leaf
    // with no CRL available is rejected as revocation-unknown.
    let root = root_ca();
    let leaf = leaf_signed_by_root(500, t(2030, 1, 1));
    let (_tmp, mut store) = store_with(&[&root], &[]);
    store.set_validation_options(ValidationOptions {
        revocation_mode: RevocationMode::Required,
        ..Default::default()
    });
    let err = store
        .validate_or_reject_application_instance_cert(
            &leaf,
            SecurityPolicy::Basic256Sha256,
            None,
            None,
        )
        .expect_err("Required revocation with no CRL must reject through the store");
    assert_eq!(err.status(), StatusCode::BadCertificateRevocationUnknown);
}

#[test]
fn store_lenient_default_accepts_ca_signed_leaf_without_crl() {
    // The default (lenient) policy keeps a CA-signed leaf valid even without any CRL configured.
    let root = root_ca();
    let leaf = leaf_signed_by_root(501, t(2030, 1, 1));
    let (_tmp, store) = store_with(&[&root], &[]);
    store
        .validate_or_reject_application_instance_cert(
            &leaf,
            SecurityPolicy::Basic256Sha256,
            None,
            None,
        )
        .expect("the default lenient policy accepts a CA-signed leaf with no CRL present");
}

// --- OCSP revocation (supplied/stapled responses) -----------------------------------------------

/// Build a DER OCSPResponse signed by `issuer_key`, asserting `revoked`/good for `serial`. Mirrors
/// `make_crl`: manual assembly + SHA256-RSA signing with the issuer key (no x509-ocsp builder).
fn make_ocsp_response(
    issuer_cn: &str,
    issuer_key: &PrivateKey,
    serial: u32,
    revoked: bool,
    this_update: DateTime<Utc>,
    next_update: DateTime<Utc>,
) -> Vec<u8> {
    use x509_ocsp::{
        BasicOcspResponse, CertId, CertStatus, OcspGeneralizedTime, OcspResponse, ResponderId,
        ResponseData, RevokedInfo, SingleResponse,
    };

    let issuer = Name::from_str(&format!("CN={issuer_cn}")).expect("ocsp issuer name");
    // The hash algorithm / issuer hashes in CertId are not used by our matcher (we require an
    // issuer-signed response + matching serial), so any well-formed values suffice.
    let sha1_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
    let cert_id = CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: sha1_oid,
            parameters: Some(Any::from(Null)),
        },
        issuer_name_hash: OctetString::new(vec![0u8; 20]).expect("name hash"),
        issuer_key_hash: OctetString::new(vec![0u8; 20]).expect("key hash"),
        serial_number: SerialNumber::from(serial),
    };
    let cert_status = if revoked {
        CertStatus::revoked(RevokedInfo {
            revocation_time: OcspGeneralizedTime::from(to_time(this_update)),
            revocation_reason: None,
        })
    } else {
        CertStatus::good()
    };
    let single = SingleResponse {
        cert_id,
        cert_status,
        this_update: OcspGeneralizedTime::from(to_time(this_update)),
        next_update: Some(OcspGeneralizedTime::from(to_time(next_update))),
        single_extensions: None,
    };
    let tbs = ResponseData {
        version: Default::default(),
        responder_id: ResponderId::ByName(issuer),
        produced_at: OcspGeneralizedTime::from(to_time(this_update)),
        responses: vec![single],
        response_extensions: None,
    };
    let tbs_der = tbs.to_der().expect("ocsp tbs der");
    let signing_key = SigningKey::<Sha256>::new(
        issuer_key
            .rsa_key_for_x509()
            .expect("ocsp signer key")
            .clone(),
    );
    let signature: Signature = signing_key.sign(&tbs_der);
    let basic = BasicOcspResponse {
        tbs_response_data: tbs,
        signature_algorithm: AlgorithmIdentifierOwned {
            oid: SHA_256_WITH_RSA_ENCRYPTION,
            parameters: Some(Any::from(Null)),
        },
        signature: BitString::from_bytes(&signature.to_vec()).expect("ocsp signature bits"),
        certs: None,
    };
    OcspResponse::successful(basic)
        .expect("ocsp response")
        .to_der()
        .expect("ocsp response der")
}

#[test]
fn ocsp_good_response_satisfies_required_mode() {
    // Part 4 §6.1.3: a valid (issuer-signed, fresh) "good" OCSP response is a definitive revocation
    // source — it satisfies Required mode even with no CRL present.
    let k = keys();
    let root = root_ca();
    let leaf = leaf_signed_by_root(700, t(2030, 1, 1));
    let ocsp = make_ocsp_response(ROOT_CN, &k.root, 700, false, t(2024, 1, 1), t(2030, 1, 1));

    let trusted = [root];
    let issuers: [X509; 0] = [];
    let crls = empty_crls();
    let ocsp_responses = [ocsp];
    let options = ValidationOptions {
        revocation_mode: RevocationMode::Required,
        ..Default::default()
    };
    let now = now_valid();
    let ctx = server_ctx_ocsp(&trusted, &issuers, &crls, &ocsp_responses, &options, &now);
    validate_certificate_chain(&leaf, &ctx)
        .expect("a good OCSP response should satisfy Required-mode revocation");
}

#[test]
fn ocsp_revoked_response_rejects_leaf() {
    // A valid OCSP response marking the leaf's serial revoked must reject it.
    let k = keys();
    let root = root_ca();
    let leaf = leaf_signed_by_root(701, t(2030, 1, 1));
    let ocsp = make_ocsp_response(ROOT_CN, &k.root, 701, true, t(2024, 1, 1), t(2030, 1, 1));

    let trusted = [root];
    let issuers: [X509; 0] = [];
    let crls = empty_crls();
    let ocsp_responses = [ocsp];
    let options = ValidationOptions::default();
    let now = now_valid();
    let ctx = server_ctx_ocsp(&trusted, &issuers, &crls, &ocsp_responses, &options, &now);
    let err = validate_certificate_chain(&leaf, &ctx)
        .expect_err("a leaf revoked by a valid OCSP response must be rejected");
    assert_eq!(err.status(), StatusCode::BadCertificateRevoked);
}

#[test]
fn ocsp_response_signed_by_non_issuer_is_ignored() {
    // An OCSP response NOT signed by the issuer (here the leaf key) must be ignored, not honoured.
    // With no CRL in Required mode, that leaves revocation unknown — proving the forged response did
    // not take effect (otherwise the leaf would be wrongly "revoked").
    let k = keys();
    let root = root_ca();
    let leaf = leaf_signed_by_root(702, t(2030, 1, 1));
    // Signed with the leaf key, which is not the issuer (root).
    let forged = make_ocsp_response(ROOT_CN, &k.leaf, 702, true, t(2024, 1, 1), t(2030, 1, 1));

    let trusted = [root];
    let issuers: [X509; 0] = [];
    let crls = empty_crls();
    let ocsp_responses = [forged];
    let options = ValidationOptions {
        revocation_mode: RevocationMode::Required,
        ..Default::default()
    };
    let now = now_valid();
    let ctx = server_ctx_ocsp(&trusted, &issuers, &crls, &ocsp_responses, &options, &now);
    let err = validate_certificate_chain(&leaf, &ctx)
        .expect_err("a non-issuer-signed OCSP response must not be honoured");
    assert_eq!(err.status(), StatusCode::BadCertificateRevocationUnknown);
}
