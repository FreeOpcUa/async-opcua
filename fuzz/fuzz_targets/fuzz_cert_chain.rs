#![cfg_attr(feature = "nightly", no_main)]

#[cfg(not(feature = "nightly"))]
fn main() {
    panic!("Fuzzing requires the nightly feature to be enabled.");
}

// Fuzz the attacker-controlled certificate-validation entry points (feature 013, T023).
// A peer's ApplicationInstanceCertificate arrives on the wire and is parsed + validated through
// the Part 4 §6.1.3 (Table 100) pipeline. Parsing and the whole chain/CRL/usage/revocation
// validation MUST NEVER panic on malformed input — only return an error. Also exercises the CRL
// decoder on the same bytes.
#[cfg(feature = "nightly")]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    use chrono::Utc;
    use opcua::crypto::{
        validate_certificate_chain, CertificatePurpose, ChainValidationContext, SecurityPolicy,
        ValidationOptions, X509,
    };
    use x509_cert::crl::CertificateList;
    use x509_cert::der::Decode;

    // The same fuzzed bytes are always offered to the CRL decoder (admin-provisioned, but still
    // must not panic); collect a 0-or-1-element CRL list to feed into validation.
    let crls: Vec<CertificateList> = CertificateList::from_der(data).into_iter().collect();

    // Parse the bytes as a certificate; parsing must never panic.
    let Ok(cert) = X509::from_der(data) else {
        return;
    };

    let options = ValidationOptions::default();
    let now = Utc::now();
    // Run the full pipeline with the parsed (attacker-shaped) certificate as the leaf, also
    // offering it as a trust anchor and as an issuer so chain-build / signature / trust-list /
    // validity / usage / revocation are all exercised. Bounded depth + cycle detection must keep
    // this terminating and panic-free.
    let trusted = [cert.clone()];
    let issuers = [cert.clone()];
    let ctx = ChainValidationContext {
        trusted_certs: &trusted,
        issuer_certs: &issuers,
        crls: &crls,
        ocsp_responses: &[],
        security_policy: SecurityPolicy::Basic256Sha256,
        purpose: CertificatePurpose::ServerApplication,
        options: &options,
        now: &now,
    };
    let _ = validate_certificate_chain(&cert, &ctx);
});
