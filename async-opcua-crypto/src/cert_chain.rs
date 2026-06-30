use std::collections::HashSet;

use chrono::{DateTime, Utc};
use const_oid::db::rfc5280::{ANY_EXTENDED_KEY_USAGE, ID_KP_CLIENT_AUTH, ID_KP_SERVER_AUTH};
#[cfg(feature = "ecc")]
use const_oid::db::rfc5912::{ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384};
use const_oid::db::rfc5912::{
    ID_RSASSA_PSS, SHA_1_WITH_RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION,
};
use const_oid::db::rfc6960::ID_PKIX_OCSP_BASIC;
use opcua_types::{status_code::StatusCode, Error};
use x509_cert::crl::{CertificateList, RevokedCert};
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::KeyUsages;
use x509_ocsp::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus};

use crate::{PublicKey, SecurityPolicy, X509};

const MAX_CHAIN_LENGTH: usize = 10;

/// The leaf application-certificate purpose being validated.
///
/// This drives the ExtendedKeyUsage check in the Table 100 validation pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificatePurpose {
    /// The leaf is being validated for server application use.
    ServerApplication,
    /// The leaf is being validated for client application use.
    ClientApplication,
}

/// Controls how CRL availability affects certificate-chain validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RevocationMode {
    /// Never fail validation because a CRL is missing.
    Disabled,
    /// Check revocation when a CRL is present, but do not require one.
    #[default]
    Lenient,
    /// Treat a missing CRL for a CA as a validation error.
    Required,
}

/// Non-critical Table 100 validation steps an administrator may suppress.
///
/// Critical steps are intentionally not represented here, so they can never be
/// suppressed through [`ValidationOptions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SuppressibleStep {
    /// Security-policy key and algorithm compatibility.
    SecurityPolicy,
    /// Per-certificate validity period checks.
    Validity,
    /// Host-name validation.
    HostName,
    /// Certificate usage and ExtendedKeyUsage validation.
    CertificateUsage,
    /// Revocation-list discovery for issuers.
    FindRevocationList,
}

/// Options for running the OPC UA Part 4 certificate-chain validation pipeline.
#[derive(Debug, Clone)]
pub struct ValidationOptions {
    /// Master switch for the full Part 4 §6.1.3 chain pipeline.
    ///
    /// When false, the caller falls back to legacy trust-list-only behavior.
    pub validate_chain: bool,
    /// Controls how CRL availability affects revocation checking.
    pub revocation_mode: RevocationMode,
    /// Suppressible steps that fail soft and are audited instead of rejected.
    pub suppressed_steps: HashSet<SuppressibleStep>,
}

impl ValidationOptions {
    /// Returns whether a suppressible validation step should fail soft.
    pub fn is_suppressed(&self, step: SuppressibleStep) -> bool {
        self.suppressed_steps.contains(&step)
    }
}

impl Default for ValidationOptions {
    fn default() -> Self {
        Self {
            validate_chain: true,
            revocation_mode: RevocationMode::Lenient,
            suppressed_steps: HashSet::new(),
        }
    }
}

/// A suppressed non-critical validation failure the caller should audit.
#[derive(Debug, Clone)]
pub struct SuppressedFinding {
    /// The validation step that produced the suppressed finding.
    pub step: SuppressibleStep,
    /// The status code that would have been returned if the step were not suppressed.
    pub status: StatusCode,
    /// Human-readable context for audit logging.
    pub message: String,
}

/// Inputs for one run of the Part 4 §6.1.3 certificate-chain validation pipeline.
#[derive(Debug, Clone, Copy)]
pub struct ChainValidationContext<'a> {
    /// Administrator-trusted certificates (the trust anchor): leaf or CA.
    pub trusted_certs: &'a [X509],
    /// CA certificates available for chain building but not directly trusted.
    pub issuer_certs: &'a [X509],
    /// CRLs loaded from the trusted/issuer CRL stores.
    pub crls: &'a [CertificateList],
    /// Stapled/supplied OCSP responses (DER-encoded OCSPResponse). Checked alongside CRLs: a
    /// Successful basic response signed by the issuer CA that covers a certificate's serial yields a
    /// definitive good/revoked verdict. Live AIA fetch is not performed (so the common source is an
    /// out-of-band/stapled response); an empty slice falls back to CRL-only revocation.
    pub ocsp_responses: &'a [Vec<u8>],
    /// The negotiated security policy (drives the Security-Policy Check).
    pub security_policy: SecurityPolicy,
    /// The use the leaf certificate is being validated for.
    pub purpose: CertificatePurpose,
    /// The validation options (enforcement, revocation mode, suppression set).
    pub options: &'a ValidationOptions,
    /// The reference time for validity-period checks.
    pub now: &'a DateTime<Utc>,
}

/// Runs the OPC UA Part 4 §6.1.3 (Table 100) certificate validation pipeline for `cert`:
/// build the chain to a trusted anchor over the certificates in `context`, verify each signature,
/// the security-policy key/algorithm, per-certificate validity, certificate usage, and CRL
/// revocation, in order, halting on the first non-suppressed failure (whose status code is returned
/// as the `Err`). On success returns the list of suppressed non-critical findings the caller should
/// emit as audit events. Host-name and application-URI checks remain with the caller.
pub fn validate_certificate_chain<'a>(
    cert: &'a X509,
    context: &'a ChainValidationContext<'a>,
) -> Result<Vec<SuppressedFinding>, Error> {
    if !context.options.validate_chain {
        return Ok(Vec::new());
    }

    let chain = build_chain(cert, context)?;

    verify_chain_signatures(&chain)?;

    let mut findings = Vec::new();
    validate_chain_security_policy(&chain, context, &mut findings)?;

    if !chain_contains_trusted_cert(&chain, context.trusted_certs)? {
        return Err(validation_error(
            StatusCode::BadCertificateUntrusted,
            "certificate chain does not contain a trusted certificate",
        ));
    }

    findings.extend(validate_chain_validity(&chain, context)?);
    validate_certificate_usage(&chain, context, &mut findings)?;
    validate_chain_revocation(&chain, context, &mut findings)?;

    Ok(findings)
}

fn build_chain<'a>(
    cert: &'a X509,
    context: &'a ChainValidationContext<'a>,
) -> Result<Vec<&'a X509>, Error> {
    let mut chain = Vec::with_capacity(MAX_CHAIN_LENGTH);
    let mut seen_der = HashSet::new();
    let mut current = cert;

    loop {
        if chain.len() >= MAX_CHAIN_LENGTH {
            return Err(chain_incomplete_error(
                "certificate chain exceeds maximum validation depth",
            ));
        }

        let current_der = cert_der(
            current,
            StatusCode::BadCertificateChainIncomplete,
            "failed to encode certificate while building chain",
        )?;
        if !seen_der.insert(current_der.clone()) {
            return Err(chain_incomplete_error(
                "certificate chain contains a certificate cycle",
            ));
        }

        chain.push(current);

        if current.is_self_signed()
            || der_in_list(
                &current_der,
                context.trusted_certs,
                StatusCode::BadCertificateChainIncomplete,
                "failed to encode trusted certificate while building chain",
            )?
        {
            return Ok(chain);
        }

        let Some(issuer) = find_issuer(current, context) else {
            return Err(chain_incomplete_error(
                "certificate issuer was not found in issuer or trusted certificates",
            ));
        };
        current = issuer;
    }
}

fn find_issuer<'a>(current: &X509, context: &'a ChainValidationContext<'a>) -> Option<&'a X509> {
    find_issuer_in(current, context.issuer_certs)
        .or_else(|| find_issuer_in(current, context.trusted_certs))
}

fn find_issuer_in<'a>(current: &X509, candidates: &'a [X509]) -> Option<&'a X509> {
    candidates
        .iter()
        .find(|candidate| candidate_matches_issuer(current, candidate))
}

fn candidate_matches_issuer(current: &X509, candidate: &X509) -> bool {
    if candidate.subject_name() != current.issuer_name() {
        return false;
    }

    match (
        current.authority_key_identifier(),
        candidate.subject_key_identifier(),
    ) {
        (Some(authority_key), Some(subject_key)) => authority_key == subject_key,
        _ => true,
    }
}

fn verify_chain_signatures(chain: &[&X509]) -> Result<(), Error> {
    let mut chain_iter = chain.iter().peekable();

    while let Some(child) = chain_iter.next() {
        let issuer = match chain_iter.peek().copied() {
            Some(issuer) => *issuer,
            None if child.is_self_signed() => *child,
            None => continue,
        };

        let issuer_public_key = issuer.public_key().map_err(|_| {
            validation_error(
                StatusCode::BadCertificateInvalid,
                "certificate issuer public key could not be read",
            )
        })?;
        verify_certificate_signature(child, &issuer_public_key)?;
    }

    Ok(())
}

fn verify_certificate_signature(child: &X509, issuer_public_key: &PublicKey) -> Result<(), Error> {
    let tbs = child.tbs_der().map_err(|_| {
        validation_error(
            StatusCode::BadCertificateInvalid,
            "certificate TBSCertificate DER could not be read",
        )
    })?;
    let signature = child.signature_and_algorithm().map_err(|_| {
        validation_error(
            StatusCode::BadCertificateInvalid,
            "certificate signature could not be read",
        )
    })?;

    if signature.algorithm_oid == SHA_256_WITH_RSA_ENCRYPTION {
        return verify_rsa_signature(
            issuer_public_key.verify_sha256(&tbs, &signature.value),
            "RSA-SHA256 certificate signature verification failed",
        );
    }

    if signature.algorithm_oid == ID_RSASSA_PSS {
        return verify_rsa_signature(
            issuer_public_key.verify_sha256_pss(&tbs, &signature.value),
            "RSA-PSS certificate signature verification failed",
        );
    }

    if signature.algorithm_oid == SHA_1_WITH_RSA_ENCRYPTION {
        return verify_rsa_signature(
            issuer_public_key.verify_sha1(&tbs, &signature.value),
            "RSA-SHA1 certificate signature verification failed",
        );
    }

    verify_ec_signature(
        issuer_public_key,
        &tbs,
        &signature.value,
        signature.algorithm_oid,
    )
}

fn verify_rsa_signature(result: Result<bool, Error>, message: &str) -> Result<(), Error> {
    match result {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(validation_error(StatusCode::BadCertificateInvalid, message)),
    }
}

#[cfg(feature = "ecc")]
fn verify_ec_signature(
    issuer_public_key: &PublicKey,
    tbs: &[u8],
    signature: &[u8],
    algorithm_oid: const_oid::ObjectIdentifier,
) -> Result<(), Error> {
    if algorithm_oid != ECDSA_WITH_SHA_256 && algorithm_oid != ECDSA_WITH_SHA_384 {
        return Err(unsupported_signature_algorithm_error());
    }

    let ecc_key = issuer_public_key.ecc_key().ok_or_else(|| {
        validation_error(
            StatusCode::BadCertificateInvalid,
            "ECDSA certificate signature requires an EC issuer public key",
        )
    })?;

    crate::ecc::ecdsa_verify_der(ecc_key, tbs, signature).map_err(|_| {
        validation_error(
            StatusCode::BadCertificateInvalid,
            "ECDSA certificate signature verification failed",
        )
    })
}

#[cfg(not(feature = "ecc"))]
fn verify_ec_signature(
    _issuer_public_key: &PublicKey,
    _tbs: &[u8],
    _signature: &[u8],
    _algorithm_oid: const_oid::ObjectIdentifier,
) -> Result<(), Error> {
    Err(unsupported_signature_algorithm_error())
}

fn chain_contains_trusted_cert(chain: &[&X509], trusted_certs: &[X509]) -> Result<bool, Error> {
    for cert in chain {
        let der = cert_der(
            cert,
            StatusCode::BadCertificateUntrusted,
            "failed to encode certificate while checking trust list",
        )?;
        if der_in_list(
            &der,
            trusted_certs,
            StatusCode::BadCertificateUntrusted,
            "failed to encode trusted certificate while checking trust list",
        )? {
            return Ok(true);
        }
    }

    Ok(false)
}

fn validate_chain_security_policy(
    chain: &[&X509],
    context: &ChainValidationContext<'_>,
    findings: &mut Vec<SuppressedFinding>,
) -> Result<(), Error> {
    if context.security_policy == SecurityPolicy::None {
        return Ok(());
    }

    validate_chain_signature_algorithms(chain, context, findings)?;

    let Some(leaf) = chain.first().copied() else {
        return Err(validation_error(
            StatusCode::BadCertificateChainIncomplete,
            "certificate chain is empty",
        ));
    };

    match leaf.key_length() {
        Ok(key_length) if context.security_policy.is_valid_keylength(key_length) => {}
        Ok(_) => handle_security_policy_failure(
            context,
            findings,
            "leaf certificate key length is not allowed by the security policy",
        )?,
        Err(_) => handle_security_policy_failure(context, findings, "cannot read leaf key length")?,
    }

    Ok(())
}

fn validate_chain_signature_algorithms(
    chain: &[&X509],
    context: &ChainValidationContext<'_>,
    findings: &mut Vec<SuppressedFinding>,
) -> Result<(), Error> {
    for (index, cert) in chain.iter().enumerate() {
        match cert.signature_and_algorithm() {
            Ok(signature)
                if context
                    .security_policy
                    .is_valid_certificate_signature_algorithm(&signature.algorithm_oid) => {}
            Ok(_) => handle_security_policy_failure(
                context,
                findings,
                signature_algorithm_policy_failure_message(index),
            )?,
            Err(_) => handle_security_policy_failure(
                context,
                findings,
                signature_algorithm_policy_read_failure_message(index),
            )?,
        }
    }

    Ok(())
}

fn signature_algorithm_policy_failure_message(index: usize) -> &'static str {
    if index == 0 {
        "leaf certificate signature algorithm is not allowed by the security policy"
    } else {
        "issuer certificate signature algorithm is not allowed by the security policy"
    }
}

fn signature_algorithm_policy_read_failure_message(index: usize) -> &'static str {
    if index == 0 {
        "cannot read leaf certificate signature algorithm"
    } else {
        "cannot read issuer certificate signature algorithm"
    }
}

fn handle_security_policy_failure(
    context: &ChainValidationContext<'_>,
    findings: &mut Vec<SuppressedFinding>,
    message: &str,
) -> Result<(), Error> {
    let status = StatusCode::BadCertificatePolicyCheckFailed;

    if context
        .options
        .is_suppressed(SuppressibleStep::SecurityPolicy)
    {
        findings.push(SuppressedFinding {
            step: SuppressibleStep::SecurityPolicy,
            status,
            message: message.to_string(),
        });
        Ok(())
    } else {
        Err(validation_error(status, message))
    }
}

fn validate_chain_validity(
    chain: &[&X509],
    context: &ChainValidationContext<'_>,
) -> Result<Vec<SuppressedFinding>, Error> {
    let mut findings = Vec::new();
    let mut is_leaf = true;

    for cert in chain {
        let status = if is_leaf {
            StatusCode::BadCertificateTimeInvalid
        } else {
            StatusCode::BadCertificateIssuerTimeInvalid
        };
        is_leaf = false;

        if certificate_is_valid_at(cert, context.now) {
            continue;
        }

        let message = "certificate validity period does not include the validation time";
        if context.options.is_suppressed(SuppressibleStep::Validity) {
            findings.push(SuppressedFinding {
                step: SuppressibleStep::Validity,
                status,
                message: message.to_string(),
            });
        } else {
            return Err(validation_error(status, message));
        }
    }

    Ok(findings)
}

fn certificate_is_valid_at(cert: &X509, now: &DateTime<Utc>) -> bool {
    match (cert.not_before(), cert.not_after()) {
        (Ok(not_before), Ok(not_after)) => now >= &not_before && now <= &not_after,
        _ => false,
    }
}

fn validate_certificate_usage(
    chain: &[&X509],
    context: &ChainValidationContext<'_>,
    findings: &mut Vec<SuppressedFinding>,
) -> Result<(), Error> {
    for (index, cert) in chain.iter().enumerate() {
        if index == 0 {
            validate_leaf_certificate_usage(cert, context, findings)?;
        } else {
            validate_issuer_certificate_usage(chain, index, cert, context, findings)?;
        }
    }

    Ok(())
}

fn validate_leaf_certificate_usage(
    cert: &X509,
    context: &ChainValidationContext<'_>,
    findings: &mut Vec<SuppressedFinding>,
) -> Result<(), Error> {
    let status = StatusCode::BadCertificateUseNotAllowed;

    if let Some(key_usage) = cert.key_usage() {
        if !key_usage.0.contains(KeyUsages::DigitalSignature) {
            handle_certificate_usage_failure(
                context,
                findings,
                status,
                "leaf certificate key usage does not allow digital signatures",
            )?;
        }
    }

    if let Some(extended_key_usage) = cert.extended_key_usage() {
        if !extended_key_usage.0.is_empty() {
            let purpose_oid = purpose_extended_key_usage_oid(context.purpose);
            if !extended_key_usage.0.contains(&purpose_oid)
                && !extended_key_usage.0.contains(&ANY_EXTENDED_KEY_USAGE)
            {
                handle_certificate_usage_failure(
                    context,
                    findings,
                    status,
                    "leaf certificate extended key usage does not allow the requested application purpose",
                )?;
            }
        }
    }

    Ok(())
}

fn validate_issuer_certificate_usage(
    chain: &[&X509],
    index: usize,
    cert: &X509,
    context: &ChainValidationContext<'_>,
    findings: &mut Vec<SuppressedFinding>,
) -> Result<(), Error> {
    let status = StatusCode::BadCertificateIssuerUseNotAllowed;

    let basic_constraints = cert.basic_constraints();
    if !basic_constraints
        .as_ref()
        .is_some_and(|basic_constraints| basic_constraints.ca)
    {
        handle_certificate_usage_failure(
            context,
            findings,
            status,
            "issuer certificate basic constraints do not identify it as a CA",
        )?;
    }

    if let Some(path_len_constraint) =
        basic_constraints.and_then(|basic_constraints| basic_constraints.path_len_constraint)
    {
        let subordinate_ca_count = subordinate_ca_count_below(chain, index);
        if subordinate_ca_count > usize::from(path_len_constraint) {
            handle_certificate_usage_failure(
                context,
                findings,
                status,
                "issuer certificate path length constraint is exceeded",
            )?;
        }
    }

    if let Some(key_usage) = cert.key_usage() {
        if !key_usage.0.contains(KeyUsages::KeyCertSign) {
            handle_certificate_usage_failure(
                context,
                findings,
                status,
                "issuer certificate key usage does not allow certificate signing",
            )?;
        }
    }

    Ok(())
}

fn subordinate_ca_count_below(chain: &[&X509], issuer_index: usize) -> usize {
    let Some(subordinate_chain) = chain.get(1..issuer_index) else {
        return 0;
    };

    subordinate_chain
        .iter()
        .filter(|cert| {
            cert.basic_constraints()
                .is_some_and(|basic_constraints| basic_constraints.ca)
        })
        .count()
}

fn handle_certificate_usage_failure(
    context: &ChainValidationContext<'_>,
    findings: &mut Vec<SuppressedFinding>,
    status: StatusCode,
    message: &str,
) -> Result<(), Error> {
    if context
        .options
        .is_suppressed(SuppressibleStep::CertificateUsage)
    {
        findings.push(SuppressedFinding {
            step: SuppressibleStep::CertificateUsage,
            status,
            message: message.to_string(),
        });
        Ok(())
    } else {
        Err(validation_error(status, message))
    }
}

fn purpose_extended_key_usage_oid(purpose: CertificatePurpose) -> const_oid::ObjectIdentifier {
    match purpose {
        CertificatePurpose::ServerApplication => ID_KP_SERVER_AUTH,
        CertificatePurpose::ClientApplication => ID_KP_CLIENT_AUTH,
    }
}

fn validate_chain_revocation(
    chain: &[&X509],
    context: &ChainValidationContext<'_>,
    findings: &mut Vec<SuppressedFinding>,
) -> Result<(), Error> {
    if context.options.revocation_mode == RevocationMode::Disabled {
        return Ok(());
    }

    for (index, pair) in chain.windows(2).enumerate() {
        let [cert, issuer_ca] = pair else {
            continue;
        };

        let revoked_status = if index == 0 {
            StatusCode::BadCertificateRevoked
        } else {
            StatusCode::BadCertificateIssuerRevoked
        };

        // A valid OCSP response (signed by the issuer, covering this serial) is a definitive source:
        // revoked -> fail; good -> revocation is known, no CRL needed. Otherwise fall back to CRL.
        match ocsp_status(context, cert, issuer_ca, findings)? {
            Some(OcspVerdict::Revoked) => {
                return Err(validation_error(
                    revoked_status,
                    "certificate serial number is revoked by a valid OCSP response",
                ));
            }
            Some(OcspVerdict::Good) => continue,
            None => {}
        }

        let Some(crl) = find_valid_crl(context.crls, issuer_ca, context, findings)? else {
            handle_revocation_unknown(context, findings, index)?;
            continue;
        };

        if crl_revokes(crl, &cert.serial_number()) {
            return Err(validation_error(
                revoked_status,
                "certificate serial number is listed in a valid CRL",
            ));
        }
    }

    Ok(())
}

/// Definitive revocation verdict from a valid OCSP response.
enum OcspVerdict {
    Good,
    Revoked,
}

/// Returns a definitive OCSP verdict for `cert` from the supplied responses, or `None` if no valid,
/// issuer-signed, fresh response covers the certificate's serial (caller then falls back to CRL).
/// Only responses signed directly by `issuer_ca` are accepted (delegated responders are not
/// supported); `Unknown` status is treated as non-definitive.
fn ocsp_status(
    context: &ChainValidationContext<'_>,
    cert: &X509,
    issuer_ca: &X509,
    findings: &mut Vec<SuppressedFinding>,
) -> Result<Option<OcspVerdict>, Error> {
    let Some(ca_public_key) = issuer_ca.public_key().ok() else {
        return Ok(None);
    };
    let serial = cert.serial_number();

    for der in context.ocsp_responses {
        let Ok(response) = OcspResponse::from_der(der) else {
            continue;
        };
        if response.response_status != OcspResponseStatus::Successful {
            continue;
        }
        let Some(bytes) = response.response_bytes else {
            continue;
        };
        if bytes.response_type != ID_PKIX_OCSP_BASIC {
            continue;
        }
        let Ok(basic) = BasicOcspResponse::from_der(bytes.response.as_bytes()) else {
            continue;
        };

        let Some(verdict) = ocsp_verdict_for_serial(&basic, &serial, context.now) else {
            continue;
        };
        if !ocsp_signature_verifies(&basic, &ca_public_key) {
            continue;
        }

        validate_revocation_signature_algorithm(
            &basic.signature_algorithm.oid,
            context,
            findings,
            "OCSP response signature algorithm is not allowed by the security policy",
        )?;
        return Ok(Some(verdict));
    }

    Ok(None)
}

fn ocsp_verdict_for_serial(
    basic: &BasicOcspResponse,
    serial: &[u8],
    now: &DateTime<Utc>,
) -> Option<OcspVerdict> {
    for single in &basic.tbs_response_data.responses {
        if single.cert_id.serial_number.as_bytes() != serial {
            continue;
        }
        if !ocsp_single_is_fresh(single, now) {
            continue;
        }
        match single.cert_status {
            CertStatus::Revoked(_) => return Some(OcspVerdict::Revoked),
            CertStatus::Good(_) => return Some(OcspVerdict::Good),
            // Unknown is not a definitive answer; keep scanning for a usable response.
            CertStatus::Unknown(_) => continue,
        }
    }

    None
}

fn ocsp_signature_verifies(basic: &BasicOcspResponse, issuer_public_key: &PublicKey) -> bool {
    let Ok(tbs) = basic.tbs_response_data.to_der() else {
        return false;
    };
    let Some(signature) = basic.signature.as_bytes() else {
        return false;
    };
    der_signature_verifies(
        issuer_public_key,
        &tbs,
        signature,
        basic.signature_algorithm.oid,
    )
}

fn ocsp_single_is_fresh(single: &x509_ocsp::SingleResponse, now: &DateTime<Utc>) -> bool {
    let now_sys: std::time::SystemTime = (*now).into();
    let this_ok = single.this_update.0.to_system_time() <= now_sys;
    let next_ok = single
        .next_update
        .as_ref()
        .is_none_or(|next| next.0.to_system_time() >= now_sys);
    this_ok && next_ok
}

fn find_valid_crl<'a>(
    crls: &'a [CertificateList],
    issuer_ca: &X509,
    context: &ChainValidationContext<'_>,
    findings: &mut Vec<SuppressedFinding>,
) -> Result<Option<&'a CertificateList>, Error> {
    let Some(ca_public_key) = issuer_ca.public_key().ok() else {
        return Ok(None);
    };

    for crl in crls {
        if !crl_issuer_matches_ca(crl, issuer_ca) || !crl_is_current(crl, context.now) {
            continue;
        }
        if !crl_signature_verifies(crl, &ca_public_key) {
            continue;
        }

        validate_revocation_signature_algorithm(
            &crl.signature_algorithm.oid,
            context,
            findings,
            "CRL signature algorithm is not allowed by the security policy",
        )?;
        return Ok(Some(crl));
    }

    Ok(None)
}

fn crl_issuer_matches_ca(crl: &CertificateList, issuer_ca: &X509) -> bool {
    crl.tbs_cert_list.issuer.to_string().replace(';', "/") == issuer_ca.subject_name()
}

fn crl_is_current(crl: &CertificateList, now: &DateTime<Utc>) -> bool {
    crl.tbs_cert_list
        .next_update
        .is_none_or(|next_update| next_update.to_system_time() >= (*now).into())
}

fn crl_signature_verifies(crl: &CertificateList, issuer_public_key: &PublicKey) -> bool {
    let Ok(tbs) = crl.tbs_cert_list.to_der() else {
        return false;
    };
    let Some(signature) = crl.signature.as_bytes() else {
        return false;
    };
    der_signature_verifies(
        issuer_public_key,
        &tbs,
        signature,
        crl.signature_algorithm.oid,
    )
}

/// Verify a DER `tbs`/`signature` pair (CRL TBSCertList or OCSP ResponseData) against the issuer
/// public key, dispatching on the signature algorithm OID. Shared by CRL and OCSP verification.
fn der_signature_verifies(
    issuer_public_key: &PublicKey,
    tbs: &[u8],
    signature: &[u8],
    algorithm_oid: const_oid::ObjectIdentifier,
) -> bool {
    if algorithm_oid == SHA_256_WITH_RSA_ENCRYPTION {
        return issuer_public_key
            .verify_sha256(tbs, signature)
            .is_ok_and(|verified| verified);
    }

    if algorithm_oid == ID_RSASSA_PSS {
        return issuer_public_key
            .verify_sha256_pss(tbs, signature)
            .is_ok_and(|verified| verified);
    }

    if algorithm_oid == SHA_1_WITH_RSA_ENCRYPTION {
        return issuer_public_key
            .verify_sha1(tbs, signature)
            .is_ok_and(|verified| verified);
    }

    crl_ec_signature_verifies(issuer_public_key, tbs, signature, algorithm_oid)
}

fn validate_revocation_signature_algorithm(
    algorithm_oid: &const_oid::ObjectIdentifier,
    context: &ChainValidationContext<'_>,
    findings: &mut Vec<SuppressedFinding>,
    message: &str,
) -> Result<(), Error> {
    if context.security_policy == SecurityPolicy::None
        || context
            .security_policy
            .is_valid_certificate_signature_algorithm(algorithm_oid)
    {
        return Ok(());
    }

    handle_security_policy_failure(context, findings, message)
}

#[cfg(feature = "ecc")]
fn crl_ec_signature_verifies(
    issuer_public_key: &PublicKey,
    tbs: &[u8],
    signature: &[u8],
    algorithm_oid: const_oid::ObjectIdentifier,
) -> bool {
    if algorithm_oid != ECDSA_WITH_SHA_256 && algorithm_oid != ECDSA_WITH_SHA_384 {
        return false;
    }

    issuer_public_key
        .ecc_key()
        .is_some_and(|ecc_key| crate::ecc::ecdsa_verify_der(ecc_key, tbs, signature).is_ok())
}

#[cfg(not(feature = "ecc"))]
fn crl_ec_signature_verifies(
    _issuer_public_key: &PublicKey,
    _tbs: &[u8],
    _signature: &[u8],
    _algorithm_oid: const_oid::ObjectIdentifier,
) -> bool {
    false
}

fn crl_revokes(crl: &CertificateList, serial: &[u8]) -> bool {
    crl.tbs_cert_list
        .revoked_certificates
        .as_deref()
        .is_some_and(|revoked_certificates| {
            revoked_certificates
                .iter()
                .any(|revoked| revoked_cert_matches_serial(revoked, serial))
        })
}

fn revoked_cert_matches_serial(revoked: &RevokedCert, serial: &[u8]) -> bool {
    revoked.serial_number.as_bytes() == serial
}

fn handle_revocation_unknown(
    context: &ChainValidationContext<'_>,
    findings: &mut Vec<SuppressedFinding>,
    index: usize,
) -> Result<(), Error> {
    if context.options.revocation_mode == RevocationMode::Lenient {
        return Ok(());
    }

    let status = if index == 0 {
        StatusCode::BadCertificateRevocationUnknown
    } else {
        StatusCode::BadCertificateIssuerRevocationUnknown
    };
    let message = "no valid CRL was found for certificate issuer";

    if context
        .options
        .is_suppressed(SuppressibleStep::FindRevocationList)
    {
        findings.push(SuppressedFinding {
            step: SuppressibleStep::FindRevocationList,
            status,
            message: message.to_string(),
        });
        Ok(())
    } else {
        Err(validation_error(status, message))
    }
}

fn der_in_list(
    target_der: &[u8],
    candidates: &[X509],
    status: StatusCode,
    message: &str,
) -> Result<bool, Error> {
    for candidate in candidates {
        let candidate_der = cert_der(candidate, status, message)?;
        if candidate_der == target_der {
            return Ok(true);
        }
    }

    Ok(false)
}

fn cert_der(cert: &X509, status: StatusCode, message: &str) -> Result<Vec<u8>, Error> {
    cert.to_der().map_err(|_| validation_error(status, message))
}

fn chain_incomplete_error(message: &str) -> Error {
    validation_error(StatusCode::BadCertificateChainIncomplete, message)
}

fn unsupported_signature_algorithm_error() -> Error {
    validation_error(
        StatusCode::BadCertificateInvalid,
        "unsupported certificate signature algorithm",
    )
}

fn validation_error(status: StatusCode, message: &str) -> Error {
    Error::new(status, message)
}
