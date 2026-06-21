use std::collections::HashSet;

use chrono::{DateTime, Utc};
use const_oid::db::rfc5280::{ANY_EXTENDED_KEY_USAGE, ID_KP_CLIENT_AUTH, ID_KP_SERVER_AUTH};
#[cfg(feature = "ecc")]
use const_oid::db::rfc5912::{ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384};
use const_oid::db::rfc5912::{
    ID_RSASSA_PSS, SHA_1_WITH_RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION,
};
use opcua_types::{status_code::StatusCode, Error};
use x509_cert::crl::{CertificateList, RevokedCert};
use x509_cert::der::Encode;
use x509_cert::ext::pkix::KeyUsages;

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

    let _ = context.security_policy; // consumed by US4

    let chain = build_chain(cert, context)?;

    verify_chain_signatures(&chain)?;

    if !chain_contains_trusted_cert(&chain, context.trusted_certs)? {
        return Err(validation_error(
            StatusCode::BadCertificateUntrusted,
            "certificate chain does not contain a trusted certificate",
        ));
    }

    let mut findings = validate_chain_validity(&chain, context)?;
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
            validate_issuer_certificate_usage(cert, context, findings)?;
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
    cert: &X509,
    context: &ChainValidationContext<'_>,
    findings: &mut Vec<SuppressedFinding>,
) -> Result<(), Error> {
    let status = StatusCode::BadCertificateIssuerUseNotAllowed;

    if !cert
        .basic_constraints()
        .is_some_and(|basic_constraints| basic_constraints.ca)
    {
        handle_certificate_usage_failure(
            context,
            findings,
            status,
            "issuer certificate basic constraints do not identify it as a CA",
        )?;
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

        let Some(crl) = find_valid_crl(context.crls, issuer_ca, context.now) else {
            handle_revocation_unknown(context, findings, index)?;
            continue;
        };

        if crl_revokes(crl, &cert.serial_number()) {
            let status = if index == 0 {
                StatusCode::BadCertificateRevoked
            } else {
                StatusCode::BadCertificateIssuerRevoked
            };
            return Err(validation_error(
                status,
                "certificate serial number is listed in a valid CRL",
            ));
        }
    }

    Ok(())
}

fn find_valid_crl<'a>(
    crls: &'a [CertificateList],
    issuer_ca: &X509,
    now: &DateTime<Utc>,
) -> Option<&'a CertificateList> {
    let ca_public_key = issuer_ca.public_key().ok()?;

    crls.iter().find(|crl| {
        crl_issuer_matches_ca(crl, issuer_ca)
            && crl_is_current(crl, now)
            && crl_signature_verifies(crl, &ca_public_key)
    })
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

    if crl.signature_algorithm.oid == SHA_256_WITH_RSA_ENCRYPTION {
        return issuer_public_key
            .verify_sha256(&tbs, signature)
            .is_ok_and(|verified| verified);
    }

    if crl.signature_algorithm.oid == ID_RSASSA_PSS {
        return issuer_public_key
            .verify_sha256_pss(&tbs, signature)
            .is_ok_and(|verified| verified);
    }

    if crl.signature_algorithm.oid == SHA_1_WITH_RSA_ENCRYPTION {
        return issuer_public_key
            .verify_sha1(&tbs, signature)
            .is_ok_and(|verified| verified);
    }

    crl_ec_signature_verifies(
        issuer_public_key,
        &tbs,
        signature,
        crl.signature_algorithm.oid,
    )
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
