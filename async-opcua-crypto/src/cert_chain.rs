use std::collections::HashSet;

use chrono::{DateTime, Utc};
use opcua_types::{status_code::StatusCode, Error};
use x509_cert::crl::CertificateList;

use crate::{SecurityPolicy, X509};

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
pub fn validate_certificate_chain(
    cert: &X509,
    context: &ChainValidationContext<'_>,
) -> Result<Vec<SuppressedFinding>, Error> {
    // T007+ implement the ordered Table 100 pipeline here.
    let _ = (cert, context);
    Err(Error::new(
        StatusCode::BadCertificateInvalid,
        "certificate chain validation is not yet implemented",
    ))
}
