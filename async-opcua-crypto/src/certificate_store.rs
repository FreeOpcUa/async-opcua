// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! The certificate store holds and retrieves private keys and certificates from disk. It is responsible
//! for checking certificates supplied by the remote end to see if they are valid and trusted or not.

use std::fs::{read_dir, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use opcua_types::{status_code::StatusCode, Error};
use tracing::{debug, error, info, trace, warn};

use x509_cert::{
    crl::CertificateList,
    der::{Decode, Reader},
};

use crate::{
    validate_certificate_chain, CertificatePurpose, ChainValidationContext, PrivateKey,
    SuppressedFinding, SuppressibleStep, ValidationOptions,
};

use super::{
    security_policy::SecurityPolicy,
    x509::{X509Data, X509},
};

/// Default path to the applications own certificate
const OWN_CERTIFICATE_PATH: &str = "own/cert.der";
/// Default path to the applications own private key
const OWN_PRIVATE_KEY_PATH: &str = "private/private.pem";
/// The directory holding trusted certificates
const TRUSTED_CERTS_DIR: &str = "trusted";
/// The directory holding issuer certificates
const ISSUER_CERTS_DIR: &str = "issuer";
/// The directory holding CRLs for trusted CA certificates
const TRUSTED_CRLS_DIR: &str = "trusted_crls";
/// The directory holding CRLs for issuer CA certificates
const ISSUER_CRLS_DIR: &str = "issuer_crls";
/// The directory holding rejected certificates
const REJECTED_CERTS_DIR: &str = "rejected";

#[derive(Clone, Copy)]
enum IncomingCertificateKind {
    ApplicationInstance,
    UserIdentity,
}

impl IncomingCertificateKind {
    fn trust_list_status(self) -> StatusCode {
        StatusCode::BadCertificateUntrusted
    }

    fn rejected_store_status(self) -> StatusCode {
        self.trust_list_status()
    }

    fn invalid_structure_status(self) -> StatusCode {
        match self {
            IncomingCertificateKind::ApplicationInstance => StatusCode::BadSecurityChecksFailed,
            IncomingCertificateKind::UserIdentity => StatusCode::BadCertificateInvalid,
        }
    }

    fn policy_check_status(self) -> StatusCode {
        match self {
            IncomingCertificateKind::ApplicationInstance => StatusCode::BadSecurityChecksFailed,
            IncomingCertificateKind::UserIdentity => StatusCode::BadCertificatePolicyCheckFailed,
        }
    }
}

/// The certificate store manages the storage of a server/client's own certificate & private key
/// and the trust / rejection of certificates from the other end.
pub struct CertificateStore {
    /// Path to the applications own certificate
    own_certificate_path: PathBuf,
    /// Path to the applications own private key
    own_private_key_path: PathBuf,
    /// Path to the certificate store on disk
    pub(crate) pki_path: PathBuf,
    /// Timestamps of the cert are normally checked on the cert to ensure it cannot be used before
    /// or after its limits, but this check can be disabled.
    check_time: bool,
    /// This option lets you skip additional certificate validations (e.g. hostname, application
    /// uri and the not before / after values). Certificates are always checked to see if they are
    /// trusted and have a valid key length.
    skip_verify_certs: bool,
    /// Ordinarily an unknown cert will be dropped into the rejected folder, but it can be dropped
    /// into the trusted folder if this flag is set. Certs in the trusted folder must still pass
    /// validity checks.
    #[allow(dead_code)] // retained for the US5 legacy trust-list path
    trust_unknown_certs: bool,
    /// Certificate validation options applied to incoming application instance certificates.
    validation_options: ValidationOptions,
}

impl CertificateStore {
    /// Sets up the certificate store to the specified PKI directory.
    /// It is a bad idea to have more than one running instance pointing to the same path
    /// location on disk.
    pub fn new(pki_path: &Path) -> CertificateStore {
        CertificateStore {
            own_certificate_path: PathBuf::from(OWN_CERTIFICATE_PATH),
            own_private_key_path: PathBuf::from(OWN_PRIVATE_KEY_PATH),
            pki_path: pki_path.to_path_buf(),
            check_time: true,
            skip_verify_certs: false,
            trust_unknown_certs: false,
            validation_options: ValidationOptions::default(),
        }
    }

    /// Create a new certificate store with application certificate from the given
    /// `cert_path`.
    pub fn new_with_x509_data<X>(
        pki_path: &Path,
        overwrite: bool,
        cert_path: Option<&Path>,
        pkey_path: Option<&Path>,
        x509_data: Option<X>,
    ) -> (CertificateStore, Option<X509>, Option<PrivateKey>)
    where
        X: Into<X509Data>,
    {
        let mut certificate_store = CertificateStore::new(pki_path);
        if let (Some(cert_path), Some(pkey_path)) = (cert_path, pkey_path) {
            certificate_store.own_certificate_path = cert_path.to_path_buf();
            certificate_store.own_private_key_path = pkey_path.to_path_buf();
        }
        let (cert, pkey) = if certificate_store.ensure_pki_path().is_err() {
            error!(
                "Folder for storing certificates cannot be examined so server has no application instance certificate or private key."
            );
            (None, None)
        } else {
            let cert = certificate_store.read_own_cert();
            let pkey = certificate_store.read_own_pkey();
            match (cert, pkey, x509_data) {
                (Ok(cert), Ok(pkey), _) => (Some(cert), Some(pkey)),
                (_, _, Some(x509_data)) => {
                    info!("Creating sample application instance certificate and private key");
                    let x509_data = x509_data.into();
                    let result = certificate_store
                        .create_and_store_application_instance_cert(&x509_data, overwrite);
                    match result {
                        Ok((cert, pkey)) => (Some(cert), Some(pkey)),
                        Err(err) => {
                            error!("Certificate creation failed, error = {}", err);
                            (None, None)
                        }
                    }
                }
                (Err(e1), Err(e2), _) => {
                    error!("Failed to get cert and private key: {e1}, {e2}");
                    (None, None)
                }
                (Err(e), _, _) | (_, Err(e), _) => {
                    error!("Failed to get cert or private key: {e}");
                    (None, None)
                }
            }
        };
        (certificate_store, cert, pkey)
    }

    /// Set `skip_verify_certs` to not verify incoming certificates.
    pub fn set_skip_verify_certs(&mut self, skip_verify_certs: bool) {
        self.skip_verify_certs = skip_verify_certs;
    }

    /// Set `trust_unknown_certs` to automatically trust valid but
    /// untrusted certificates.
    pub fn set_trust_unknown_certs(&mut self, trust_unknown_certs: bool) {
        self.trust_unknown_certs = trust_unknown_certs;
    }

    /// Check expiration time of incoming certificates.
    pub fn set_check_time(&mut self, check_time: bool) {
        self.check_time = check_time;
    }

    /// Set certificate validation options for incoming application instance certificates.
    pub fn set_validation_options(&mut self, options: ValidationOptions) {
        self.validation_options = options;
    }

    /// Reads a private key from a path on disk.
    pub fn read_pkey(path: &Path) -> Result<PrivateKey, String> {
        if let Ok(pkey) = PrivateKey::read_pem_file(path) {
            return Ok(pkey);
        }

        Err(format!("Cannot read pkey from path {path:?}"))
    }

    /// Reads the store's own certificate
    pub fn read_own_cert(&self) -> Result<X509, String> {
        CertificateStore::read_cert(&self.own_certificate_path()).map_err(|e| {
            format!(
                "Cannot read cert from path {:?}: {e}",
                self.own_certificate_path()
            )
        })
    }

    /// Read own private key from file.
    pub fn read_own_pkey(&self) -> Result<PrivateKey, String> {
        CertificateStore::read_pkey(&self.own_private_key_path()).map_err(|e| {
            format!(
                "Cannot read pkey from path {:?}: {e}",
                self.own_private_key_path()
            )
        })
    }

    /// Create a certificate and key pair to the specified locations
    pub fn create_certificate_and_key(
        args: &X509Data,
        overwrite: bool,
        cert_path: &Path,
        pkey_path: &Path,
    ) -> Result<(X509, PrivateKey), String> {
        let (cert, pkey) = X509::cert_and_pkey(args)?;

        // Write the public cert
        let _ = CertificateStore::store_cert(&cert, cert_path, overwrite)?;

        // Write the private key
        use rsa::pkcs8;
        use x509_cert::der::pem::PemLabel;
        let doc = pkey
            .to_der()
            .map_err(|e| format!("Failed to convert private key to DER: {e:?}"))?;
        let pem = doc
            .to_pem(rsa::pkcs8::PrivateKeyInfo::PEM_LABEL, pkcs8::LineEnding::CR)
            .map_err(|e| format!("Failed to convert private key to PEM: {e:?}"))?;
        let _ = CertificateStore::write_private_key_to_file(pem.as_bytes(), pkey_path, overwrite)?;
        Ok((cert, pkey))
    }

    /// This function will use the supplied arguments to create an Application Instance Certificate
    /// consisting of a X509v3 certificate and public/private key pair. The cert (including pubkey)
    /// and private key will be written to disk under the pki path.
    pub fn create_and_store_application_instance_cert(
        &self,
        args: &X509Data,
        overwrite: bool,
    ) -> Result<(X509, PrivateKey), String> {
        CertificateStore::create_certificate_and_key(
            args,
            overwrite,
            &self.own_certificate_path(),
            &self.own_private_key_path(),
        )
    }

    /// Validates the cert as trusted and valid. If the cert is unknown, it will be written to
    /// the rejected folder so that the administrator can manually move it to the trusted folder.
    ///
    /// # Errors
    ///
    /// A non `Good` status code indicates a failure in the cert or in some action required in
    /// order to validate it.
    ///
    pub fn validate_or_reject_application_instance_cert(
        &self,
        cert: &X509,
        security_policy: SecurityPolicy,
        hostname: Option<&str>,
        application_uri: Option<&str>,
    ) -> Result<(), Error> {
        self.validate_application_instance_cert(cert, security_policy, hostname, application_uri)
    }

    /// Validates an X.509 user identity certificate before thumbprint-based user mapping.
    ///
    /// User identity certificates use the same trust-chain, validity, revocation, security-policy,
    /// and usage pipeline as incoming application certificates, but a configured user thumbprint is
    /// not a trust anchor. Suppressed non-critical findings are returned to the caller so they can
    /// be audited as required by OPC UA Part 4.
    pub fn validate_user_identity_cert(
        &self,
        cert: &X509,
        security_policy: SecurityPolicy,
    ) -> Result<Vec<SuppressedFinding>, Error> {
        self.validate_incoming_cert(
            cert,
            security_policy,
            CertificatePurpose::ClientApplication,
            false,
            IncomingCertificateKind::UserIdentity,
        )
    }

    /// Ensures that the cert provided is the same as the one specified by a path. This is a
    /// security check to stop someone from renaming a cert on disk to match another cert and
    /// somehow bypassing or subverting a check. The disk cert must exactly match the memory cert
    /// or the test is assumed to fail.
    #[allow(dead_code)] // retained for the US5 legacy trust-list path
    fn ensure_cert_and_file_are_the_same(cert: &X509, cert_path: &Path) -> bool {
        if !cert_path.exists() {
            trace!("Cannot find cert on disk");
            false
        } else {
            match CertificateStore::read_cert(cert_path) {
                Ok(file_der) => {
                    // Compare the buffers
                    trace!("Comparing cert on disk to memory");
                    let der;
                    {
                        let r = cert.to_der();
                        match r {
                            Err(_) => return false,
                            Ok(val) => der = val,
                        }
                    }

                    let target_der;
                    {
                        let r = file_der.to_der();
                        match r {
                            Err(_) => return false,
                            Ok(val) => target_der = val,
                        }
                    }

                    der == target_der
                }
                Err(err) => {
                    trace!("Cannot read cert from disk {:?} - {}", cert_path, err);
                    // No cert2 to compare to
                    false
                }
            }
        }
    }

    /// Validates the certificate according to the strictness set in the CertificateStore itself.
    /// Validation might include checking the issue time, expiration time, revocation, trust chain
    /// etc. In the first instance this function will only check if the cert is recognized
    /// and is already contained in the trusted or rejected folder.
    ///
    /// # Errors
    ///
    /// A non `Good` status code indicates a failure in the cert or in some action required in
    /// order to validate it.
    ///
    pub fn validate_application_instance_cert(
        &self,
        cert: &X509,
        security_policy: SecurityPolicy,
        hostname: Option<&str>,
        application_uri: Option<&str>,
    ) -> Result<(), Error> {
        // Server application certificates carry host names; client validation does not.
        let purpose = if hostname.is_some() {
            CertificatePurpose::ServerApplication
        } else {
            CertificatePurpose::ClientApplication
        };
        let cert_file_name = CertificateStore::cert_file_name(cert);
        let findings = self.validate_incoming_cert(
            cert,
            security_policy,
            purpose,
            true,
            IncomingCertificateKind::ApplicationInstance,
        )?;
        for finding in findings {
            warn!(
                "Certificate {cert_file_name}: suppressed certificate-validation finding [{:?}] {} - {}",
                finding.step, finding.status, finding.message
            );
        }

        if self.skip_verify_certs {
            debug!(
                "Skipping additional verifications for certificate {}",
                cert_file_name
            );
            return Ok(());
        }

        // Compare the hostname of the cert against the cert supplied
        if let Some(hostname) = hostname {
            cert.is_hostname_valid(hostname)?;
        }

        // Compare the application / product uri to the supplied application description
        if let Some(application_uri) = application_uri {
            cert.is_application_uri_valid(application_uri)?;
        }

        Ok(())
    }

    fn validate_incoming_cert(
        &self,
        cert: &X509,
        security_policy: SecurityPolicy,
        purpose: CertificatePurpose,
        allow_trust_unknown_certs: bool,
        kind: IncomingCertificateKind,
    ) -> Result<Vec<SuppressedFinding>, Error> {
        let cert_file_name = CertificateStore::cert_file_name(cert);
        debug!("Validating cert with name on disk {}", cert_file_name);

        // Reject unsupported / unavailable security policies before any policy-crypto call.
        security_policy.ensure_supported()?;

        // Look for the cert in the rejected folder. If it's rejected there is no purpose going
        // any further
        {
            let mut cert_path = self.rejected_certs_dir();
            if !cert_path.exists() {
                error!(
                    "Path for rejected certificates {} does not exist",
                    cert_path.display()
                );
                return Err(Error::new(
                    StatusCode::BadUnexpectedError,
                    format!(
                        "Path for rejected certificates {} does not exist",
                        cert_path.display()
                    ),
                ));
            }
            cert_path.push(&cert_file_name);
            if cert_path.exists() {
                warn!(
                    "Certificate {} is untrusted because it resides in the rejected directory",
                    cert_file_name
                );
                return Err(Error::new(
                    kind.rejected_store_status(),
                    format!(
                        "Certificate {} is untrusted because it resides in the rejected directory",
                        cert_file_name
                    ),
                ));
            }
        }

        #[cfg(feature = "ecc")]
        cert.ensure_curve_matches_policy(security_policy)?;

        // Check that the certificate is the right length for the security policy
        match cert.key_length() {
            Err(_) => {
                error!("Cannot read key length from certificate {}", cert_file_name);
                return Err(Error::new(
                    kind.invalid_structure_status(),
                    format!("Cannot read key length from certificate {}", cert_file_name),
                ));
            }
            Ok(key_length) => {
                if !security_policy.is_valid_keylength(key_length) {
                    warn!(
                        "Certificate {} has an invalid key length {} for the policy {}",
                        cert_file_name, key_length, security_policy
                    );
                    return Err(Error::new(
                        kind.policy_check_status(),
                        format!(
                            "Certificate {} has an invalid key length {} for the policy {}",
                            cert_file_name, key_length, security_policy
                        ),
                    ));
                }
            }
        }

        let mut options = self.validation_options.clone();
        if !self.check_time || self.skip_verify_certs {
            options.suppressed_steps.insert(SuppressibleStep::Validity);
        }

        self.ensure_trusted_certs_dir_available(cert, &cert_file_name, kind)?;

        let mut trusted = self.read_trusted_certs_for_validation(cert, &cert_file_name, kind)?;
        // Honor trust_unknown_certs: auto-trust an unknown presented certificate by persisting it and
        // making it its own trust anchor. The chain engine still verifies its signature (a self-signed
        // cert self-verifies; a non-self-signed anchor is trusted as presented) and its validity period.
        if allow_trust_unknown_certs && self.trust_unknown_certs {
            let already_trusted = trusted.iter().any(|t| t.thumbprint() == cert.thumbprint());
            if !already_trusted {
                warn!(
                    "Certificate {} is unknown but trust_unknown_certs is set, so it will be trusted",
                    cert_file_name
                );
                let _ = self.store_trusted_cert(cert);
                trusted.push(cert.clone());
            }
        }
        let issuers = self.read_issuer_certs();
        let mut crls = self.read_trusted_crls();
        crls.extend(self.read_issuer_crls());
        let now = chrono::Utc::now();
        let context = ChainValidationContext {
            trusted_certs: &trusted,
            issuer_certs: &issuers,
            crls: &crls,
            // No live OCSP fetch; the store has no out-of-band/stapled responses to supply.
            ocsp_responses: &[],
            security_policy,
            purpose,
            options: &options,
            now: &now,
        };
        match validate_certificate_chain(cert, &context) {
            Err(e) => {
                let _ = self.store_rejected_cert(cert);
                Err(e)
            }
            Ok(findings) => Ok(findings),
        }
    }

    fn ensure_trusted_certs_dir_available(
        &self,
        cert: &X509,
        cert_file_name: &str,
        kind: IncomingCertificateKind,
    ) -> Result<(), Error> {
        let trusted_dir = self.trusted_certs_dir();
        if let Err(err) = read_dir(&trusted_dir) {
            let thumbprint = cert.thumbprint().as_hex_string();
            error!(
                "Certificate {} cannot be trusted because trusted certificate directory {} is unavailable: {}",
                cert_file_name,
                trusted_dir.display(),
                err
            );
            return Err(Error::new(
                kind.trust_list_status(),
                format!(
                    "Certificate {} ({}) cannot be trusted because trusted certificate directory {} is unavailable: {}",
                    cert_file_name,
                    thumbprint,
                    trusted_dir.display(),
                    err
                ),
            ));
        }

        Ok(())
    }

    fn read_trusted_certs_for_validation(
        &self,
        cert: &X509,
        cert_file_name: &str,
        kind: IncomingCertificateKind,
    ) -> Result<Vec<X509>, Error> {
        let trusted_dir = self.trusted_certs_dir();
        CertificateStore::read_cert_dir_strict(&trusted_dir).map_err(|err| {
            let thumbprint = cert.thumbprint().as_hex_string();
            error!(
                "Certificate {} cannot be trusted because trusted certificate storage {} is invalid: {}",
                cert_file_name,
                trusted_dir.display(),
                err
            );
            Error::new(
                kind.trust_list_status(),
                format!(
                    "Certificate {} ({}) cannot be trusted because trusted certificate storage {} is invalid: {}",
                    cert_file_name,
                    thumbprint,
                    trusted_dir.display(),
                    err
                ),
            )
        })
    }

    /// Returns a certificate file name from the cert's issuer and thumbprint fields.
    /// File name is either "prefix - \[thumbprint\].der" or "thumbprint.der" depending on
    /// the cert's common name being empty or not
    pub fn cert_file_name(cert: &X509) -> String {
        let prefix = if let Ok(common_name) = cert.common_name() {
            common_name.trim().to_string().replace('/', "")
        } else {
            String::new()
        };
        let thumbprint = cert.thumbprint().as_hex_string();

        if !prefix.is_empty() {
            format!("{prefix} [{thumbprint}].der")
        } else {
            format!("{thumbprint}.der")
        }
    }

    /// Creates the PKI directory structure
    ///
    /// # Errors
    ///
    /// A string description of any failure
    ///
    pub fn ensure_pki_path(&self) -> Result<(), String> {
        let mut path = self.pki_path.clone();
        let subdirs = [
            TRUSTED_CERTS_DIR,
            REJECTED_CERTS_DIR,
            ISSUER_CERTS_DIR,
            TRUSTED_CRLS_DIR,
            ISSUER_CRLS_DIR,
        ];
        for subdir in &subdirs {
            path.push(subdir);
            CertificateStore::ensure_dir(&path)?;
            path.pop();
        }
        Ok(())
    }

    /// Ensure the directory exists, creating it if necessary
    ///
    /// # Errors
    ///
    /// A string description of any failure
    ///
    fn ensure_dir(path: &Path) -> Result<(), String> {
        if path.exists() {
            if !path.is_dir() {
                Err(format!("{} is not a directory ", path.display()))
            } else {
                Ok(())
            }
        } else {
            std::fs::create_dir_all(path)
                .map_err(|_| format!("Cannot make directories for {}", path.display()))
        }
    }

    /// Get path to application instance certificate
    pub fn own_certificate_path(&self) -> PathBuf {
        let mut path = PathBuf::from(&self.pki_path);
        path.push(&self.own_certificate_path);
        path
    }

    /// Get path to application instance private key
    pub fn own_private_key_path(&self) -> PathBuf {
        let mut path = PathBuf::from(&self.pki_path);
        path.push(&self.own_private_key_path);
        path
    }

    /// Get the path to the rejected certs dir
    pub fn rejected_certs_dir(&self) -> PathBuf {
        let mut path = PathBuf::from(&self.pki_path);
        path.push(REJECTED_CERTS_DIR);
        path
    }

    /// Get the path to the trusted certs dir
    pub fn trusted_certs_dir(&self) -> PathBuf {
        let mut path = PathBuf::from(&self.pki_path);
        path.push(TRUSTED_CERTS_DIR);
        path
    }

    /// Get the path to the issuer certs dir
    pub fn issuer_certs_dir(&self) -> PathBuf {
        let mut path = PathBuf::from(&self.pki_path);
        path.push(ISSUER_CERTS_DIR);
        path
    }

    /// Get the path to the trusted CRLs dir
    pub fn trusted_crls_dir(&self) -> PathBuf {
        let mut path = PathBuf::from(&self.pki_path);
        path.push(TRUSTED_CRLS_DIR);
        path
    }

    /// Get the path to the issuer CRLs dir
    pub fn issuer_crls_dir(&self) -> PathBuf {
        let mut path = PathBuf::from(&self.pki_path);
        path.push(ISSUER_CRLS_DIR);
        path
    }

    /// Read all trusted certificates from the store.
    pub fn read_trusted_certs(&self) -> Vec<X509> {
        CertificateStore::read_cert_dir(&self.trusted_certs_dir())
    }

    /// Read all issuer certificates from the store.
    pub fn read_issuer_certs(&self) -> Vec<X509> {
        CertificateStore::read_cert_dir(&self.issuer_certs_dir())
    }

    /// Read all trusted CRLs from the store.
    pub fn read_trusted_crls(&self) -> Vec<CertificateList> {
        CertificateStore::read_crl_dir(&self.trusted_crls_dir())
    }

    /// Read all issuer CRLs from the store.
    pub fn read_issuer_crls(&self) -> Vec<CertificateList> {
        CertificateStore::read_crl_dir(&self.issuer_crls_dir())
    }

    /// Write a cert to the rejected directory. If the write succeeds, the function
    /// returns a path to the written file.
    ///
    /// # Errors
    ///
    /// A string description of any failure
    ///
    pub fn store_rejected_cert(&self, cert: &X509) -> Result<PathBuf, String> {
        // Store the cert in the rejected folder where untrusted certs go
        let cert_file_name = CertificateStore::cert_file_name(cert);
        let mut cert_path = self.rejected_certs_dir();
        cert_path.push(&cert_file_name);
        let _ = CertificateStore::store_cert(cert, &cert_path, true)?;
        Ok(cert_path)
    }

    /// Writes a cert to the trusted directory. If the write succeeds, the function
    /// returns a path to the written file.
    ///
    /// # Errors
    ///
    /// A string description of any failure
    ///
    #[allow(dead_code)] // retained for the US5 legacy trust-list path
    fn store_trusted_cert(&self, cert: &X509) -> Result<PathBuf, String> {
        // Store the cert in the trusted folder where trusted certs go
        let cert_file_name = CertificateStore::cert_file_name(cert);
        let mut cert_path = self.trusted_certs_dir();
        cert_path.push(&cert_file_name);
        let _ = CertificateStore::store_cert(cert, &cert_path, true)?;
        Ok(cert_path)
    }

    /// Writes a cert to the specified directory
    ///
    /// # Errors
    ///
    /// A string description of any failure
    ///
    fn store_cert(cert: &X509, path: &Path, overwrite: bool) -> Result<usize, String> {
        let der = cert
            .to_der()
            .map_err(|e| format!("Could not encode X509 cert as DER: {e:?}"))?;
        info!("Writing X509 cert to {}", path.display());
        CertificateStore::write_to_file(&der, path, overwrite)
    }

    /// Reads an X509 certificate in .def or .pem format from disk
    ///
    /// # Errors
    ///
    /// A string description of any failure
    ///
    pub fn read_cert(path: &Path) -> Result<X509, String> {
        let file = File::open(path);
        if file.is_err() {
            return Err(format!("Could not open cert file {}", path.display()));
        }

        let mut file: File =
            file.map_err(|_| format!("Could not open cert file {}", path.display()))?;
        let mut cert = Vec::new();
        let bytes_read = file.read_to_end(&mut cert);
        if bytes_read.is_err() {
            return Err(format!(
                "Could not read bytes from cert file {}",
                path.display()
            ));
        }

        let cert = match path.extension() {
            Some(v) if v == "der" => X509::from_der(&cert),
            Some(v) if v == "pem" => X509::from_pem(&cert),
            _ => return Err("Only .der and .pem certificates are supported".to_string()),
        };

        match cert {
            Err(_) => Err(format!(
                "Could not read cert from cert file {}",
                path.display()
            )),
            Ok(val) => Ok(val),
        }
    }

    fn read_cert_dir(path: &Path) -> Vec<X509> {
        let entries = match read_dir(path) {
            Ok(entries) => entries,
            Err(err) => {
                trace!(
                    "Cannot read certificate directory {}: {}",
                    path.display(),
                    err
                );
                return Vec::new();
            }
        };

        let mut certs = Vec::new();
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    trace!(
                        "Cannot read certificate directory entry from {}: {}",
                        path.display(),
                        err
                    );
                    continue;
                }
            };
            let cert_path = entry.path();
            if !CertificateStore::is_der_or_pem_file(&cert_path) {
                continue;
            }

            match CertificateStore::read_cert(&cert_path) {
                Ok(cert) => certs.push(cert),
                Err(err) => {
                    trace!("Cannot read certificate {}: {}", cert_path.display(), err);
                }
            }
        }
        certs
    }

    fn read_cert_dir_strict(path: &Path) -> Result<Vec<X509>, String> {
        let entries = read_dir(path).map_err(|err| {
            format!(
                "Cannot read certificate directory {}: {}",
                path.display(),
                err
            )
        })?;

        let mut certs = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|err| {
                format!(
                    "Cannot read certificate directory entry from {}: {}",
                    path.display(),
                    err
                )
            })?;
            let cert_path = entry.path();
            if !CertificateStore::is_der_or_pem_file(&cert_path) {
                continue;
            }

            let cert = CertificateStore::read_cert(&cert_path).map_err(|err| {
                format!("Cannot read certificate {}: {}", cert_path.display(), err)
            })?;
            certs.push(cert);
        }

        Ok(certs)
    }

    fn read_crl_dir(path: &Path) -> Vec<CertificateList> {
        let entries = match read_dir(path) {
            Ok(entries) => entries,
            Err(err) => {
                trace!("Cannot read CRL directory {}: {}", path.display(), err);
                return Vec::new();
            }
        };

        let mut crls = Vec::new();
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    trace!(
                        "Cannot read CRL directory entry from {}: {}",
                        path.display(),
                        err
                    );
                    continue;
                }
            };
            let crl_path = entry.path();
            if !CertificateStore::is_der_or_pem_file(&crl_path) {
                continue;
            }

            match CertificateStore::read_crl(&crl_path) {
                Ok(crl) => crls.push(crl),
                Err(err) => {
                    trace!("Cannot read CRL {}: {}", crl_path.display(), err);
                }
            }
        }
        crls
    }

    fn read_crl(path: &Path) -> Result<CertificateList, String> {
        let crl = std::fs::read(path)
            .map_err(|_| format!("Could not read bytes from CRL file {}", path.display()))?;

        match path.extension().and_then(|extension| extension.to_str()) {
            Some("der") => CertificateList::from_der(&crl),
            Some("pem") => CertificateStore::read_pem_crl(&crl),
            _ => return Err("Only .der and .pem CRLs are supported".to_string()),
        }
        .map_err(|_| format!("Could not read CRL from CRL file {}", path.display()))
    }

    fn read_pem_crl(crl: &[u8]) -> Result<CertificateList, x509_cert::der::Error> {
        let mut reader = x509_cert::der::PemReader::new(crl)?;
        let crl = CertificateList::decode(&mut reader)?;
        reader.finish(crl)
    }

    fn is_der_or_pem_file(path: &Path) -> bool {
        path.is_file()
            && matches!(
                path.extension().and_then(|extension| extension.to_str()),
                Some("der" | "pem")
            )
    }

    /// Writes bytes to file and returns the size written, or an error reason for failure.
    ///
    /// # Errors
    ///
    /// A string description of any failure
    ///
    fn write_to_file(bytes: &[u8], file_path: &Path, overwrite: bool) -> Result<usize, String> {
        if !overwrite && file_path.exists() {
            Err(format!(
                "File {} already exists and will not be overwritten. Enable overwrite to disable this safeguard.",
                file_path.display()
            ))
        } else {
            if let Some(parent) = file_path.parent() {
                CertificateStore::ensure_dir(parent)?;
            }
            match File::create(file_path) {
                Ok(mut file) => file
                    .write(bytes)
                    .map_err(|_| format!("Could not write bytes to file {}", file_path.display())),
                Err(_) => Err(format!("Could not create file {}", file_path.display())),
            }
        }
    }

    fn write_private_key_to_file(
        bytes: &[u8],
        file_path: &Path,
        overwrite: bool,
    ) -> Result<usize, String> {
        if !overwrite && file_path.exists() {
            Err(format!(
                "File {} already exists and will not be overwritten. Enable overwrite to disable this safeguard.",
                file_path.display()
            ))
        } else {
            if let Some(parent) = file_path.parent() {
                CertificateStore::ensure_dir(parent)?;
            }
            let mut options = OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            options.mode(0o600);
            match options.open(file_path) {
                Ok(mut file) => file
                    .write(bytes)
                    .map_err(|_| format!("Could not write bytes to file {}", file_path.display())),
                Err(_) => Err(format!("Could not create file {}", file_path.display())),
            }
        }
    }
}
