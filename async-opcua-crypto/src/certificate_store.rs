// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! The certificate store holds and retrieves private keys and certificates from disk. It is responsible
//! for checking certificates supplied by the remote end to see if they are valid and trusted or not.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use tracing::{debug, error, info, trace, warn};

use opcua_types::status_code::StatusCode;

use super::{
    pkey::PrivateKey,
    security_policy::SecurityPolicy,
    x509::{X509Data, X509},
};

use rsa;
use x509_cert;

/// Default path to the applications own certificate
const OWN_CERTIFICATE_PATH: &str = "own/cert.der";
/// Default path to the applications own private key
const OWN_PRIVATE_KEY_PATH: &str = "private/private.pem";
/// The directory holding trusted certificates
const TRUSTED_CERTS_DIR: &str = "trusted";
/// The directory holding rejected certificates
const REJECTED_CERTS_DIR: &str = "rejected";

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
    trust_unknown_certs: bool,
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
            error!("Folder for storing certificates cannot be examined so server has no application instance certificate or private key.");
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
        let doc = pkey.to_der().unwrap();
        let pem = doc
            .to_pem(rsa::pkcs8::PrivateKeyInfo::PEM_LABEL, pkcs8::LineEnding::CR)
            .unwrap();
        let _ = CertificateStore::write_to_file(pem.as_bytes(), pkey_path, overwrite)?;
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
    ) -> Result<(), StatusCode> {
        self.validate_application_instance_cert(cert, security_policy, hostname, application_uri)
    }

    /// Ensures that the cert provided is the same as the one specified by a path. This is a
    /// security check to stop someone from renaming a cert on disk to match another cert and
    /// somehow bypassing or subverting a check. The disk cert must exactly match the memory cert
    /// or the test is assumed to fail.
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
    ) -> Result<(), StatusCode> {
        let cert_file_name = CertificateStore::cert_file_name(cert);
        debug!("Validating cert with name on disk {}", cert_file_name);

        // Look for the cert in the rejected folder. If it's rejected there is no purpose going
        // any further
        {
            let mut cert_path = self.rejected_certs_dir();
            if !cert_path.exists() {
                error!(
                    "Path for rejected certificates {} does not exist",
                    cert_path.display()
                );
                return Err(StatusCode::BadUnexpectedError);
            }
            cert_path.push(&cert_file_name);
            if cert_path.exists() {
                warn!(
                    "Certificate {} is untrusted because it resides in the rejected directory",
                    cert_file_name
                );
                return Err(StatusCode::BadSecurityChecksFailed);
            }
        }

        // Check the trusted folder. These checks are more strict to ensure the cert is genuinely
        // trusted
        {
            // Check the trusted folder
            let mut cert_path = self.trusted_certs_dir();
            if !cert_path.exists() {
                error!(
                    "Path for rejected certificates {} does not exist",
                    cert_path.display()
                );
                return Err(StatusCode::BadUnexpectedError);
            }
            cert_path.push(&cert_file_name);

            // Check if cert is in the trusted folder
            if !cert_path.exists() {
                // ... trust checks based on ca could be added here to add cert straight to trust folder
                if self.trust_unknown_certs {
                    // Put the unknown cert into the trusted folder
                    warn!("Certificate {} is unknown but policy will store it into the trusted directory", cert_file_name);
                    let _ = self.store_trusted_cert(cert);
                // Note that we drop through and still check the cert for validity
                } else {
                    warn!("Certificate {} is unknown and untrusted so it will be stored in rejected directory", cert_file_name);
                    let _ = self.store_rejected_cert(cert);
                    return Err(StatusCode::BadCertificateUntrusted);
                }
            }

            // Read the cert from the trusted folder to make sure it matches the one supplied
            if !CertificateStore::ensure_cert_and_file_are_the_same(cert, &cert_path) {
                error!("Certificate in memory does not match the one on disk {} so cert will automatically be treated as untrusted", cert_path.display());
                return Err(StatusCode::BadUnexpectedError);
            }

            // Check that the certificate is the right length for the security policy
            match cert.key_length() {
                Err(_) => {
                    error!("Cannot read key length from certificate {}", cert_file_name);
                    return Err(StatusCode::BadSecurityChecksFailed);
                }
                Ok(key_length) => {
                    if !security_policy.is_valid_keylength(key_length) {
                        warn!(
                            "Certificate {} has an invalid key length {} for the policy {}",
                            cert_file_name, key_length, security_policy
                        );
                        return Err(StatusCode::BadSecurityChecksFailed);
                    }
                }
            }

            if self.skip_verify_certs {
                debug!(
                    "Skipping additional verifications for certificate {}",
                    cert_file_name
                );
                return Ok(());
            }

            // Now inspect the cert not before / after values to ensure its validity
            if self.check_time {
                use chrono::Utc;
                let now = Utc::now();
                cert.is_time_valid(&now)?;
            }

            // Compare the hostname of the cert against the cert supplied
            if let Some(hostname) = hostname {
                cert.is_hostname_valid(hostname)?;
            }

            // Compare the application / product uri to the supplied application description
            if let Some(application_uri) = application_uri {
                cert.is_application_uri_valid(application_uri)?;
            }

            // Other tests that we might do with trust lists
            // ... issuer
            // ... trust (self-signed, ca etc.)
            // ... revocation
        }
        Ok(())
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
        let subdirs = [TRUSTED_CERTS_DIR, REJECTED_CERTS_DIR];
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
        let der = cert.to_der().unwrap();
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

        let mut file: File = file.unwrap();
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

    /// Writes bytes to file and returns the size written, or an error reason for failure.
    ///
    /// # Errors
    ///
    /// A string description of any failure
    ///
    fn write_to_file(bytes: &[u8], file_path: &Path, overwrite: bool) -> Result<usize, String> {
        if !overwrite && file_path.exists() {
            Err(format!("File {} already exists and will not be overwritten. Enable overwrite to disable this safeguard.", file_path.display()))
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
}
