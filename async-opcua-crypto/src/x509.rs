// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Wrapper for X509 certificates, and related tooling.

use std::{
    self,
    collections::HashSet,
    fmt::{self, Debug, Formatter},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    result::Result,
};

use chrono::{DateTime, Utc};
use tracing::{error, info, trace, warn};
type ChronoUtc = DateTime<Utc>;

use rsa::pkcs1v15;
use rsa::RsaPublicKey as RsaPublicKeyInner;
use x509_cert::{
    self as x509,
    der::{
        asn1::{Ia5String, OctetString},
        Encode,
    },
    ext::pkix::{
        name::GeneralName, AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
        SubjectKeyIdentifier,
    },
};

use x509::builder::Error as BuilderError;
use x509::ext::pkix::name as xname;

use opcua_types::{status_code::StatusCode, ApplicationDescription, ByteString, Error};

#[cfg(feature = "ecc")]
use crate::SecurityPolicy;
use crate::{KeySize, PrivateKey, PublicKey};

use super::{hostname, thumbprint::Thumbprint};

const DEFAULT_KEYSIZE: u32 = 2048;
const DEFAULT_COUNTRY: &str = "IE";
const DEFAULT_STATE: &str = "Dublin";

#[derive(Debug, Default)]
/// Alternate names for an X509 certificate.
pub struct AlternateNames {
    /// List of alternative names.
    pub names: x509::ext::pkix::SubjectAltName,
}

impl AlternateNames {
    /// Create a new `AlternateNames` struct with no contents.
    pub fn new() -> Self {
        use x509::ext::pkix::SubjectAltName;
        Self {
            names: SubjectAltName(xname::GeneralNames::new()),
        }
    }

    /// Create a new list of alternate names from a list of addresses.
    pub fn new_from_addresses(ads: Vec<String>) -> Self {
        let mut result = Self::new();
        result.add_addresses(&ads);
        result
    }

    /// `true` if no alternate names are added.
    pub fn is_empty(&self) -> bool {
        self.names.0.is_empty()
    }

    /// Number of alternate names added.
    pub fn len(&self) -> usize {
        self.names.0.len()
    }

    /// Add an IPV4 address as alternate name.
    pub fn add_ipv4(&mut self, ad: &std::net::Ipv4Addr) {
        if let Ok(v) = x509::der::asn1::OctetString::new(ad.octets()) {
            self.names.0.push(xname::GeneralName::IpAddress(v));
        }
    }

    /// Add an IPV6 address as alternate name.
    pub fn add_ipv6(&mut self, ad: &std::net::Ipv6Addr) {
        if let Ok(v) = x509::der::asn1::OctetString::new(ad.octets()) {
            self.names.0.push(xname::GeneralName::IpAddress(v))
        }
    }

    /// Add a DNS name as alternate name.
    pub fn add_dns(&mut self, v: impl AsRef<str>) {
        if let Ok(v) = x509::der::asn1::Ia5String::new(v.as_ref()) {
            self.names.0.push(xname::GeneralName::DnsName(v));
        }
    }

    /// Add an IP or hostname.
    pub fn add_address(&mut self, v: impl AsRef<str>) {
        let v = v.as_ref();
        {
            if let Ok(ip) = v.parse::<std::net::Ipv4Addr>() {
                self.add_ipv4(&ip);
                return;
            }
        }
        {
            if let Ok(r) = v.parse::<std::net::Ipv6Addr>() {
                self.add_ipv6(&r);
                return;
            }
        }
        self.add_dns(v);
    }

    /// Add a URI.
    pub fn add_uri(&mut self, v: &str) {
        if let Ok(uri) = Ia5String::new(v) {
            self.names
                .0
                .push(xname::GeneralName::UniformResourceIdentifier(uri));
        }
    }

    /// Add a list of addresses.
    pub fn add_addresses(&mut self, ads: &[String]) {
        ads.iter().for_each(|h| {
            self.add_address(h);
        })
    }

    fn convert_name(name: &x509::ext::pkix::name::GeneralName) -> Option<String> {
        match name {
            GeneralName::DnsName(val) => Some(val.to_string()),
            GeneralName::DirectoryName(val) => Some(val.to_string()),
            GeneralName::Rfc822Name(val) => Some(val.to_string()),
            GeneralName::UniformResourceIdentifier(val) => Some(val.to_string()),
            GeneralName::IpAddress(val) => {
                let bytes = val.as_bytes();
                match bytes.len() {
                    4 => bytes
                        .try_into()
                        .ok()
                        .map(|addr: [u8; 4]| Ipv4Addr::from(addr).to_string()),

                    16 => bytes
                        .try_into()
                        .ok()
                        .map(|addr: [u8; 16]| Ipv6Addr::from(addr).to_string()),
                    _ => None,
                }
            }

            _ => None,
        }
    }

    /// Iterate over all the registered names.
    pub fn iter(&self) -> impl Iterator<Item = String> + '_ {
        AlternateNamesStringIterator {
            source: &self.names.0,
            index: 0,
        }
    }
}

struct AlternateNamesStringIterator<'a> {
    source: &'a xname::GeneralNames,
    index: usize,
}

impl Iterator for AlternateNamesStringIterator<'_> {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.source.len() {
            let converted = self
                .source
                .get(self.index)
                .and_then(AlternateNames::convert_name);
            self.index += 1;

            match converted {
                None => Some("".to_string()),
                Some(val) => Some(val),
            }
        } else {
            None
        }
    }
}

impl From<Vec<String>> for AlternateNames {
    fn from(source: Vec<String>) -> Self {
        Self::new_from_addresses(source)
    }
}

/// Data for constructing an X509 certificate.
pub struct X509Data {
    /// Requested key size.
    pub key_size: u32,
    /// Certificate CN.
    pub common_name: String,
    /// Certificate organization.
    pub organization: String,
    /// Certificate organizational unit.
    pub organizational_unit: String,
    /// Certificate country.
    pub country: String,
    /// Certificate state.
    pub state: String,
    /// A list of alternate host names as text. The first entry is expected to be the application uri.
    /// The remainder are treated as IP addresses or DNS names depending on whether they parse as IPv4, IPv6 or neither.
    /// IP addresses are expected to be in their canonical form and you will run into trouble
    /// especially in IPv6 if they are not because string comparison may be used during validation.
    /// e.g. IPv6 canonical format shortens addresses by stripping leading zeros, sequences of zeros
    /// and using lowercase hex.
    pub alt_host_names: AlternateNames,
    /// The number of days the certificate is valid for, i.e. it will be valid from now until now + duration_days.
    pub certificate_duration_days: u32,
}

impl From<(ApplicationDescription, Option<Vec<String>>)> for X509Data {
    fn from(v: (ApplicationDescription, Option<Vec<String>>)) -> Self {
        let (application_description, addresses) = v;
        let application_uri = application_description.application_uri.as_ref();
        let mut alt_host_names = AlternateNames::new();
        Self::compute_alt_host_names(
            &mut alt_host_names,
            application_uri,
            addresses,
            true,
            true,
            true,
        );
        X509Data {
            key_size: DEFAULT_KEYSIZE,
            common_name: application_description.application_name.to_string(),
            organization: application_description.application_name.to_string(),
            organizational_unit: application_description.application_name.to_string(),
            country: DEFAULT_COUNTRY.to_string(),
            state: DEFAULT_STATE.to_string(),
            alt_host_names,
            certificate_duration_days: 365,
        }
    }
}

impl From<ApplicationDescription> for X509Data {
    fn from(v: ApplicationDescription) -> Self {
        X509Data::from((v, None))
    }
}

impl X509Data {
    /// Gets a list of possible dns hostnames for this device
    pub fn computer_hostnames() -> Vec<String> {
        let mut result = Vec::with_capacity(2);

        if let Ok(hostname) = hostname() {
            if !hostname.is_empty() {
                result.push(hostname);
            }
        }
        if result.is_empty() {
            // Look for environment vars
            if let Ok(machine_name) = std::env::var("COMPUTERNAME") {
                result.push(machine_name);
            }
            if let Ok(machine_name) = std::env::var("NAME") {
                result.push(machine_name);
            }
        }

        result
    }

    /// Create `AlternateNames` from the current host and application URI, with
    /// an optional extra list of addresses.
    pub fn alt_host_names(
        application_uri: &str,
        addresses: Option<Vec<String>>,
        add_localhost: bool,
        add_computer_name: bool,
        add_ip_addresses: bool,
    ) -> AlternateNames {
        let mut result = AlternateNames::new();
        Self::compute_alt_host_names(
            &mut result,
            application_uri,
            addresses,
            add_localhost,
            add_computer_name,
            add_ip_addresses,
        );
        result
    }

    /// Creates a list of uri + DNS hostnames using the supplied arguments
    fn compute_alt_host_names(
        result: &mut AlternateNames,
        application_uri: &str,
        addresses: Option<Vec<String>>,
        add_localhost: bool,
        add_computer_name: bool,
        add_ip_addresses: bool,
    ) {
        // The first name is the application uri

        result.add_uri(application_uri);

        // Addresses supplied by caller
        if let Some(addresses) = addresses {
            result.add_addresses(&addresses);
        }

        // The remainder are alternative IP/DNS entries
        if add_localhost {
            result.add_address("localhost");
            if add_ip_addresses {
                result.add_address("127.0.0.1");
                result.add_address("::1");
            }
        }
        // Get the machine name / ip address
        if add_computer_name {
            let computer_hostnames = Self::computer_hostnames();
            if add_ip_addresses {
                let mut ipaddresses = HashSet::new();
                // Iterate hostnames, produce a set of ip addresses from lookup, using set to eliminate duplicates
                computer_hostnames.iter().for_each(|h| {
                    ipaddresses.extend(Self::ipaddresses_from_hostname(h));
                });
                result.add_addresses(&computer_hostnames);
                ipaddresses.iter().for_each(|v| {
                    result.add_address(v);
                });
            } else {
                result.add_addresses(&computer_hostnames);
            }
        }
    }

    /// Do a hostname lookup, find matching IP addresses
    fn ipaddresses_from_hostname(hostname: &str) -> Vec<String> {
        // Get ip addresses
        if let Ok(addresses) = (hostname, 0u16).to_socket_addrs() {
            addresses
                .map(|addr| match addr {
                    SocketAddr::V4(addr) => addr.ip().to_string(),
                    SocketAddr::V6(addr) => addr.ip().to_string(),
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Creates a sample certificate for testing, sample purposes only
    pub fn sample_cert() -> X509Data {
        let mut alt_host_names = AlternateNames::new();
        Self::compute_alt_host_names(&mut alt_host_names, "urn:OPCUADemo", None, true, true, true);
        X509Data {
            key_size: 2048,
            common_name: "OPC UA Demo Key".to_string(),
            organization: "OPC UA for Rust".to_string(),
            organizational_unit: "OPC UA for Rust".to_string(),
            country: DEFAULT_COUNTRY.to_string(),
            state: DEFAULT_STATE.to_string(),
            alt_host_names,
            certificate_duration_days: 365,
        }
    }
}

#[derive(Debug)]
/// Error returned when handling X509 certificates.
pub struct X509Error;

impl fmt::Display for X509Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "X509Error")
    }
}

impl std::error::Error for X509Error {}

impl From<x509::der::Error> for X509Error {
    fn from(_err: x509::der::Error) -> Self {
        X509Error
    }
}

#[derive(Clone)]
/// Wrapper around an X509 certificate.
pub struct X509 {
    value: x509::certificate::Certificate,
}

/// The signature and signature-algorithm of an X.509 certificate, as needed to
/// verify it against its issuer's public key.
#[derive(Debug, Clone)]
pub struct CertificateSignature {
    /// The raw signature octets (the certificate `signature` BIT STRING contents).
    pub value: Vec<u8>,
    /// The signature algorithm OID (e.g. sha256WithRSAEncryption, ecdsa-with-SHA256).
    pub algorithm_oid: const_oid::ObjectIdentifier,
    /// DER-encoded AlgorithmIdentifier parameters when present (e.g. RSASSA-PSS params).
    pub parameters: Option<Vec<u8>>,
}

impl Debug for X509 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // This impl will not write out the cert, and exists to keep derive happy
        // on structs that contain an X509 instance
        write!(f, "[x509]")
    }
}

impl X509 {
    /// Load an X509 certificate from a pem file.
    pub fn from_pem(data: &[u8]) -> Result<Self, X509Error> {
        use der::Decode;
        use der::Reader;
        use x509::der;

        let mut reader = der::PemReader::new(data)?;
        let val = x509::certificate::Certificate::decode(&mut reader)?;
        let valf = reader.finish(val)?;
        Ok(X509 { value: valf })

        //keep certificate chain for another story
        //let r = x509::certificate::Certificate::load_pem_chain(data);
    }

    /// Load an X509 certificate from a der file.
    pub fn from_der(data: &[u8]) -> Result<Self, X509Error> {
        use x509::der::Decode;

        let val = x509::certificate::Certificate::from_der(data)?;
        Ok(X509 { value: val })
    }

    /// Serialize the X509 file to a der file.
    pub fn to_der(&self) -> Result<Vec<u8>, X509Error> {
        use x509_cert::der::Encode;
        let data = self.value.to_der()?;
        Ok(data)

        /*
        let length = self.value.encoded_len()?;
        let size : u32 = length.into();

                let mut data: Vec<u8> = vec![0;size as usize];
                let mut slice =  x509::der::SliceWriter::new(&mut data);
                self.value.encode(&mut slice)?;
                Ok(data)
        */
    }

    /// Creates a self-signed X509v3 certificate and public/private key from the supplied creation args.
    /// The certificate identifies an instance of the application running on a host as well
    /// as the public key. The PKey holds the corresponding public/private key. Note that if
    /// the pkey is stored by cert store, then only the private key will be written. The public key
    /// is only ever stored with the cert.
    ///
    /// See Part 6 Table 23 for full set of requirements
    ///
    /// In particular, application instance cert requires subjectAltName to specify alternate
    /// hostnames / ip addresses that the host runs on.
    pub fn cert_and_pkey(x509_data: &X509Data) -> Result<(Self, PrivateKey), String> {
        // Create a key pair

        let pkey = PrivateKey::new(x509_data.key_size)
            .map_err(|e| format!("Failed to generate RSA private key: {e}"))?;

        // Create an X509 cert to hold the public key
        let cert = Self::from_pkey(&pkey, x509_data)?;

        Ok((cert, pkey))
    }

    /// Creates a self-signed EC X509v3 certificate and matching private key.
    #[cfg(feature = "ecc")]
    pub fn cert_and_pkey_ecc(
        curve: crate::ecc::EccCurve,
        x509_data: &X509Data,
    ) -> Result<(Self, PrivateKey), String> {
        match curve {
            crate::ecc::EccCurve::P256 => {
                let signer =
                    p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
                let scalar = signer.to_bytes();
                let private_key =
                    crate::ecc::EccPrivateKey::from_scalar_bytes(curve, scalar.as_slice())
                        .map(PrivateKey::from_ecc)
                        .map_err(|e| format!("Failed to generate P-256 private key: {e}"))?;
                let public_key =
                    x509_cert::spki::SubjectPublicKeyInfoOwned::from_key(*signer.verifying_key())
                        .map_err(|e| format!("Failed to encode P-256 public key: {e}"))?;
                let cert = Self::create_ec_certificate_with_signer::<_, p256::ecdsa::DerSignature>(
                    x509_data, public_key, &signer,
                )
                .map_err(Self::builder_error_to_string)?;
                Ok((cert, private_key))
            }
            crate::ecc::EccCurve::P384 => {
                let signer =
                    p384::ecdsa::SigningKey::random(&mut p384::elliptic_curve::rand_core::OsRng);
                let scalar = signer.to_bytes();
                let private_key =
                    crate::ecc::EccPrivateKey::from_scalar_bytes(curve, scalar.as_slice())
                        .map(PrivateKey::from_ecc)
                        .map_err(|e| format!("Failed to generate P-384 private key: {e}"))?;
                let public_key =
                    x509_cert::spki::SubjectPublicKeyInfoOwned::from_key(*signer.verifying_key())
                        .map_err(|e| format!("Failed to encode P-384 public key: {e}"))?;
                let cert = Self::create_ec_certificate_with_signer::<_, p384::ecdsa::DerSignature>(
                    x509_data, public_key, &signer,
                )
                .map_err(Self::builder_error_to_string)?;
                Ok((cert, private_key))
            }
        }
    }

    fn builder_error_to_string(e: BuilderError) -> String {
        match e {
            BuilderError::Asn1(_) => "Invalid der".to_string(),
            BuilderError::PublicKey(_) => "Invalid public key".to_string(),
            BuilderError::Signature(_) => "Invalid signature".to_string(),
            _ => "Invalid".to_string(),
        }
    }

    fn append_to_name(name: &mut String, param: &str, data: &str) {
        if !data.is_empty() {
            if !name.is_empty() {
                name.push(',');
            }
            name.push_str(param);
            name.push('=');
            name.push_str(data);
        }
    }

    /// Create a certificate from a private key and certificate description.
    pub fn from_pkey(pkey: &PrivateKey, x509_data: &X509Data) -> Result<Self, String> {
        let result = Self::create_from_pkey(pkey, x509_data);

        match result {
            Ok(val) => Ok(val),
            Err(e) => Err(Self::builder_error_to_string(e)),
        }
    }

    #[cfg(feature = "ecc")]
    fn create_ec_certificate_with_signer<S, Sig>(
        x509_data: &X509Data,
        public_key: x509_cert::spki::SubjectPublicKeyInfoOwned,
        signer: &S,
    ) -> Result<Self, BuilderError>
    where
        S: x509_cert::spki::DynSignatureAlgorithmIdentifier + ecdsa::signature::Keypair,
        S::VerifyingKey: x509_cert::spki::EncodePublicKey,
        S: ecdsa::signature::Signer<Sig>,
        Sig: x509_cert::spki::SignatureBitStringEncoding,
    {
        use std::str::FromStr;
        use std::time::Duration;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;

        let validity = Validity::from_now(Duration::new(
            86400 * u64::from(x509_data.certificate_duration_days),
            0,
        ))?;

        let serial_number = SerialNumber::from(42u32);
        let mut issuer = String::new();
        Self::append_to_name(&mut issuer, "CN", &x509_data.common_name);
        Self::append_to_name(&mut issuer, "O", &x509_data.organization);
        Self::append_to_name(&mut issuer, "OU", &x509_data.organizational_unit);
        Self::append_to_name(&mut issuer, "C", &x509_data.country);
        Self::append_to_name(&mut issuer, "ST", &x509_data.state);
        let subject = Name::from_str(&issuer)?;

        let profile = Profile::Manual {
            issuer: Some(subject.clone()),
        };
        let ski = Self::subject_key_identifier_from_public_key(&public_key);
        let mut builder = CertificateBuilder::new(
            profile,
            serial_number.clone(),
            validity,
            subject.clone(),
            public_key,
            signer,
        )?;

        builder.add_extension(&x509::ext::pkix::SubjectKeyIdentifier(OctetString::new(
            ski.as_slice(),
        )?))?;
        builder.add_extension(&x509::ext::pkix::AuthorityKeyIdentifier {
            authority_cert_issuer: Some(vec![GeneralName::DirectoryName(subject)]),
            key_identifier: Some(OctetString::new(ski.as_slice())?),
            authority_cert_serial_number: Some(serial_number),
        })?;
        builder.add_extension(&x509::ext::pkix::BasicConstraints {
            ca: false,
            path_len_constraint: None,
        })?;

        {
            use x509::ext::pkix::KeyUsage;
            use x509::ext::pkix::KeyUsages;

            let key_usage = KeyUsages::DigitalSignature | KeyUsages::NonRepudiation;
            builder.add_extension(&KeyUsage(key_usage))?;
        }

        {
            use x509::ext::pkix::ExtendedKeyUsage;
            let usage = vec![
                const_oid::db::rfc5280::ID_KP_CLIENT_AUTH,
                const_oid::db::rfc5280::ID_KP_SERVER_AUTH,
            ];
            builder.add_extension(&ExtendedKeyUsage(usage))?;
        }

        if !x509_data.alt_host_names.is_empty() {
            builder.add_extension(&x509_data.alt_host_names.names)?;
        }

        Ok(X509 {
            value: builder.build::<Sig>()?,
        })
    }

    #[cfg(feature = "ecc")]
    fn subject_key_identifier_from_public_key(
        public_key: &x509_cert::spki::SubjectPublicKeyInfoOwned,
    ) -> Vec<u8> {
        use sha1::Digest;

        let mut hasher = sha1::Sha1::new();
        hasher.update(public_key.subject_public_key.raw_bytes());
        hasher.finalize().to_vec()
    }

    fn create_from_pkey(pkey: &PrivateKey, x509_data: &X509Data) -> Result<Self, BuilderError> {
        use std::time::Duration;
        use x509_cert::builder::{CertificateBuilder, Profile};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;

        let pub_key;
        {
            let r = pkey.public_key_to_info();
            match r {
                Err(e) => return Err(BuilderError::PublicKey(e)),
                Ok(v) => pub_key = v,
            }
        }

        // Validity is built from a non-negative duration in whole days.
        #[allow(clippy::unwrap_used)]
        let validity = Validity::from_now(Duration::new(
            86400 * x509_data.certificate_duration_days as u64,
            0,
        ))
        .unwrap();

        let rsa_key = pkey
            .rsa_key_for_x509()
            .map_err(|_| BuilderError::PublicKey(x509_cert::spki::Error::KeyMalformed))?;
        let signing_key = pkcs1v15::SigningKey::<sha2::Sha256>::new(rsa_key.clone());

        let serial_number = SerialNumber::from(42u32);

        let subject;

        {
            let mut issuer = String::new();
            Self::append_to_name(&mut issuer, "CN", &x509_data.common_name);
            Self::append_to_name(&mut issuer, "O", &x509_data.organization);
            Self::append_to_name(&mut issuer, "OU", &x509_data.organizational_unit);
            Self::append_to_name(&mut issuer, "C", &x509_data.country);
            Self::append_to_name(&mut issuer, "ST", &x509_data.state);

            use std::str::FromStr;
            subject = Name::from_str(&issuer)?;
        }

        // Issuer and subject shall be the same for self-signed cert
        let profile = Profile::Manual {
            issuer: Some(subject.clone()),
        };

        // Generate a SKI, and set it as the AKI for the certificate according to Part 6, 6.2.2
        // Generation is as suggested in RFC3280, 4.2.1.2. A 160-bit SHA-1 hash of the public key bitstring.
        use sha1::Digest;
        let mut hasher = sha1::Sha1::new();
        // Public key info was produced from a valid in-memory RSA key above.
        #[allow(clippy::expect_used)]
        hasher.update(
            pub_key
                .subject_public_key
                .as_bytes()
                .expect("Invalid public key"),
        );
        let ski = hasher.finalize();

        let mut builder = CertificateBuilder::new(
            profile,
            serial_number.clone(),
            validity,
            subject.clone(),
            pub_key,
            &signing_key,
        )?;

        // SHA-1 output is a valid ASN.1 octet string.
        #[allow(clippy::unwrap_used)]
        builder.add_extension(&x509::ext::pkix::SubjectKeyIdentifier(
            OctetString::new(ski.as_slice()).unwrap(),
        ))?;
        builder.add_extension(&x509::ext::pkix::AuthorityKeyIdentifier {
            authority_cert_issuer: Some(vec![GeneralName::DirectoryName(subject)]),
            // SHA-1 output is a valid ASN.1 octet string.
            #[allow(clippy::unwrap_used)]
            key_identifier: Some(OctetString::new(ski.as_slice()).unwrap()),
            authority_cert_serial_number: Some(serial_number),
        })?;
        builder.add_extension(&x509::ext::pkix::BasicConstraints {
            ca: false,
            path_len_constraint: None,
        })?;

        {
            use x509::ext::pkix::KeyUsage;
            use x509::ext::pkix::KeyUsages;

            let key_usage = KeyUsages::DigitalSignature
                | KeyUsages::NonRepudiation
                | KeyUsages::KeyEncipherment
                | KeyUsages::DataEncipherment
                | KeyUsages::KeyCertSign;
            builder.add_extension(&KeyUsage(key_usage))?;
        }

        {
            use x509::ext::pkix::ExtendedKeyUsage;
            let usage = vec![
                const_oid::db::rfc5280::ID_KP_CLIENT_AUTH,
                const_oid::db::rfc5280::ID_KP_SERVER_AUTH,
            ];
            builder.add_extension(&ExtendedKeyUsage(usage))?;
        }

        {
            if !x509_data.alt_host_names.is_empty() {
                builder.add_extension(&x509_data.alt_host_names.names)?;
            }
        }

        use x509_cert::builder::Builder;
        let built = builder.build()?;

        Ok(X509 { value: built })
    }

    /// Load a certificate from a der byte string.
    pub fn from_byte_string(data: &ByteString) -> Result<X509, Error> {
        if data.is_null_or_empty() {
            Err(Error::new(
                StatusCode::BadCertificateInvalid,
                "Cannot make certificate from null bytestring",
            ))
        } else {
            let Some(value) = data.value.as_ref() else {
                return Err(Error::new(
                    StatusCode::BadCertificateInvalid,
                    "Cannot make certificate from null bytestring",
                ));
            };
            let r = Self::from_der(value);
            match r {
                Err(e) => Err(Error::new(StatusCode::BadCertificateInvalid, e)),
                Ok(cert) => Ok(cert),
            }
        }
    }

    /// Returns a ByteString representation of the cert which is DER encoded form of X509v3
    pub fn as_byte_string(&self) -> ByteString {
        // Encoding an already parsed/generated certificate is an internal invariant.
        #[allow(clippy::unwrap_used)]
        let der = self.to_der().unwrap();
        ByteString::from(&der)
    }

    /// Try to get the public key from this certificate.
    pub fn public_key(&self) -> Result<PublicKey, Error> {
        use x509_cert::der::referenced::OwnedToRef;

        let spki = &self.value.tbs_certificate.subject_public_key_info;
        let r = RsaPublicKeyInner::try_from(spki.owned_to_ref());
        if let Ok(v) = r {
            return Ok(PublicKey::from_rsa(v));
        }

        #[cfg(feature = "ecc")]
        if let Some(curve) = Self::ec_curve_from_subject_public_key_info(spki)? {
            let key = crate::ecc::EccPublicKey::from_subject_public_key_info(curve, spki)?;
            return Ok(PublicKey::from_ecc(key));
        }

        Err(Error::new(
            StatusCode::BadCertificateInvalid,
            "certificate subject public key is not a supported RSA or EC key",
        ))
    }

    /// Returns the key length in bits (if possible)
    pub fn key_length(&self) -> Result<usize, X509Error> {
        let r = self.public_key();
        match r {
            Err(_) => Err(X509Error),
            Ok(v) => Ok(v.bit_length()),
        }
    }

    /// Ensures an EC certificate uses the curve required by the negotiated ECC policy.
    #[cfg(feature = "ecc")]
    pub fn ensure_curve_matches_policy(
        &self,
        security_policy: SecurityPolicy,
    ) -> Result<(), Error> {
        let expected_curve = match crate::ecc::EccCurve::from_security_policy(security_policy) {
            Ok(curve) => curve,
            Err(_) => return Ok(()),
        };

        let public_key = self.public_key()?;
        match public_key.ecc_curve() {
            Some(actual_curve) if actual_curve == expected_curve => Ok(()),
            Some(actual_curve) => Err(Error::new(
                StatusCode::BadSecurityChecksFailed,
                format!(
                    "certificate EC curve {actual_curve:?} does not match security policy {security_policy}"
                ),
            )),
            None => Err(Error::new(
                StatusCode::BadSecurityChecksFailed,
                format!(
                    "certificate public key has no EC curve for security policy {security_policy}"
                ),
            )),
        }
    }

    #[cfg(feature = "ecc")]
    fn ec_curve_from_subject_public_key_info(
        spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
    ) -> Result<Option<crate::ecc::EccCurve>, Error> {
        if spki.algorithm.oid != const_oid::db::rfc5912::ID_EC_PUBLIC_KEY {
            return Ok(None);
        }

        let Some(parameters) = spki.algorithm.parameters.as_ref() else {
            return Err(Error::new(
                StatusCode::BadCertificateInvalid,
                "EC SubjectPublicKeyInfo is missing named-curve parameters",
            ));
        };

        let curve_oid = parameters
            .decode_as::<const_oid::ObjectIdentifier>()
            .map_err(|err| {
                Error::new(
                    StatusCode::BadCertificateInvalid,
                    format!("EC SubjectPublicKeyInfo has invalid named-curve parameters: {err}"),
                )
            })?;

        match curve_oid {
            oid if oid == const_oid::db::rfc5912::SECP_256_R_1 => {
                Ok(Some(crate::ecc::EccCurve::P256))
            }
            oid if oid == const_oid::db::rfc5912::SECP_384_R_1 => {
                Ok(Some(crate::ecc::EccCurve::P384))
            }
            _ => Err(Error::new(
                StatusCode::BadCertificateInvalid,
                format!("unsupported EC certificate curve {curve_oid}"),
            )),
        }
    }

    fn get_subject_entry(&self, nid: const_oid::ObjectIdentifier) -> Result<String, X509Error> {
        for dn in self.value.tbs_certificate.subject.0.iter() {
            for tv in dn.0.iter() {
                if tv.oid == nid {
                    return Ok(tv.to_string());
                }
            }
        }

        Err(X509Error)
    }

    /// Produces a subject name string such as "CN=foo/C=IE"
    pub fn subject_name(&self) -> String {
        let r = self.value.tbs_certificate.subject.to_string();
        r.replace(";", "/")
    }

    /// Produces an issuer name string such as "CN=foo/C=IE".
    pub fn issuer_name(&self) -> String {
        let r = self.value.tbs_certificate.issuer.to_string();
        r.replace(";", "/")
    }

    /// Returns the certificate serial number bytes.
    pub fn serial_number(&self) -> Vec<u8> {
        self.value.tbs_certificate.serial_number.as_bytes().to_vec()
    }

    /// Returns the DER-encoded TBSCertificate signed bytes.
    pub fn tbs_der(&self) -> Result<Vec<u8>, Error> {
        self.value.tbs_certificate.to_der().map_err(|err| {
            Error::new(
                StatusCode::BadCertificateInvalid,
                format!("failed to encode TBSCertificate DER: {err}"),
            )
        })
    }

    /// Returns the certificate signature bytes, algorithm OID, and optional parameter DER.
    pub fn signature_and_algorithm(&self) -> Result<CertificateSignature, Error> {
        let Some(signature_bytes) = self.value.signature.as_bytes() else {
            return Err(Error::new(
                StatusCode::BadCertificateInvalid,
                "certificate signature bit string is not octet-aligned",
            ));
        };

        let algorithm_parameters_der = self
            .value
            .signature_algorithm
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.to_der().ok());

        Ok(CertificateSignature {
            value: signature_bytes.to_vec(),
            algorithm_oid: self.value.signature_algorithm.oid,
            parameters: algorithm_parameters_der,
        })
    }

    /// Returns the KeyUsage extension, when present and well-formed.
    pub fn key_usage(&self) -> Option<KeyUsage> {
        let r: Result<Option<(bool, KeyUsage)>, _> = self.value.tbs_certificate.get::<KeyUsage>();
        match r {
            Err(_) => None,
            Ok(option) => option.map(|(_critical, ext)| ext),
        }
    }

    /// Returns the ExtendedKeyUsage extension, when present and well-formed.
    pub fn extended_key_usage(&self) -> Option<ExtendedKeyUsage> {
        let r: Result<Option<(bool, ExtendedKeyUsage)>, _> =
            self.value.tbs_certificate.get::<ExtendedKeyUsage>();
        match r {
            Err(_) => None,
            Ok(option) => option.map(|(_critical, ext)| ext),
        }
    }

    /// Returns the BasicConstraints extension, when present and well-formed.
    pub fn basic_constraints(&self) -> Option<BasicConstraints> {
        let r: Result<Option<(bool, BasicConstraints)>, _> =
            self.value.tbs_certificate.get::<BasicConstraints>();
        match r {
            Err(_) => None,
            Ok(option) => option.map(|(_critical, ext)| ext),
        }
    }

    /// Returns the AuthorityKeyIdentifier key identifier bytes, when present and well-formed.
    pub fn authority_key_identifier(&self) -> Option<Vec<u8>> {
        let r: Result<Option<(bool, AuthorityKeyIdentifier)>, _> =
            self.value.tbs_certificate.get::<AuthorityKeyIdentifier>();
        match r {
            Err(_) => None,
            Ok(option) => match option {
                None => None,
                Some((_critical, ext)) => ext
                    .key_identifier
                    .map(|key_identifier| key_identifier.as_bytes().to_vec()),
            },
        }
    }

    /// Returns the SubjectKeyIdentifier bytes, when present and well-formed.
    pub fn subject_key_identifier(&self) -> Option<Vec<u8>> {
        let r: Result<Option<(bool, SubjectKeyIdentifier)>, _> =
            self.value.tbs_certificate.get::<SubjectKeyIdentifier>();
        match r {
            Err(_) => None,
            Ok(option) => match option {
                None => None,
                Some((_critical, ext)) => Some(ext.0.as_bytes().to_vec()),
            },
        }
    }

    /// Returns true when the issuer and subject distinguished names are structurally equal.
    pub fn is_self_signed(&self) -> bool {
        self.value.tbs_certificate.issuer == self.value.tbs_certificate.subject
    }

    /// Gets the common name out of the cert
    pub fn common_name(&self) -> Result<String, X509Error> {
        self.get_subject_entry(const_oid::db::rfc4519::COMMON_NAME)
    }

    /// Tests if the certificate is valid for the supplied time using the not before and not
    /// after values on the cert.
    pub fn is_time_valid(&self, now: &DateTime<Utc>) -> Result<(), Error> {
        // Issuer time
        let not_before = self.not_before();
        if let Ok(not_before) = not_before {
            if now.lt(&not_before) {
                error!("Certificate < before date)");
                return Err(Error::new(
                    StatusCode::BadCertificateTimeInvalid,
                    format!(
                        "Certificate not yet valid (valid from {not_before}, current time {now})",
                    ),
                ));
            }
        } else {
            // No before time
            error!("Certificate has no before date");
            return Err(Error::new(
                StatusCode::BadCertificateInvalid,
                "Certificate has no not_before date",
            ));
        }

        // Expiration time
        let not_after = self.not_after();
        if let Ok(not_after) = not_after {
            if now.gt(&not_after) {
                error!("Certificate has expired (> after date)");
                return Err(Error::new(
                    StatusCode::BadCertificateTimeInvalid,
                    format!("Certificate has expired (valid to {not_after}, current time {now})"),
                ));
            }
        } else {
            // No after time
            error!("Certificate has no after date");
            return Err(Error::new(
                StatusCode::BadCertificateInvalid,
                "Certificate has no not_after date",
            ));
        }

        trace!("Certificate is valid for this time");
        Ok(())
    }

    fn get_alternate_names(&self) -> Option<x509::ext::pkix::name::GeneralNames> {
        use x509::ext::pkix::SubjectAltName;

        let r: Result<Option<(bool, SubjectAltName)>, _> = self.value.tbs_certificate.get();
        match r {
            Err(_) => None,
            Ok(option) => match option {
                None => None,
                Some(v) => {
                    Some(v.1 .0) //the second field of option (ie SubjectAltName) then the first field
                }
            },
        }
    }

    /// Tests if the supplied hostname matches any of the dns alt subject name entries on the cert
    pub fn is_hostname_valid(&self, hostname: &str) -> Result<(), Error> {
        trace!("is_hostname_valid against {} on cert", hostname);
        // Look through alt subject names for a matching entry
        if hostname.is_empty() {
            error!("Hostname is empty");
            Err(Error::new(
                StatusCode::BadCertificateHostNameInvalid,
                "Certificate hostname is empty",
            ))
        } else if let Some(subject_alt_names) = self.get_alternate_names() {
            let found = subject_alt_names
                .iter()
                .skip(1) //skip the application uri
                .any(|n| {
                    let name = AlternateNames::convert_name(n);
                    match name {
                        Some(val) => val.eq_ignore_ascii_case(hostname),
                        _ => false,
                    }
                });
            if found {
                info!("Certificate host name {} is good", hostname);
                Ok(())
            } else {
                warn!("Did not find hostname {hostname} in alt names {subject_alt_names:?}");
                Err(Error::new(StatusCode::BadCertificateHostNameInvalid, format!("Certificate hostname ({hostname}) not found in alt names ({subject_alt_names:?})")))
            }
        } else {
            // No alt names
            error!("Cert has no subject alt names at all");
            Err(Error::new(
                StatusCode::BadCertificateHostNameInvalid,
                "Certificate has no subject alt names",
            ))
        }
    }

    /// Tests if the supplied application uri matches the uri alt subject name entry on the cert
    pub fn is_application_uri_valid(&self, application_uri: &str) -> Result<(), Error> {
        // Expecting the first subject alternative name to be a uri that matches with the supplied
        // application uri
        if let Some(alt_names) = self.get_alternate_names() {
            if !alt_names.is_empty() {
                let Some(first_alt_name) = alt_names.first() else {
                    error!("Cert has zero subject alt names");
                    return Err(Error::new(
                        StatusCode::BadCertificateUriInvalid,
                        "Certificate has no subject alt names",
                    ));
                };
                match AlternateNames::convert_name(first_alt_name) {
                    Some(val) => {
                        if val == application_uri {
                            Ok(())
                        } else {
                            error!(
                                "Application uri {} does not match first alt name {}",
                                application_uri, val
                            );
                            Err(Error::new(StatusCode::BadCertificateUriInvalid, format!("Application uri {application_uri} does not match first alt name {val}")))
                        }
                    }

                    _ => {
                        error!("Alternate name {:?} cannot be converted", first_alt_name);
                        Err(Error::new(
                            StatusCode::BadCertificateUriInvalid,
                            format!(
                                "Failed to convert certificate alt name {:?} to string",
                                first_alt_name
                            ),
                        ))
                    }
                }
            } else {
                error!("Cert has zero subject alt names");
                Err(Error::new(
                    StatusCode::BadCertificateUriInvalid,
                    "Certificate has no subject alt names",
                ))
            }
        } else {
            error!("Cert has no subject alt names at all");
            // No alt names
            Err(Error::new(
                StatusCode::BadCertificateUriInvalid,
                "Certificate has no subject alt names",
            ))
        }
    }

    /// OPC UA Part 6 MessageChunk structure
    ///
    /// The thumbprint is the SHA1 digest of the DER form of the certificate. The hash is 160 bits
    /// (20 bytes) in length and is sent in some secure conversation headers.
    ///
    /// The thumbprint might be used by the server / client for look-up purposes.
    pub fn thumbprint(&self) -> Thumbprint {
        use sha1::Digest;
        use x509_cert::der::Encode;

        // Encoding an already parsed/generated certificate is an internal invariant.
        #[allow(clippy::unwrap_used)]
        let der = self.value.to_der().unwrap();

        let mut hasher = sha1::Sha1::new();
        hasher.update(&der);
        let digest = hasher.finalize();
        // SHA-1 always returns exactly the 20 bytes required for an OPC UA thumbprint.
        #[allow(clippy::expect_used)]
        Thumbprint::new(&digest).expect("SHA-1 digest is 20 bytes")
    }

    /// Turn the Asn1 values into useful portable types
    pub fn not_before(&self) -> Result<ChronoUtc, X509Error> {
        let dur = self
            .value
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration();
        let r = ChronoUtc::from_timestamp_micros(dur.as_micros() as i64);
        match r {
            None => Err(X509Error),
            Some(val) => Ok(val),
        }
    }

    /// Turn the Asn1 values into useful portable types
    pub fn not_after(&self) -> Result<ChronoUtc, X509Error> {
        let dur = self
            .value
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration();
        let r = ChronoUtc::from_timestamp_micros(dur.as_micros() as i64);
        match r {
            None => Err(X509Error),
            Some(val) => Ok(val),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "ecc")]
    mod ec_fixtures {
        use std::{
            fs::File,
            io::Write,
            path::Path,
            str::FromStr,
            time::{Duration, SystemTime, UNIX_EPOCH},
        };

        use opcua_types::StatusCode;
        use rand::rngs::OsRng;
        use x509_cert::{
            builder::{Builder, CertificateBuilder, Profile},
            der::asn1::OctetString,
            ext::pkix::{
                AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
                SubjectKeyIdentifier,
            },
            name::Name,
            serial_number::SerialNumber,
            spki::SubjectPublicKeyInfoOwned,
            time::{Time, Validity},
        };

        use crate::{certificate_store::CertificateStore, ecc::EccCurve, KeySize, SecurityPolicy};

        use super::{AlternateNames, GeneralName, X509};

        const APPLICATION_URI: &str = "urn:test:ec-application";
        const APPLICATION_HOSTNAME: &str = "localhost";

        #[derive(Clone, Copy)]
        enum EcFixtureCurve {
            P256,
            P384,
        }

        impl EcFixtureCurve {
            fn ecc_curve(self) -> EccCurve {
                match self {
                    Self::P256 => EccCurve::P256,
                    Self::P384 => EccCurve::P384,
                }
            }

            fn matching_policy(self) -> SecurityPolicy {
                match self {
                    Self::P256 => SecurityPolicy::EccNistP256,
                    Self::P384 => SecurityPolicy::EccNistP384,
                }
            }

            fn mismatched_policy(self) -> SecurityPolicy {
                match self {
                    Self::P256 => SecurityPolicy::EccNistP384,
                    Self::P384 => SecurityPolicy::EccNistP256,
                }
            }

            fn name(self) -> &'static str {
                match self {
                    Self::P256 => "P-256",
                    Self::P384 => "P-384",
                }
            }
        }

        struct EcCertificateFixture {
            cert: X509,
            curve: EcFixtureCurve,
        }

        fn valid_ec_certificate(curve: EcFixtureCurve) -> EcCertificateFixture {
            EcCertificateFixture {
                cert: build_ec_certificate(curve, validity_from_now(60)),
                curve,
            }
        }

        fn expired_ec_certificate(curve: EcFixtureCurve) -> EcCertificateFixture {
            let not_before = UNIX_EPOCH + Duration::from_secs(1_000_000);
            let not_after = UNIX_EPOCH + Duration::from_secs(1_086_400);
            EcCertificateFixture {
                cert: build_ec_certificate(curve, validity_between(not_before, not_after)),
                curve,
            }
        }

        fn build_ec_certificate(curve: EcFixtureCurve, validity: Validity) -> X509 {
            match curve {
                EcFixtureCurve::P256 => {
                    let signer = p256::ecdsa::SigningKey::random(&mut OsRng);
                    let public_key =
                        SubjectPublicKeyInfoOwned::from_key(*signer.verifying_key()).unwrap();
                    build_certificate_with_signer::<_, p256::ecdsa::DerSignature>(
                        curve, validity, public_key, &signer,
                    )
                }
                EcFixtureCurve::P384 => {
                    let signer = p384::ecdsa::SigningKey::random(&mut OsRng);
                    let public_key =
                        SubjectPublicKeyInfoOwned::from_key(*signer.verifying_key()).unwrap();
                    build_certificate_with_signer::<_, p384::ecdsa::DerSignature>(
                        curve, validity, public_key, &signer,
                    )
                }
            }
        }

        fn build_certificate_with_signer<S, Sig>(
            curve: EcFixtureCurve,
            validity: Validity,
            public_key: SubjectPublicKeyInfoOwned,
            signer: &S,
        ) -> X509
        where
            S: x509_cert::spki::DynSignatureAlgorithmIdentifier + ecdsa::signature::Keypair,
            S::VerifyingKey: x509_cert::spki::EncodePublicKey,
            S: ecdsa::signature::Signer<Sig>,
            Sig: x509_cert::spki::SignatureBitStringEncoding,
        {
            let ski = subject_key_identifier(&public_key);
            let serial_number = match curve {
                EcFixtureCurve::P256 => SerialNumber::from(256u32),
                EcFixtureCurve::P384 => SerialNumber::from(384u32),
            };
            let subject =
                Name::from_str(&format!("CN=OPC UA EC {} Test,O=async-opcua", curve.name()))
                    .unwrap();
            let profile = Profile::Manual {
                issuer: Some(subject.clone()),
            };
            let mut builder = CertificateBuilder::new(
                profile,
                serial_number.clone(),
                validity,
                subject.clone(),
                public_key,
                signer,
            )
            .unwrap();

            builder
                .add_extension(&SubjectKeyIdentifier(
                    OctetString::new(ski.as_slice()).unwrap(),
                ))
                .unwrap();
            builder
                .add_extension(&AuthorityKeyIdentifier {
                    authority_cert_issuer: Some(vec![GeneralName::DirectoryName(subject)]),
                    key_identifier: Some(OctetString::new(ski.as_slice()).unwrap()),
                    authority_cert_serial_number: Some(serial_number),
                })
                .unwrap();
            builder
                .add_extension(&BasicConstraints {
                    ca: false,
                    path_len_constraint: None,
                })
                .unwrap();
            builder
                .add_extension(&KeyUsage(
                    KeyUsages::DigitalSignature | KeyUsages::NonRepudiation,
                ))
                .unwrap();
            builder
                .add_extension(&ExtendedKeyUsage(vec![
                    const_oid::db::rfc5280::ID_KP_CLIENT_AUTH,
                    const_oid::db::rfc5280::ID_KP_SERVER_AUTH,
                ]))
                .unwrap();

            let mut alt_names = AlternateNames::new();
            alt_names.add_uri(APPLICATION_URI);
            alt_names.add_dns(APPLICATION_HOSTNAME);
            builder.add_extension(&alt_names.names).unwrap();

            X509 {
                value: builder.build::<Sig>().unwrap(),
            }
        }

        fn subject_key_identifier(public_key: &SubjectPublicKeyInfoOwned) -> Vec<u8> {
            use sha1::Digest;

            let mut hasher = sha1::Sha1::new();
            hasher.update(public_key.subject_public_key.raw_bytes());
            hasher.finalize().to_vec()
        }

        fn validity_from_now(days: u64) -> Validity {
            Validity::from_now(Duration::from_secs(86_400 * days)).unwrap()
        }

        fn validity_between(not_before: SystemTime, not_after: SystemTime) -> Validity {
            Validity {
                not_before: Time::try_from(not_before).unwrap(),
                not_after: Time::try_from(not_after).unwrap(),
            }
        }

        fn make_certificate_store() -> (tempfile::TempDir, CertificateStore) {
            let tmp_dir = tempfile::Builder::new().prefix("ec-pki").tempdir().unwrap();
            let cert_store = CertificateStore::new(tmp_dir.path());
            cert_store.ensure_pki_path().unwrap();
            (tmp_dir, cert_store)
        }

        fn trust_cert(store: &CertificateStore, cert: &X509) {
            let mut cert_path = store.trusted_certs_dir();
            cert_path.push(CertificateStore::cert_file_name(cert));
            write_der(cert, &cert_path);
        }

        fn write_der(cert: &X509, path: &Path) {
            let mut file = File::create(path).unwrap();
            file.write_all(&cert.to_der().unwrap()).unwrap();
        }

        fn assert_ec_public_key_recognized(fixture: &EcCertificateFixture) {
            let public_key = fixture.cert.public_key().unwrap_or_else(|err| {
                panic!("EC {} public key should parse: {err}", fixture.curve.name())
            });
            assert_eq!(
                public_key.bit_length(),
                fixture.curve.ecc_curve().encoded_public_key_len() * 4
            );
            assert_eq!(fixture.cert.key_length().unwrap(), public_key.bit_length());
            assert_eq!(fixture.cert.thumbprint().value().len(), 20);
        }

        fn assert_trusted_validates(fixture: &EcCertificateFixture) {
            let (_tmp_dir, cert_store) = make_certificate_store();
            trust_cert(&cert_store, &fixture.cert);

            let result = cert_store.validate_or_reject_application_instance_cert(
                &fixture.cert,
                fixture.curve.matching_policy(),
                Some(APPLICATION_HOSTNAME),
                Some(APPLICATION_URI),
            );
            assert!(
                result.is_ok(),
                "trusted EC {} cert should validate: {result:?}",
                fixture.curve.name()
            );
        }

        #[test]
        fn ec_p256_application_certificate_public_key_and_thumbprint_are_recognized() {
            let fixture = valid_ec_certificate(EcFixtureCurve::P256);

            assert_ec_public_key_recognized(&fixture);
        }

        #[test]
        fn ec_p384_application_certificate_public_key_and_thumbprint_are_recognized() {
            let fixture = valid_ec_certificate(EcFixtureCurve::P384);

            assert_ec_public_key_recognized(&fixture);
        }

        #[test]
        fn ec_p256_trusted_application_certificate_validates() {
            let fixture = valid_ec_certificate(EcFixtureCurve::P256);

            assert_trusted_validates(&fixture);
        }

        #[test]
        fn ec_p384_trusted_application_certificate_validates() {
            let fixture = valid_ec_certificate(EcFixtureCurve::P384);

            assert_trusted_validates(&fixture);
        }

        #[test]
        fn ec_application_certificate_untrusted_is_rejected() {
            let (_tmp_dir, cert_store) = make_certificate_store();
            let fixture = valid_ec_certificate(EcFixtureCurve::P256);

            let err = cert_store
                .validate_or_reject_application_instance_cert(
                    &fixture.cert,
                    fixture.curve.matching_policy(),
                    None,
                    None,
                )
                .expect_err("untrusted EC certificate should be rejected");
            assert_eq!(err.status(), StatusCode::BadCertificateUntrusted);
        }

        #[test]
        fn ec_application_certificate_expired_is_rejected() {
            let (_tmp_dir, cert_store) = make_certificate_store();
            let fixture = expired_ec_certificate(EcFixtureCurve::P384);
            trust_cert(&cert_store, &fixture.cert);

            let err = cert_store
                .validate_or_reject_application_instance_cert(
                    &fixture.cert,
                    fixture.curve.matching_policy(),
                    None,
                    None,
                )
                .expect_err("expired EC certificate should be rejected");
            assert_eq!(err.status(), StatusCode::BadCertificateTimeInvalid);
        }

        #[test]
        fn ec_p256_certificate_rejected_for_ecc_nist_p384_policy() {
            assert_curve_policy_mismatch_is_rejected(valid_ec_certificate(EcFixtureCurve::P256));
        }

        #[test]
        fn ec_p384_certificate_rejected_for_ecc_nist_p256_policy() {
            assert_curve_policy_mismatch_is_rejected(valid_ec_certificate(EcFixtureCurve::P384));
        }

        fn assert_curve_policy_mismatch_is_rejected(fixture: EcCertificateFixture) {
            let (_tmp_dir, cert_store) = make_certificate_store();
            trust_cert(&cert_store, &fixture.cert);

            let err = cert_store
                .validate_or_reject_application_instance_cert(
                    &fixture.cert,
                    fixture.curve.mismatched_policy(),
                    None,
                    None,
                )
                .expect_err("EC certificate curve should be rejected for mismatched ECC policy");
            assert_eq!(err.status(), StatusCode::BadSecurityChecksFailed);
            assert!(
                err.to_string().to_ascii_lowercase().contains("curve"),
                "mismatch should be reported as an EC curve/policy failure, got: {err}"
            );
        }
    }

    /*
        #[test]
        fn parse_asn1_date_test() {
            use chrono::{Datelike, Timelike};

            assert!(X509::parse_asn1_date("").is_err());
            assert!(X509::parse_asn1_date("Jan 69 00:00:00 1970").is_err());
            assert!(X509::parse_asn1_date("Feb 21 00:00:00 1970").is_ok());
            assert!(X509::parse_asn1_date("Feb 21 00:00:00 1970 GMT").is_ok());

            let dt: DateTime<Utc> = X509::parse_asn1_date("Feb 21 12:45:30 1999 GMT").unwrap();
            assert_eq!(dt.month(), 2);
            assert_eq!(dt.day(), 21);
            assert_eq!(dt.hour(), 12);
            assert_eq!(dt.minute(), 45);
            assert_eq!(dt.second(), 30);
            assert_eq!(dt.year(), 1999);
        }
    */

    /// This test checks that a cert will validate dns or ip entries in the subject alt host names
    #[test]
    fn alt_hostnames() {
        let mut alt_host_names = AlternateNames::new();
        alt_host_names.add_dns("uri:foo"); //the application uri
        alt_host_names.add_address("host2");
        alt_host_names.add_address("www.google.com");
        alt_host_names.add_address("192.168.1.1");
        alt_host_names.add_address("::1");

        // Create a cert with alt hostnames which are both IP and DNS entries
        let args = X509Data {
            key_size: 2048,
            common_name: "x".to_string(),
            organization: "x.org".to_string(),
            organizational_unit: "x.org ops".to_string(),
            country: "EN".to_string(),
            state: "London".to_string(),
            alt_host_names,
            certificate_duration_days: 60,
        };

        let (x509, _pkey) = X509::cert_and_pkey(&args).unwrap();

        assert!(x509.is_hostname_valid("").is_err());
        assert!(x509.is_hostname_valid("uri:foo").is_err()); // The application uri should not be valid
        assert!(x509.is_hostname_valid("192.168.1.0").is_err());
        assert!(x509.is_hostname_valid("www.cnn.com").is_err());
        assert!(x509.is_hostname_valid("host1").is_err());

        args.alt_host_names.iter().skip(1).for_each(|n| {
            assert!(x509.is_hostname_valid(n.as_str()).is_ok());
        })
    }
}
