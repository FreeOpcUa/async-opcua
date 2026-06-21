use std::str::FromStr;

use crate::SecurityPolicy;

#[test]
fn is_deprecated() {
    // Deprecated
    #[cfg(feature = "legacy-crypto")]
    {
        assert!(SecurityPolicy::Basic256.is_deprecated());
        assert!(SecurityPolicy::Basic128Rsa15.is_deprecated());
    }
    // Not deprecated
    assert!(!SecurityPolicy::None.is_deprecated());
    assert!(!SecurityPolicy::Basic256Sha256.is_deprecated());
    assert!(!SecurityPolicy::Aes128Sha256RsaOaep.is_deprecated());
    assert!(!SecurityPolicy::Aes256Sha256RsaPss.is_deprecated());
    assert!(!SecurityPolicy::EccNistP256.is_deprecated());
    assert!(!SecurityPolicy::EccNistP384.is_deprecated());
}

#[test]
fn from_str() {
    // Invalid from_str
    assert_eq!(
        SecurityPolicy::from_str("").unwrap(),
        SecurityPolicy::Unknown
    );
    assert_eq!(
        SecurityPolicy::from_str("none").unwrap(),
        SecurityPolicy::Unknown
    );
    assert_eq!(
        SecurityPolicy::from_str(" None").unwrap(),
        SecurityPolicy::Unknown
    );
    assert_eq!(
        SecurityPolicy::from_str("Basic256 ").unwrap(),
        SecurityPolicy::Unknown
    );
    assert_eq!(
        SecurityPolicy::from_str("http://opcfoundation.org/UA/SecurityPolicy#").unwrap(),
        SecurityPolicy::Unknown
    );

    // Valid from str will take either the short name or the URI
    assert_eq!(
        SecurityPolicy::from_str("None").unwrap(),
        SecurityPolicy::None
    );
    assert_eq!(
        SecurityPolicy::from_str("http://opcfoundation.org/UA/SecurityPolicy#None").unwrap(),
        SecurityPolicy::None
    );
    #[cfg(feature = "legacy-crypto")]
    {
        assert_eq!(
            SecurityPolicy::from_str("Basic128Rsa15").unwrap(),
            SecurityPolicy::Basic128Rsa15
        );
        assert_eq!(
            SecurityPolicy::from_str("http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15")
                .unwrap(),
            SecurityPolicy::Basic128Rsa15
        );
        assert_eq!(
            SecurityPolicy::from_str("Basic256").unwrap(),
            SecurityPolicy::Basic256
        );
        assert_eq!(
            SecurityPolicy::from_str("http://opcfoundation.org/UA/SecurityPolicy#Basic256")
                .unwrap(),
            SecurityPolicy::Basic256
        );
    }
    #[cfg(not(feature = "legacy-crypto"))]
    {
        assert_eq!(
            SecurityPolicy::from_str("Basic128Rsa15").unwrap(),
            SecurityPolicy::Basic128Rsa15
        );
        assert_eq!(
            SecurityPolicy::from_str("Basic256").unwrap(),
            SecurityPolicy::Basic256
        );
    }
    assert_eq!(
        SecurityPolicy::from_str("Basic256Sha256").unwrap(),
        SecurityPolicy::Basic256Sha256
    );
    assert_eq!(
        SecurityPolicy::from_str("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256")
            .unwrap(),
        SecurityPolicy::Basic256Sha256
    );
    assert_eq!(
        SecurityPolicy::from_str("Aes128-Sha256-RsaOaep").unwrap(),
        SecurityPolicy::Aes128Sha256RsaOaep
    );
    assert_eq!(
        SecurityPolicy::from_str(
            "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
        )
        .unwrap(),
        SecurityPolicy::Aes128Sha256RsaOaep
    );
    assert_eq!(
        SecurityPolicy::from_str("Aes256-Sha256-RsaPss").unwrap(),
        SecurityPolicy::Aes256Sha256RsaPss
    );
    assert_eq!(
        SecurityPolicy::from_str("http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss")
            .unwrap(),
        SecurityPolicy::Aes256Sha256RsaPss
    );
    assert_eq!(
        SecurityPolicy::from_str("ECC_nistP256").unwrap(),
        SecurityPolicy::EccNistP256
    );
    assert_eq!(
        SecurityPolicy::from_str("http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256")
            .unwrap(),
        SecurityPolicy::EccNistP256
    );
    assert_eq!(
        SecurityPolicy::from_str("ECC_nistP384").unwrap(),
        SecurityPolicy::EccNistP384
    );
    assert_eq!(
        SecurityPolicy::from_str("http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP384")
            .unwrap(),
        SecurityPolicy::EccNistP384
    );
}

#[test]
fn to_uri() {
    assert_eq!(
        SecurityPolicy::None.to_uri(),
        "http://opcfoundation.org/UA/SecurityPolicy#None"
    );
    #[cfg(feature = "legacy-crypto")]
    {
        assert_eq!(
            SecurityPolicy::Basic128Rsa15.to_uri(),
            "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"
        );
        assert_eq!(
            SecurityPolicy::Basic256.to_uri(),
            "http://opcfoundation.org/UA/SecurityPolicy#Basic256"
        );
    }
    assert_eq!(
        SecurityPolicy::Basic256Sha256.to_uri(),
        "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
    );
    assert_eq!(
        SecurityPolicy::Aes128Sha256RsaOaep.to_uri(),
        "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
    );
    assert_eq!(
        SecurityPolicy::Aes256Sha256RsaPss.to_uri(),
        "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"
    );
    assert_eq!(
        SecurityPolicy::EccNistP256.to_uri(),
        "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256"
    );
    assert_eq!(
        SecurityPolicy::EccNistP384.to_uri(),
        "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP384"
    );
}

#[test]
fn is_valid_keylength() {
    #[cfg(feature = "legacy-crypto")]
    {
        assert!(SecurityPolicy::Basic128Rsa15.is_valid_keylength(1024));
        assert!(SecurityPolicy::Basic128Rsa15.is_valid_keylength(2048));
        assert!(!SecurityPolicy::Basic128Rsa15.is_valid_keylength(4096));
        assert!(!SecurityPolicy::Basic128Rsa15.is_valid_keylength(512));

        assert!(SecurityPolicy::Basic256.is_valid_keylength(1024));
        assert!(SecurityPolicy::Basic256.is_valid_keylength(2048));
        assert!(!SecurityPolicy::Basic256.is_valid_keylength(4096));
        assert!(!SecurityPolicy::Basic256.is_valid_keylength(512));
    }

    assert!(SecurityPolicy::Basic256Sha256.is_valid_keylength(2048));
    assert!(SecurityPolicy::Basic256Sha256.is_valid_keylength(4096));
    assert!(!SecurityPolicy::Basic256Sha256.is_valid_keylength(1024));
    assert!(!SecurityPolicy::Basic256Sha256.is_valid_keylength(8192));

    assert!(SecurityPolicy::Aes128Sha256RsaOaep.is_valid_keylength(2048));
    assert!(SecurityPolicy::Aes128Sha256RsaOaep.is_valid_keylength(4096));
    assert!(!SecurityPolicy::Aes128Sha256RsaOaep.is_valid_keylength(1024));
    assert!(!SecurityPolicy::Aes128Sha256RsaOaep.is_valid_keylength(8192));

    assert!(SecurityPolicy::Aes256Sha256RsaPss.is_valid_keylength(2048));
    assert!(SecurityPolicy::Aes256Sha256RsaPss.is_valid_keylength(4096));
    assert!(!SecurityPolicy::Aes256Sha256RsaPss.is_valid_keylength(1024));
    assert!(!SecurityPolicy::Aes256Sha256RsaPss.is_valid_keylength(8192));

    assert!(SecurityPolicy::EccNistP256.is_valid_keylength(256));
    assert!(!SecurityPolicy::EccNistP256.is_valid_keylength(384));
    assert!(SecurityPolicy::EccNistP384.is_valid_keylength(384));
    assert!(!SecurityPolicy::EccNistP384.is_valid_keylength(256));
}

#[test]
fn ecc_support_is_feature_gated() {
    assert_eq!(
        SecurityPolicy::EccNistP256.is_supported(),
        cfg!(feature = "ecc")
    );
    assert_eq!(
        SecurityPolicy::EccNistP384.is_supported(),
        cfg!(feature = "ecc")
    );
}

#[test]
fn ecc_policy_metadata() {
    assert_eq!(SecurityPolicy::EccNistP256.to_str(), "ECC_nistP256");
    assert_eq!(SecurityPolicy::EccNistP384.to_str(), "ECC_nistP384");
    assert_eq!(SecurityPolicy::EccNistP256.symmetric_signature_size(), 32);
    assert_eq!(SecurityPolicy::EccNistP384.symmetric_signature_size(), 48);
    assert_eq!(SecurityPolicy::EccNistP256.encrypting_key_length(), 16);
    assert_eq!(SecurityPolicy::EccNistP384.encrypting_key_length(), 32);
    assert_eq!(
        SecurityPolicy::EccNistP256.secure_channel_nonce_length(),
        64
    );
    assert_eq!(
        SecurityPolicy::EccNistP384.secure_channel_nonce_length(),
        96
    );
}
