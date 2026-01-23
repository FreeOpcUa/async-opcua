use std::fs::File;
use std::io::Write;

use opcua_types::StatusCode;

use crate::{
    aes::calculate_cipher_text_size,
    certificate_store::*,
    from_hex, hash,
    policy::rsa::{
        Aes128Sha256RsaOaep, OaepSha1, OaepSha256, Pkcs1v15, RsaAsymmetricEncryptionAlgorithm,
        RsaSecurityPolicy,
    },
    random,
    tests::{
        make_certificate_store, make_test_cert_1024, make_test_cert_2048, APPLICATION_HOSTNAME,
        APPLICATION_URI,
    },
    user_identity::{legacy_secret_decrypt, legacy_secret_encrypt},
    x509::{X509Data, X509},
    KeySize, PrivateKey, PublicKey, SecurityPolicy, SHA1_SIZE, SHA256_SIZE,
};

#[test]
fn create_cert() {
    let (x509, _) = make_test_cert_1024();
    let not_before = x509.not_before().unwrap().to_string();
    println!("Not before = {not_before}");
    let not_after = x509.not_after().unwrap().to_string();
    println!("Not after = {not_after}");
}

#[test]
fn ensure_pki_path() {
    let (tmp_dir, cert_store) = make_certificate_store();
    let pki = cert_store.pki_path.clone();
    for dirname in ["rejected", "trusted"].iter() {
        let mut subdir = pki.to_path_buf();
        subdir.push(dirname);
        assert!(subdir.exists());
    }
    drop(tmp_dir);
}

#[test]
fn create_own_cert_in_pki() {
    let args = X509Data {
        key_size: 2048,
        common_name: "x".to_string(),
        organization: "x.org".to_string(),
        organizational_unit: "x.org ops".to_string(),
        country: "EN".to_string(),
        state: "London".to_string(),
        alt_host_names: vec!["host1".to_string(), "host2".to_string()].into(),
        certificate_duration_days: 60,
    };

    let (tmp_dir, cert_store) = make_certificate_store();
    let result = cert_store.create_and_store_application_instance_cert(&args, false);
    assert!(result.is_ok());

    // Create again with no overwrite
    let result = cert_store.create_and_store_application_instance_cert(&args, false);
    assert!(result.is_err());

    // Create again with overwrite
    let result = cert_store.create_and_store_application_instance_cert(&args, true);
    assert!(result.is_ok());
    drop(tmp_dir)
}

#[test]
fn create_rejected_cert_in_pki() {
    let (tmp_dir, cert_store) = make_certificate_store();

    let (cert, _) = make_test_cert_1024();
    let result = cert_store.store_rejected_cert(&cert);
    assert!(result.is_ok());

    let path = result.unwrap();
    assert!(path.exists());
    drop(tmp_dir);
}

#[test]
fn test_and_reject_application_instance_cert() {
    let (tmp_dir, cert_store) = make_certificate_store();

    // Make an unrecognized cert
    let (cert, _) = make_test_cert_1024();
    let result = cert_store.validate_or_reject_application_instance_cert(
        &cert,
        SecurityPolicy::Basic128Rsa15,
        None,
        None,
    );
    assert!(result.is_err());

    drop(tmp_dir);
}

#[test]
fn test_and_trust_application_instance_cert() {
    let (tmp_dir, cert_store) = make_certificate_store();

    // Make a cert, write it to the trusted dir
    let (cert, _) = make_test_cert_1024();

    // Simulate user/admin copying cert to the trusted folder
    let der = cert.to_der().unwrap();
    let mut cert_trusted_path = cert_store.trusted_certs_dir();
    cert_trusted_path.push(CertificateStore::cert_file_name(&cert));
    {
        println!("Writing der file to {cert_trusted_path:?}");
        let mut file = File::create(cert_trusted_path).unwrap();
        assert!(file.write(&der).is_ok());
    }

    // Now validate the cert was stored properly
    let result = cert_store.validate_or_reject_application_instance_cert(
        &cert,
        SecurityPolicy::Basic128Rsa15,
        None,
        None,
    );
    assert!(result.is_ok());

    drop(tmp_dir);
}

#[test]
fn test_and_reject_thumbprint_mismatch() {
    let (tmp_dir, cert_store) = make_certificate_store();

    // Make two certs, write it to the trusted dir
    let (cert, _) = make_test_cert_1024();
    let (cert2, _) = make_test_cert_1024();

    // Simulate user/admin copying cert to the trusted folder and renaming it to cert2's name,
    // e.g. to trick the cert store to trust an untrusted cert
    let der = cert.to_der().unwrap();
    let mut cert_trusted_path = cert_store.trusted_certs_dir();
    cert_trusted_path.push(CertificateStore::cert_file_name(&cert2));
    {
        let mut file = File::create(cert_trusted_path).unwrap();
        assert!(file.write(&der).is_ok());
    }

    // Now validate the cert was rejected because the thumbprint does not match the one on disk
    let result = cert_store.validate_or_reject_application_instance_cert(
        &cert2,
        SecurityPolicy::Basic128Rsa15,
        None,
        None,
    );
    assert!(result.is_err());

    drop(tmp_dir);
}

fn test_asymmetric_encrypt_and_decrypt(
    cert: &X509,
    key: &PrivateKey,
    security_policy: SecurityPolicy,
    plaintext_size: usize,
) {
    let plaintext = (0..plaintext_size)
        .map(|i| (i % 256) as u8)
        .collect::<Vec<u8>>();

    let mut ciphertext = vec![0u8; plaintext_size + 8192];
    let mut plaintext2 = vec![0u8; plaintext_size + 8192];

    println!("Encrypt with security policy {security_policy:?}");
    println!("Encrypting data of length {plaintext_size}");
    let encrypted_size = security_policy
        .asymmetric_encrypt(&cert.public_key().unwrap(), &plaintext, &mut ciphertext)
        .unwrap();
    println!("Encrypted size = {encrypted_size}");
    println!("Decrypting cipher text back");
    let decrypted_size = security_policy
        .asymmetric_decrypt(key, &ciphertext[..encrypted_size], &mut plaintext2)
        .unwrap();
    println!("Decrypted size = {decrypted_size}");

    assert_eq!(plaintext_size, decrypted_size);
    assert_eq!(&plaintext[..], &plaintext2[..decrypted_size]);
}

#[test]
fn asymmetric_encrypt_and_decrypt() {
    let (cert, key) = make_test_cert_2048();
    // Try all security policies, ensure they encrypt / decrypt for various sizes
    for security_policy in &[
        SecurityPolicy::Basic128Rsa15,
        SecurityPolicy::Basic256,
        SecurityPolicy::Basic256Sha256,
        SecurityPolicy::Aes128Sha256RsaOaep,
        SecurityPolicy::Aes256Sha256RsaPss,
    ] {
        for data_size in &[0, 1, 127, 128, 129, 255, 256, 257, 13001] {
            test_asymmetric_encrypt_and_decrypt(&cert, &key, *security_policy, *data_size);
        }
    }
}

#[test]
fn test_calculate_cipher_text_size() {
    let (_, pkey) = make_test_cert_2048();
    let s = pkey.size();

    // Testing -11 bounds
    assert_eq!(calculate_cipher_text_size::<Pkcs1v15>(s, 1), 256);
    assert_eq!(calculate_cipher_text_size::<Pkcs1v15>(s, 245), 256);
    assert_eq!(calculate_cipher_text_size::<Pkcs1v15>(s, 246), 512);
    assert_eq!(calculate_cipher_text_size::<Pkcs1v15>(s, 255), 512);
    assert_eq!(calculate_cipher_text_size::<Pkcs1v15>(s, 256), 512);
    assert_eq!(calculate_cipher_text_size::<Pkcs1v15>(s, 512), 768);

    // Testing -42 bounds
    assert_eq!(calculate_cipher_text_size::<OaepSha1>(s, 1), 256);
    assert_eq!(calculate_cipher_text_size::<OaepSha1>(s, 214), 256);
    assert_eq!(calculate_cipher_text_size::<OaepSha1>(s, 215), 512);
    assert_eq!(calculate_cipher_text_size::<OaepSha1>(s, 255), 512);
    assert_eq!(calculate_cipher_text_size::<OaepSha1>(s, 256), 512);
    assert_eq!(calculate_cipher_text_size::<OaepSha1>(s, 512), 768);

    // Testing -66 bounds
    assert_eq!(calculate_cipher_text_size::<OaepSha256>(s, 1), 256);
    assert_eq!(calculate_cipher_text_size::<OaepSha256>(s, 190), 256);
    assert_eq!(calculate_cipher_text_size::<OaepSha256>(s, 191), 512);
    assert_eq!(calculate_cipher_text_size::<OaepSha256>(s, 255), 512);
    assert_eq!(calculate_cipher_text_size::<OaepSha256>(s, 256), 512);
    assert_eq!(calculate_cipher_text_size::<OaepSha256>(s, 512), 768);
}

#[test]
fn calculate_cipher_text_size2() {
    let (cert, private_key) = make_test_cert_1024();
    let public_key = cert.public_key().unwrap();

    fn inner_test<T: RsaAsymmetricEncryptionAlgorithm>(
        private_key: &PrivateKey,
        public_key: &PublicKey,
    ) {
        // The cipher text size function should report exactly the same value as the value returned
        // by encrypting bytes. This is especially important on boundary values.
        for src_len in 1..550 {
            let src = vec![127u8; src_len];

            // Encrypt the bytes to a dst buffer of the expected size with padding
            let expected_size = calculate_cipher_text_size::<T>(private_key.size(), src_len);
            let mut dst = vec![0u8; expected_size];
            let actual_size = public_key.public_encrypt::<T>(&src, &mut dst).unwrap();
            if expected_size != actual_size {
                println!(
                    "Expected size {expected_size} != actual size {actual_size} for src length {src_len}"
                );
                assert_eq!(expected_size, actual_size);
            }

            // Decrypt to be sure the data is same as input
            let mut src2 = vec![0u8; expected_size];
            let src2_len = private_key.private_decrypt::<T>(&dst, &mut src2).unwrap();
            assert_eq!(src_len, src2_len);
            assert_eq!(&src[..], &src[..src2_len]);
        }
    }

    inner_test::<Pkcs1v15>(&private_key, &public_key);
    inner_test::<OaepSha1>(&private_key, &public_key);
    inner_test::<OaepSha256>(&private_key, &public_key);
}

#[test]
fn sign_verify_sha1() {
    let (cert, private_key) = make_test_cert_2048();
    let public_key = cert.public_key().unwrap();

    let msg = b"Mary had a little lamb";
    let msg2 = b"It's fleece was white as snow";
    let mut signature = [0u8; 256];
    let signed_len = private_key.sign_sha1(msg, &mut signature).unwrap();

    assert_eq!(signed_len, 256);
    assert!(public_key.verify_sha1(msg, &signature).unwrap());
    assert!(!public_key.verify_sha1(msg2, &signature).unwrap());

    assert!(!public_key
        .verify_sha1(msg, &signature[..signature.len() - 1])
        .unwrap());
    signature[0] = !signature[0]; // bitwise not
    assert!(!public_key.verify_sha1(msg, &signature).unwrap());
}

#[test]
fn sign_verify_sha256() {
    let (cert, private_key) = make_test_cert_2048();

    let msg = b"Mary had a little lamb";
    let msg2 = b"It's fleece was white as snow";
    let mut signature = [0u8; 256];
    let signed_len = private_key.sign_sha256(msg, &mut signature).unwrap();

    assert_eq!(signed_len, 256);
    let public_key = cert.public_key().unwrap();

    assert!(public_key.verify_sha256(msg, &signature).unwrap());
    assert!(!public_key.verify_sha256(msg2, &signature).unwrap());

    assert!(!public_key
        .verify_sha256(msg, &signature[..signature.len() - 1])
        .unwrap());
    signature[0] = !signature[0]; // bitwise not
    assert!(!public_key.verify_sha256(msg, &signature).unwrap());
}

#[test]
fn sign_verify_sha256_pss() {
    let (cert, private_key) = make_test_cert_2048();

    let msg = b"Mary had a little lamb";
    let msg2 = b"It's fleece was white as snow";
    let mut signature = [0u8; 256];
    let signed_len = private_key.sign_sha256_pss(msg, &mut signature).unwrap();

    assert_eq!(signed_len, 256);
    let public_key = cert.public_key().unwrap();

    assert!(public_key.verify_sha256_pss(msg, &signature).unwrap());
    assert!(!public_key.verify_sha256_pss(msg2, &signature).unwrap());

    assert!(!public_key
        .verify_sha256_pss(msg, &signature[..signature.len() - 1])
        .unwrap());
    signature[0] = !signature[0]; // bitwise not
    assert!(!public_key.verify_sha256_pss(msg, &signature).unwrap());
}

#[test]
fn sign_hmac_sha1() {
    use crate::hash;

    let key = b"key";
    let data = b"";

    let mut signature_wrong_size = [0u8; SHA1_SIZE - 1];
    assert!(hash::hmac_sha1(key, data, &mut signature_wrong_size).is_err());

    let mut signature = [0u8; SHA1_SIZE];
    assert!(hash::hmac_sha1(key, data, &mut signature).is_ok());
    let expected = from_hex("f42bb0eeb018ebbd4597ae7213711ec60760843f");
    assert_eq!(&signature, &expected[..]);

    let data = b"The quick brown fox jumps over the lazy dog";
    assert!(hash::hmac_sha1(key, data, &mut signature).is_ok());
    let expected = from_hex("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
    assert_eq!(&signature, &expected[..]);

    assert!(hash::verify_hmac_sha1(key, data, &expected));
    assert!(!hash::verify_hmac_sha1(key, &data[1..], &expected));
}

#[test]
fn sign_hmac_sha256() {
    let key = b"key";
    let data = b"";

    let mut signature_wrong_size = [0u8; SHA256_SIZE - 1];
    assert!(hash::hmac_sha256(key, data, &mut signature_wrong_size).is_err());

    let mut signature = [0u8; SHA256_SIZE];

    assert!(hash::hmac_sha256(key, data, &mut signature).is_ok());

    let expected = from_hex("5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0");
    assert_eq!(&signature, &expected[..]);

    let data = b"The quick brown fox jumps over the lazy dog";
    assert!(hash::hmac_sha256(key, data, &mut signature).is_ok());
    let expected = from_hex("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
    assert_eq!(&signature, &expected[..]);

    assert!(hash::verify_hmac_sha256(key, data, &expected));
    assert!(!hash::verify_hmac_sha1(key, &data[1..], &expected));
}

#[test]
fn generate_nonce() {
    // Generate a random nonce through the function and ensure it is the expected length
    assert!(SecurityPolicy::None.random_nonce().is_null());
    assert_eq!(
        SecurityPolicy::Basic128Rsa15.random_nonce().as_ref().len(),
        16
    );
    assert_eq!(SecurityPolicy::Basic256.random_nonce().as_ref().len(), 32);
    assert_eq!(
        SecurityPolicy::Basic256Sha256.random_nonce().as_ref().len(),
        32
    );
}

#[test]
fn certificate_with_hostname_mismatch() {
    let (cert, _) = make_test_cert_2048();
    let wrong_host_name = format!("wrong_{APPLICATION_HOSTNAME}");

    // Create a certificate and ensure that when the hostname does not match, the verification fails
    // with the correct error
    let result = cert.is_hostname_valid(&wrong_host_name).unwrap_err();
    assert_eq!(result, StatusCode::BadCertificateHostNameInvalid);

    // Create a certificate and ensure that when the hostname does  match, the verification succeeds
    cert.is_hostname_valid(APPLICATION_HOSTNAME).unwrap();

    // Try a few times with different case
    cert.is_hostname_valid(&APPLICATION_HOSTNAME.to_string().to_uppercase())
        .unwrap();
    cert.is_hostname_valid(&APPLICATION_HOSTNAME.to_string().to_lowercase())
        .unwrap();
}

#[test]
fn certificate_with_application_uri_mismatch() {
    let (cert, _) = make_test_cert_2048();

    // Compare the certificate to the wrong application uri in the description, expect error
    let result = cert.is_application_uri_valid("urn:WrongURI").unwrap_err();
    assert_eq!(result, StatusCode::BadCertificateUriInvalid);

    // Compare the certificate to the correct application uri in the description, expect success
    cert.is_application_uri_valid(APPLICATION_URI).unwrap();
}

#[test]
fn encrypt_decrypt_password() {
    let password = String::from("abcdef123456");
    let nonce = random::byte_string(20);

    let (cert, pkey) = make_test_cert_1024();

    let secret = legacy_secret_encrypt(
        password.as_bytes(),
        nonce.as_ref(),
        &cert,
        SecurityPolicy::Aes128Sha256RsaOaep,
    )
    .unwrap();
    let password2 = legacy_secret_decrypt::<
        <Aes128Sha256RsaOaep as RsaSecurityPolicy>::AsymmetricEncryption,
    >(&secret, nonce.as_ref(), &pkey)
    .unwrap();

    assert_eq!(
        password,
        String::from_utf8(password2.value.unwrap()).unwrap()
    );
}
