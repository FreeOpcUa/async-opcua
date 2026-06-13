import re

path = "async-opcua-crypto/src/tests/crypto.rs"
with open(path, "r") as f:
    content = f.read()

# Let's completely wipe the first block of imports up to `fn create_cert` and rewrite it
end = content.find("#[test]\nfn create_cert()")

if end != -1:
    new_imports = """use std::fs::File;
use std::io::Write;

use opcua_types::StatusCode;

use crate::{
    aes::calculate_cipher_text_size,
    certificate_store::*,
    from_hex, hash,
    policy::rsa::{
        Aes128Sha256RsaOaep, OaepSha1, OaepSha256, RsaAsymmetricEncryptionAlgorithm,
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

#[cfg(feature = "legacy-crypto")]
use crate::policy::rsa::Pkcs1v15;

"""
    content = new_imports + content[end:]

with open(path, "w") as f:
    f.write(content)
