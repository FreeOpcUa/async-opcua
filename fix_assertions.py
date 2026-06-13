import re

path = "async-opcua-crypto/src/tests/crypto.rs"
with open(path, "r") as f:
    content = f.read()

content = content.replace(
    "    // Testing -11 bounds\n    assert_eq!(calculate_cipher_text_size::<Pkcs1v15>(s, 1), 256);\n    assert_eq!(calculate_cipher_text_size::<Pkcs1v15>(s, 245), 256);\n    assert_eq!(calculate_cipher_text_size::<Pkcs1v15>(s, 246), 512);\n    assert_eq!(calculate_cipher_text_size::<Pkcs1v15>(s, 255), 512);\n    assert_eq!(calculate_cipher_text_size::<Pkcs1v15>(s, 256), 512);\n    assert_eq!(calculate_cipher_text_size::<Pkcs1v15>(s, 512), 768);",
    "    #[cfg(feature = \"legacy-crypto\")]\n    {\n        assert_eq!(calculate_cipher_text_size::<Pkcs1v15>(s, 1), 256);\n        assert_eq!(calculate_cipher_text_size::<Pkcs1v15>(s, 245), 256);\n        assert_eq!(calculate_cipher_text_size::<Pkcs1v15>(s, 246), 512);\n        assert_eq!(calculate_cipher_text_size::<Pkcs1v15>(s, 255), 512);\n        assert_eq!(calculate_cipher_text_size::<Pkcs1v15>(s, 256), 512);\n        assert_eq!(calculate_cipher_text_size::<Pkcs1v15>(s, 512), 768);\n    }"
)

content = content.replace("    inner_test::<Pkcs1v15>(&private_key, &public_key);", "    #[cfg(feature = \"legacy-crypto\")]\n    inner_test::<Pkcs1v15>(&private_key, &public_key);")

content = content.replace("    assert!(!hash::verify_hmac_sha1(key, &data[1..], &expected));", "    #[cfg(feature = \"legacy-crypto\")]\n    assert!(!hash::verify_hmac_sha1(key, &data[1..], &expected));")
content = content.replace("    assert!(hash::verify_hmac_sha1(key, data, &expected));", "    #[cfg(feature = \"legacy-crypto\")]\n    assert!(hash::verify_hmac_sha1(key, data, &expected));")

# Also for diffie hellman
dh_path = "async-opcua-crypto/src/aes/diffie_hellman.rs"
with open(dh_path, "r") as f:
    dh_content = f.read()
dh_content = dh_content.replace("let mut exchange = RsaDiffieHellman::<Basic128Rsa15>::new();", "let mut exchange = RsaDiffieHellman::<crate::policy::rsa::Basic128Rsa15>::new();")
with open(dh_path, "w") as f:
    f.write(dh_content)

with open(path, "w") as f:
    f.write(content)
