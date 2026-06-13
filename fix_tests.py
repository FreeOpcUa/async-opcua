import re

def fix_diffie_hellman():
    path = "async-opcua-crypto/src/aes/diffie_hellman.rs"
    with open(path, "r") as f:
        content = f.read()
    
    content = content.replace("#[cfg(feature = \"legacy-crypto\")] policy::rsa::Basic128Rsa15, AesDerivedKeys,", "AesDerivedKeys,")
    content = content.replace("use crate::{", "#[cfg(feature = \"legacy-crypto\")]\n        use crate::policy::rsa::Basic128Rsa15;\n        use crate::{")
    
    with open(path, "w") as f:
        f.write(content)

def fix_crypto_tests():
    path = "async-opcua-crypto/src/tests/crypto.rs"
    with open(path, "r") as f:
        content = f.read()

    content = content.replace("#[cfg(feature = \"legacy-crypto\")] Pkcs1v15,\n        OaepSha1, OaepSha256, RsaAsymmetricEncryptionAlgorithm", "OaepSha1, OaepSha256, RsaAsymmetricEncryptionAlgorithm")
    content = content.replace("Aes128Sha256RsaOaep, OaepSha1, OaepSha256, RsaAsymmetricEncryptionAlgorithm,", "Aes128Sha256RsaOaep, OaepSha1, OaepSha256, RsaAsymmetricEncryptionAlgorithm,\n    };\n    #[cfg(feature = \"legacy-crypto\")]\n    use crate::policy::rsa::Pkcs1v15;\n    use crate::policy::rsa::{")
    
    with open(path, "w") as f:
        f.write(content)

fix_diffie_hellman()
fix_crypto_tests()
