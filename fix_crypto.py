import os

def fix_security_policy():
    path = "async-opcua-crypto/src/security_policy.rs"
    with open(path, "r") as f:
        content = f.read()
    
    # Remove crate::policy::aes:: prefix
    content = content.replace("crate::policy::aes::Basic128Rsa15", "Basic128Rsa15")
    content = content.replace("crate::policy::aes::Basic256", "Basic256")
    content = content.replace("crate::policy::aes::Aes128Sha256RsaOaep", "Aes128Sha256RsaOaep")
    content = content.replace("crate::policy::aes::Aes256Sha256RsaPss", "Aes256Sha256RsaPss")
    
    # Write back
    with open(path, "w") as f:
        f.write(content)

def fix_aes():
    path = "async-opcua-crypto/src/policy/aes.rs"
    with open(path, "r") as f:
        content = f.read()
    
    target = "/// HMAC-SHA1 signature algorithm\npub(crate) struct DsigHmacSha1;\nimpl AesSymmetricSignatureAlgorithm for DsigHmacSha1 {"
    replacement = "#[cfg(feature = \"legacy-crypto\")]\n/// HMAC-SHA1 signature algorithm\n#[cfg(feature = \"legacy-crypto\")]\npub(crate) struct DsigHmacSha1;\n#[cfg(feature = \"legacy-crypto\")]\nimpl AesSymmetricSignatureAlgorithm for DsigHmacSha1 {"
    content = content.replace(target, replacement)
    
    with open(path, "w") as f:
        f.write(content)

def fix_rsa():
    path = "async-opcua-crypto/src/policy/rsa.rs"
    with open(path, "r") as f:
        content = f.read()
    
    targets = [
        ("/// RSA-SHA1 asymmetric signature algorithm\npub(crate) struct DsigRsaSha1;\nimpl RsaAsymmetricSignatureAlgorithm for DsigRsaSha1 {",
         "#[cfg(feature = \"legacy-crypto\")]\n/// RSA-SHA1 asymmetric signature algorithm\n#[cfg(feature = \"legacy-crypto\")]\npub(crate) struct DsigRsaSha1;\n#[cfg(feature = \"legacy-crypto\")]\nimpl RsaAsymmetricSignatureAlgorithm for DsigRsaSha1 {"),
        
        ("/// Basic128Rsa15 security policy (deprecated in OPC UA 1.04)\n",
         "#[cfg(feature = \"legacy-crypto\")]\n/// Basic128Rsa15 security policy (deprecated in OPC UA 1.04)\n"),
        
        ("pub(crate) struct Basic128Rsa15;\nimpl RsaSecurityPolicy for Basic128Rsa15 {",
         "#[cfg(feature = \"legacy-crypto\")]\npub(crate) struct Basic128Rsa15;\n#[cfg(feature = \"legacy-crypto\")]\nimpl RsaSecurityPolicy for Basic128Rsa15 {"),
        
        ("/// Basic256 security policy (deprecated in OPC UA 1.04)\n",
         "#[cfg(feature = \"legacy-crypto\")]\n/// Basic256 security policy (deprecated in OPC UA 1.04)\n"),
        
        ("pub(crate) struct Basic256;\nimpl RsaSecurityPolicy for Basic256 {",
         "#[cfg(feature = \"legacy-crypto\")]\npub(crate) struct Basic256;\n#[cfg(feature = \"legacy-crypto\")]\nimpl RsaSecurityPolicy for Basic256 {"),
         
        ("/// PKCS1v15 asymmetric encryption algorithm\npub(crate) struct Pkcs1v15;\nimpl RsaAsymmetricEncryptionAlgorithm for Pkcs1v15 {",
         "#[cfg(feature = \"legacy-crypto\")]\n/// PKCS1v15 asymmetric encryption algorithm\n#[cfg(feature = \"legacy-crypto\")]\npub(crate) struct Pkcs1v15;\n#[cfg(feature = \"legacy-crypto\")]\nimpl RsaAsymmetricEncryptionAlgorithm for Pkcs1v15 {")
    ]
    
    for t, r in targets:
        content = content.replace(t, r)
        
    with open(path, "w") as f:
        f.write(content)

fix_security_policy()
fix_aes()
fix_rsa()
