# Encryption

Encryption in OPC UA for Rust is dictated by the specification, particularly:
 
* OPC UA Part 2 describes the security model, threats and objectives.
* OPC UA Part 6 describes the handshake and secure conversation mechanism.
* OPC UA Part 4 describes identity tokens and how UserNameIdentityTokens encrypt data according to security policy. 
* OPC UA Part 7 describes various security policies that a server / client may support.

This document summarizes what algorithms are used by the implementation and issues concerned with moving away from OpenSSL
to a pure Rust crypto library.

## async-opcua-crypto

OPC UA for Rust is implemented in various crates that encapsulate server, client and common code.

The crypto functionality is contained in the `async-opcua-crypto` crate that both the server and client depend on. This provides functions and wrappers that call various rust cryptography packages from the [`rustcrypto`](https://github.com/rustcrypto) project.

* [`hmac`](https://github.com/RustCrypto/MACs/tree/master/hmac)
* [`sha2`](https://github.com/RustCrypto/hashes/tree/master/sha2)
* [`sha1`](https://docs.rs/sha1/latest/sha1/), note that SHA-1 is considered broken, and OPC-UA methods using this are considered unsafe.
* [`cbc`](https://docs.rs/cbc/latest/cbc/) for Cipher Block Chaining encryption and decryption.
* [`aes`](https://docs.rs/aes/latest/aes/) for AES encryption.
* [`rsa`](https://docs.rs/rsa/latest/rsa/) for RSA encryption.
* [`rand`](https://docs.rs/rand/latest/rand/) for cryptographically secure random numbers.
* [`x509-cert`](https://docs.rs/x509-cert/latest/x509_cert/) for tools for working with X509 certificates.

## Security Profiles

OPC UA for Rust supports these OPC UA 1.03 security profiles:

* None - No encryption
* Basic128Rsa15 - AES-128 / SHA-1 / RSA-15
* Basic256 - AES-256 / SHA-1 / RSA-OAEP
* Basic256Sha256 - AES-256 / SHA-256 / RSA-OAEP

It also supports these OPC UA 1.04 policies. 

* Aes128-Sha256-RsaOaep - AES-128 / SHA-256 / RSA-OAEP (a replacement for Basic128Rsa15 with stronger hash & padding)
* Aes256-Sha256-RsaPss - AES256 / SHA-256 / RSA-OAEP with RSA-PSS for signature algorithm

OPC UA 1.04 deprecates Basic128Rsa15 and Basic256 due to perceived weaknesses with SHA-1.

## Deprecated (legacy) security policies

Basic128Rsa15 and Basic256 are compiled in by default (the `legacy-crypto`
feature of `async-opcua-crypto`, forwarded by the `async-opcua` umbrella),
but they are **disabled at runtime by default** and must be explicitly
enabled on each side:

* Servers: set `allow_legacy_crypto: true` in the server configuration (or
  `ServerBuilder::allow_legacy_crypto(true)`). Without it, configuring a
  legacy endpoint fails validation, legacy endpoints are not advertised via
  GetEndpoints, and OpenSecureChannel requests for a legacy policy are
  rejected with `BadSecurityPolicyRejected`.
* Clients: set `allow_legacy_crypto: true` in the client configuration (or
  `ClientBuilder::allow_legacy_crypto(true)`). Without it, connecting to a
  legacy endpoint fails before any network traffic with
  `BadSecurityPolicyRejected`.

Every connection actually established with a deprecated policy logs a
`warn!`-level deprecation message on both sides. Builds with
`default-features = false` exclude the legacy algorithms entirely; legacy
policies are still recognized by name so they can be rejected with proper
errors rather than panics.

## ECC (NIST) security policies

Behind the `ecc` feature, `async-opcua-crypto` also implements the elliptic-curve
security policies (pure Rust, RustCrypto — no OpenSSL/C):

* ECC_nistP256 - ECDH on P-256 / ECDSA / SHA-256 / AES-128
* ECC_nistP384 - ECDH on P-384 / ECDSA / SHA-384 / AES-256

For secure channels (Part 6 §6.8.1), `OpenSecureChannel` carries ephemeral EC
public keys in `ClientNonce` / `ServerNonce`; NIST curve points are encoded as
zero-padded big-endian `x || y`, and the ECDH shared secret feeds HKDF to derive
the same signing/encryption/IV material shape used by the existing symmetric
layer. After key derivation, ECC secure channels use the same AES-CBC + HMAC
message protection as RSA secure channels; only the handshake signature and key
agreement differ.

Security-review note: the ECC handshake/crypto path was reviewed against the
Part 6 key-agreement requirements, the ChannelThumbprint binding, certificate
curve matching, malformed point/signature rejection, and secret logging. The
path is covered by RFC/NIST vectors, loopback channel tests, negative tests, and
the `fuzz_comms` decode-path fuzz target. Third-party ECC wire interop remains a
documented gap until an open62541 or UA-.NETStandard ECC peer is available.

### Token EphemeralKey exchange (Part 6 §6.8.2)

To encrypt a `UserNameIdentityToken` / `IssuedIdentityToken` secret under an ECC
policy, the client and server must exchange ECC **EphemeralKeys**. Part 6 §6.8.2
notes the standard CreateSession/ActivateSession handshake has no field for this,
so the exchange is carried in the **`AdditionalHeader`** of the request/response
headers as an `AdditionalParametersType` name-value list (Part 6 Table 70):

* The client places `ECDHPolicyUri` (the chosen ECC policy) in the **request**
  `AdditionalHeader`.
* The server generates a fresh ephemeral key pair for that policy, signs the
  ephemeral public key with its application-instance certificate key (Part 4
  §7.15: the signature is over the publicKey bytes), and returns it as `ECDHKey`
  (`EphemeralKeyType`) in the **response** `AdditionalHeader`. An
  unsupported/invalid `ECDHPolicyUri` yields `Bad_SecurityPolicyRejected` in
  place of the key; a request with no `ECDHPolicyUri` leaves the header null and
  behaves exactly as before.
* The client verifies the `ECDHKey` signature against the server certificate,
  decodes the curve point, and retains the most-recent authentic server
  EphemeralKey.

At ActivateSession the server follows the §6.8.2 new-vs-retain rules
(`decide_ecdh_key_action`): a requested policy → a fresh signed key; absent +
unused prior key → retain it. The consumed-key anti-replay rule ("never accept
the same EphemeralKey twice") is enforced where the key is actually consumed to
decrypt a secret — the `EccEncryptedSecret` identity-token wrapping (Part 4
§7.40.2.5 / Part 6 §6.8.3), described next. RSA and `None` flows, and builds with
the `ecc` feature off, are unaffected.

### Encrypted identity-token secrets (`EccEncryptedSecret`, Part 4 §7.40.2.5)

Over an ECC policy a `UserNameIdentityToken` password (or `IssuedIdentityToken`
token data) is wrapped as an **`EccEncryptedSecret`** (Part 4 §7.40.2.5, Table 186)
rather than the legacy RSA-OAEP secret. The envelope is an ExtensionObject-framed
structure: a common header (`SecurityPolicyUri`, signing `Certificate`,
`SigningTime`), **unencrypted** `KeyData` (the sender + receiver EphemeralKey
public keys), an AES-CBC-encrypted payload (`Nonce`, `Secret`, padding), and a
trailing **asymmetric ECDSA `Signature`** over the whole envelope.

* **Key derivation (Part 6 §6.8.3)**: ECDH between the client and server
  EphemeralKeys (from the §6.8.2 exchange) → RFC 5869 HKDF with the salt
  `L | "opcua-secret" | SenderPublicKey | ReceiverPublicKey` → the AES
  `EncryptingKey` + `InitializationVector` (no derived signing key — integrity is
  the asymmetric signature). Hash and AES size are per curve: SHA-256 + AES-128-CBC
  for `ECC_nistP256`, SHA-384 + AES-256-CBC for `ECC_nistP384`.
* **Client** (`ecc_encrypt_secret`): generates a fresh sender EphemeralKey, derives
  the keys against the retained server `ECDHKey`, encrypts the secret bound to the
  **current server nonce**, and signs the envelope with the client
  ApplicationInstance certificate.
* **Server** (`ecc_decrypt_secret`): validates the signature **before** decrypting,
  checks the receiver key is its own EphemeralKey, derives the keys, decrypts,
  verifies padding, and checks the `Nonce` equals the session's current server
  nonce. Every failure returns a **single uniform error** (no padding/MAC/nonce
  oracle) and never panics on attacker-supplied bytes.
* **Anti-replay (Part 6 §6.8.2)**: the server marks its EphemeralKey *consumed*
  after a successful decrypt and rotates to a fresh key for the next activation
  (the §6.8.2 `decide_ecdh_key_action` lifecycle); the client retains the rotated
  key from the ActivateSession response. Together with the server-nonce binding, a
  captured secret cannot be replayed and the same EphemeralKey is never reused.

The legacy RSA secret path and the `None` policy are unchanged; all of the above is
behind the `ecc` feature.

## Hash

Hashing functions are used to produce message authentication codes and for signing / verification.

* SHA-1 - used to create a filename from an X509 certificate and for comparison purposes of the public key. Also used by signing / verification functions.
* SHA-2 - Used by signing / verification functions. Below it is referred to as SHA-256 because this is the variant used in OPC UA to create a 256-bit digest.

## Pseudo-random generator

OPC UA for Rust creates nonces through a secure random function provided by OpenSSL. OpenSSL in turn utilizes 
functions provided by the operating system that ensure sufficient entropy in their result. This is encapsulated by a
couple of functions:

* `rand::bytes()` fills a buffer with random values
* `rand::byte_string()` returns a `ByteString` with the number of bytes.

## Key derivation

Client and server derive session keys and initialization vectors by exchanging and feeding nonces
into a pseudo random function that generates a key that allows each to talk with the other.

* P_SHA-1 or P_SHA-256 via `hash::p_sha()` are used as pseudo random functions depending on security policy.

## Signing / Verification functions

Messages are signed / verified using a hash based message authentication code (HMAC) using either SHA-1 or SHA-256 according
to the security policy.

* HMAC_SHA1 - via `sha1::Sha1` and `hmac::Hmac`
* HMAC_SHA256 - via `sha2::Sha256` and `hmac::Hmac`

## Symmetric ciphers

Symmetric encryption uses AES with cipher-block-chaining and a key size according to the security policy.
CBC means each block is XOR'd with the previous block prior to encryption while the first block is made unique 
with an initialization vector that was created during key derivation.

* AES_128_CBC - via `AesKey`
* AES_256_CBC - via `AesKey`

## Asymmetric ciphers

Public / private keys are used for asymmetric encryption at a variety of key lengths especially during the handshake 
before symmetric encryption kicks in, but also when passing encrypted user-name password identity tokens to the server. 

OPC UA for Rust doesn't enforce a minimum key length although the OPC UA Specification refers to NIST when it suggests
no less than 1024 bits for the Basic128Rsa15 profile and 2048 bits or more for other profiles. It also recommends
that a key length of < 2048 bits be deprecated.

Private keys are stored in PEM and public certs are stored on disk in DER format and loaded into memory when required.

NOTE: Future impls may favour .pem for both certs & keys to allow for chained signing of certificates.

### Padding

Encrypted data is padded to randomly salt the message and make it harder to decrypt without the correct key.

* PKCS#1 1.5 is an older padding scheme.
* OAEP - Optimal Asymmetric Encryption Padding used by later versions of RSA
* RSA-PSS - Probabilistic Signature Scheme - a form of padding used when making signatures. 

OPC UA 1.04 introduced the Aes256-Sha256-RsaPss security profile that requires a RSA-PSS
padding scheme for signatures.

## X509 certificates

X509 certificates wrap an asymmetric public key with some meta information and a signature - the issuer, serial number, subject alternative names. The signature is either by the private key in the key pair (a self-signed cert) or by another certificate's private key. 

The biggest difficulty with OPC UA is that it needs the ability to:

* X509 v3 support
* Subject alt names including DNS and IP entries
* Create self-signed certificates (via the `certificate-creator` tool)
* Save/read ASCII armoured (PEM) certificate (and private key) from a buffer
* Verify a certificate's signature and contents (e.g. validity dates)
* Build and verify the CA signing chain to a trusted anchor, check certificate usage
  (KeyUsage/ExtendedKeyUsage), the negotiated security policy's signature algorithm and key length,
  and CRL revocation — per OPC UA Part 4 §6.1.3 (Table 100). See *Certificate validation* below.

### Certificate validation (Part 4 §6.1.3)

When validating a peer's application instance certificate (server validating the client cert, client
validating the server cert), the `CertificateStore` runs the Table 100 steps in order, each mapped to
its OPC UA status code: certificate structure, build chain, signature, security-policy check, trust
list, validity period, host name (server certs only), URI, certificate usage, find revocation list,
and revocation check. A certificate is trusted when it — or a CA in its chain — is in the trusted
list; a self-signed certificate placed directly in `trusted/` is its own anchor and remains valid
(existing deployments are unaffected). The chain pipeline is always on and is backward compatible.

Configuration:

* Revocation defaults to **lenient** (a CRL is consulted when present but not required). Set
  `require_certificate_revocation(true)` on the server or client builder to make a missing CRL for a
  CA fail validation (`Bad_Certificate…RevocationUnknown`).
* `check_time(false)` (server) / `verify_server_certs(false)` (client) suppress the validity-period
  step as before; `trust_client_certs` / `trust_server_certs` still auto-trust an unknown peer cert.

Pure-Rust only (no OpenSSL/C): chain, CRL, and supplied/stapled OCSP handling are built on `x509-cert`,
`x509-ocsp`, and the in-tree RSA and ECDSA verifiers. The `CertificateStore` does not perform live OCSP
fetching; it validates OCSP responses only when supplied to the chain-validation context. Certificate
validation failures emit the matching `AuditCertificate*` event subtype where the server has audit context.

### X509 Fields

X509 Certs are generated subject to the requirements of OPC UA which requires a serial number and the first alt subject name to be an application URI. Subsequent alt subjects can be IP or DNS entries of the host.

Ordinarily a valid self signed cert can be produced by using the `certificate-creator` tool.

## PKI infrastructure

All certificates and a server's private key are managed by the `CertificateStore`. Each cert and key is stored on disk in a PEM encoded file with different directories representing rejected and accepted certs. 
