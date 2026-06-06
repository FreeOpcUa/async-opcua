# Async OPC-UA Crypto

Part of [async-opcua](https://crates.io/crates/async-opcua), a general purpose OPC-UA library in rust.

This defines common cryptographic tooling for the OPC-UA protocol using libraries from [Rust Crypto](https://github.com/rustcrypto).

Currently supported security policies:

 - `Basic256` (Deprecated)
 - `Basic128Rsa15` (Deprecated)
 - `Basic256Sha256` (Deprecated)
 - `Aes256Sha256RsaPss`
 - `Aes128Sha256Oaep`

There's also some general tooling for working with and generating X509 Certificates, as well as support for the _legacy_ password encryption/decryption scheme in OPC-UA.

You are unlikely to want to use this library directly, but it is used in both the server and client parts `async-opcua`.
