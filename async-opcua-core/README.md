# Async OPC-UA Core

Part of [async-opcua](https://crates.io/crates/async-opcua), a general purpose OPC-UA library in rust.

This library contains common types used by the server and client parts of the `async-opcua` library.

You will typically use either the client or server, and rarely use this library directly.

`async-opcua-core` covers a few different areas of shared functionality.

 - The `RequestMessage` and `ResponseMessage` enums, which discriminate over the possible messages in an OPC-UA request and response.
 - Core message types such as `HelloMessage`, `AcknowledgeMessage`, `MessageChunk`, etc. and components of these.
 - The low-level implementation of the opc/tcp protocol.
 - The `SecureChannel` type, which uses [async-opcua-crypto](https://crates.io/crates/async-opcua-crypto) to encrypt OPC-UA messages.
