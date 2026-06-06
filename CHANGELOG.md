# Changelog

## [0.18.0] - 2026-02-24

Mostly bug fixes and refactoring, some of which is externally visible.

### Client

#### Fixed

 - Fix race condition when creating monitored items causing the first message to sometimes be missed.
 - Fix an error causing sequence numbers to get out of sync after a cancelled or timed out request.
 - Correctly accept values between 1 and 1024 for the initial sequence number from the server.

#### Changed

 - Refactor the internal transport representation and expose a generic `StreamTransport` and `StreamConnector` which can be used to build custom transports over OPC-UA binary.
 - The client event loop is now generic over the transport layer. Most usage should not be affected, but if you ever pass the event loop between functions you will need to change the signature.

#### Added

 - Expose `MonitoredItemMap` to make it possible to create custom subscription callbacks more easily.

### Common

#### Changed

 - Refactor crypto internals in preparation of ECC support. Unless you use the OPC-UA crypto primitives directly, this should not affect you at all.

## [0.17.1] - 2025-12-09

Fix to a critical issue in the client causing a busy-loop.

### Client

#### Fixed
 - Fixed issue causing a busy loop in the subscription event loop in the client.

## [0.17.0] - 2025-12-04

A number of important fixes, some affecting the core protocol. Improvements to codegen, support for reverse connect, and a few other features.

### Common

#### Fixed
 - Treat empty remote certificate as missing during channel establishment.
 - Treat empty as null in a few more cases. Some misbehaving clients or servers send empty values instead of null values, but we can treat them the same in a few cases.

#### Added
 - Add fallback type loader, enabled by default. This captures `ExtensionObject` payloads without a matching type loader.
 - Added `NodeIdRef` and use this in a few places that accept `NodeId`s. This lets you pass, for example, `(1, "hello")` as a node ID, instead of needing to construct an owned copy.
 - Add support for OPC-UA reverse connect.
 - Add support for environment variable expansion in config files.
 - Added a `ValueRank` type, which is convenient in both client and server applications.

### Client

#### Fixed
 - Fixed nonces created as part of CreateSession, which fixes support for SHA128 legacy encryption.
 - Correctly use `max_chunk_count` from config in the connection.
 - Fixed issue that caused a race condition during secure channel renewal.

#### Changed
 - Certain errors from the subscription event loop are now forwarded to the main event loop, meaning that subscriptions can act as a keep alive in some cases.

### Server

#### Fixed
 - Fixed issue causing the available sequence numbers sent to the client to not include the sequence number of the publish itself.

#### Added
 - Add support for OPC-UA reverse connect.

#### Changed
 - Delay notifications that arrived too early, to emulate actually sampling the data. This avoids losing information if values are reported irregularly.

### Codegen

#### Added
 - Correctly set `DefaultEncodingId` in nodeset code generation.
 - Add support for dependent nodesets during types codegen.

#### Removed
 - Removed unused functionality to load `documentation.csv` files as part of nodeset codegen.

## [0.16.0] - 2025-06-11

Various fixes and adjustments. Support for `IssuedToken` authentication and `OfType` event filters.

### Common

#### Changed
 - Improve logic for dealing with sequence numbers, and add internal support for the new kind of sequence numbers defined in recent versions of the OPC-UA standard.

#### Added
 - Added a comprehensive sample with multiple node managers to showcase more complex uses of the server SDK.
 - Option to enable lock tracing. Set the environment variable `OPCUA_TRACE_LOCKS` to enable. This can be useful for debugging deadlocks.

### Client

#### Added
 - Support for `IssuedToken` based authentication. Actually obtaining the token will require custom code.
 - Pause the publishing loop when receiving `BadNoSubscription` from the server. This typically happens due to a race-condition or an issue on the server.
 - The `OnSubscriptionNotificationCore` trait is used as a base for subscription notifications, making it possible to control, on a low-level, the exact behavior when a publish notification is received.

#### Changed
 - Ignore port when matching server endpoints, which better adheres to the standard and is in general more correct.
 - Make the subscription services stateless. This is a breaking change if you are using the low-level subscription services directly. They no longer require the session subscription state, instead assuming that the caller will correctly track state and produce publish requests.

### Server

#### Added
 - Support for `IssuedToken` based authentication, you will need to use a custom authenticator that does the necessary validation.
 - Support for the `OfType` operator in event subscriptions. This uses the `TypeTreeForUser`, so different users can see different type trees here too, like in other services.
 - Expose the `TcpConfig` and `CertificateValidation` structs in server config.

#### Fixed
 - Fixed a panic caused by updating a variable to a time _before_ the latest value while clients were subscribed to that value.
 - Fixed an issue where we would incorrectly increment subscription sequence numbers for keep-alive messages.

### Codegen

#### Changed
 - Infer namespace URIs from the schema instead of requiring them to be specified in config. This makes it easier to configure custom codegen, and is less likely to cause issues.

## [0.15.1] - 2025-04-23

Fix to a build issue in `types` when compiling with the `xml` feature but not the `json` feature,
or only `json` and not `xml`.

### Common

#### Fixed
 - Fix build of `async-opcua-types` when only one of the `json` or `xml` features are enabled.

## [0.15.0] - 2025-04-22

Further changes and polish of the library. This release adds more comprehensive support for XML and JSON encoding, fixes a few bugs, and improves the ergonomics of defining custom types on servers.

### Common

#### Added
 - Support for `StructureWithOptionalFields`
 - A common `OpcUaError` type used in a few places when parsing and building common types.
 - Support for `Unions` in encoding macros, when `Encodable/Decodable` are derived on rust enums.
 - Replace `FromXml` with `XmlEncodable` and `XmlDecodable`, adding full support for OPC-UA XML.
 - Support for XML in JSON and binary extension object payloads.
 - The `#[ua_encodable]` attribute macro, to automatically derive all the encodable traits with appropriate features.

#### Fixed
 - Fix issues related to unions in custom structs.
 - Properly clear padding in legacy encrypted token secrets.

#### Removed
 - The `console_logging` feature has been removed. You need to use a library like [env_logger](https://docs.rs/env_logger/latest/env_logger/) to enable logging instead.

### Server

#### Added
 - Implement a few more server diagnostics.

#### Fixed
 - Fix the data type of server capabilities, should be `u16`, not `u32`.
 - Make `NodeId::next_numneric` start at 1, not 0.

#### Changed
 - The simple node manager will now write values to memory if nodes are set to writable but no write callback is provided.
 - Logging now uses `tracing`. Behavior should be mostly the same, but if you want to have tracing on your server, it should now be much simpler to implement. We write tracing events to logging, so no additional action is necessary if you just want to log like before.

### Codegen

#### Added
 - Support for using `NodeSet2.xml` files for types codegen.
 - Better system for reusing XML files over different codegen targets.

#### Fixed
 - Numerous improvements to custom codegen.

#### Changed
 - Logging in `async-opcua-codegen` now uses `log`, enabled by default.

## [0.14.0] - 2025-01-22

First release of the async-opcua library. Version number picks up where this forked from opcua. This changelog is almost certainly incomplete, the library has in large part been rewritten.

### Common

#### Changed
 - The libraries are now named `async-opcua-*`. The root module is still `opcua`. Do not use this together with the old opcua library.
 - `ExtensionObject` is now stored as an extension of `dyn Any`.
 - We no longer depend on OpenSSL, all crypto is now done with pure rust crates.
 - Generated types and address space now targets OPC-UA version 1.05.
 - The library is separated into multiple crates. Most users should still just depend on the `async-opcua` crate with appropriate features.
 - A number of minor optimizations in the common comms layer.

#### Added
 - `async-opcua-xml`, a library for parsing a number of OPC-UA XML structures. Included in `async-opcua` if you enable the `xml` feature.
 - `async-opcua-macros`, a common macro library for `async-opcua`. Macros are re-exported depending on enabled features.
 - Basic support for custom structures.
 - Much more tooling around generated code, enough that it should be possible to implement a companion standard using the same tooling that generates the core address space. See [samples/custom-codegen](samples/custom-codegen).

#### Fixed
 - A number of deviations from the standard and other bugs related to generated types.
 - A few common issues in encoding, and opc/tcp.
 - Generated certificates are now fully compliant with the OPC-UA standard.

### Server

#### Changed
 - The server library is rewritten from scratch, and has a completely new interface. Instead of defining a single `AddressSpace` and simply mutating that, servers now define a number of `NodeManager`s which may present parts of the address space in different ways. The closest equivalent to the old behavior is adding a `SimpleNodeManager`. See [docs/server.md](docs/server.md) for details.
 - The server no longer automatically samples data from nodes. Instead, you must `notify` the server of changes to variables. The `SyncSampler` type can be used to do this with sampling, and the `SimpleNodeManager` does this automatically.
 - The server is now fully async, and does not define its own tokio runtime.

#### Added
 - It is now possible to define servers that are far more flexible than before, including storing the entire address space in databases or external systems, using notification-based mechanisms for notifications, etc.
 - Tools for managing the server runtime, including graceful shutdown notifying clients, tools for managing the service level, and more.

#### Removed
 - The web interface for the server has been completely removed.

### Client

#### Changed
 - The client is now fully async, and does not define its own tokio runtime. All services are async.

#### Added
 - The client is now able to efficiently restore subscriptions on reconnect. This can be turned off.
 - There are a few more configuration options.
 - A flexible system for request building, making it possible to automatically retry OPC-UA services.
 - A builder-pattern for creating OPC-UA connections, making the connection establishment part of the client more flexible.