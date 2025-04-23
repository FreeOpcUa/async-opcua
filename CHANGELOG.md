# Changelog

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