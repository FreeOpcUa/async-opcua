# Async OPC-UA

This is an [OPC-UA](https://opcfoundation.org/about/opc-technologies/opc-ua/) server / client API implementation for Rust.

OPC-UA is an industry standard for information modeling and communication. It is used for control systems, IoT, etc.

The OPC-UA standard is very large and complex, and implementations are often flawed. The strictness of Rust makes it a good choice for implementing OPC-UA, and the performance characteristics are useful when creating OPC-UA tooling that will run in constrained environments.

Read the [compatibility](../docs/compatibility.md) page for how the implementation conforms with the OPC UA spec.

Read the [change log](../CHANGELOG.md) for changes per version as well as aspirational / upcoming work.

## This is a fork

This is a fork of [opcua](https://github.com/locka99/opcua) with a broader goal of a generic OPC-UA implementation and a number of different design decisions. See [fork.md](../docs/fork.md) for details on this decision and the differences between this library and the original.

# MSRV Policy

We target the latest `stable` rust compiler and make no promises of support for older rust versions. We have use for several recent and upcoming rust features so this is unlikely to change.

# License

The code is licenced under [MPL-2.0](https://opensource.org/licenses/MPL-2.0). Like all open source code, you use this code at your own risk.

# Documentation

Tutorials for using the server and client are available in the `async-opcua` github repo:

* [Client Tutorial](../docs/client.md)
* [Server Tutorial](../docs/server.md)
* [General documentation](../docs/opc_ua_overview.md)
* [Library design](../docs/design.md)

There are also generated API docs on crates.io.

# Features

* `all`, enables the `server` and `client` features.
* `server`, includes the server SDK.
* `base-server`, includes the server SDK, but without the core address space. Most users should use the `server` feature.
* `client`, includes the client SDK.
* `json`, adds support for OPC-UA JSON to generated types.
* `generated-address-space`, adds the core OPC-UA namespace. This is usually required for compliant OPC-UA servers.
* `discovery-server-registration`, allows the server to register itself with a local discovery server, by pulling in a client.
* `xml`, adds support for loading generated types from XML, and for loading `NodeSet2.xml` files.

By default, no features are enabled, so only core types and functionality is pulled in. You will typically want to enable either the `client` or `server` features.

# Crates

Note that this library is split into multiple different crates. OPC-UA is a complex standard, and implementations typically involve a great deal of generated code. In order to allow good isolation of different components, and to speed up compile times, the `async-opcua` library is split into several crates.

* `async-opcua`, the general crate that most users will use as the entry point. Contains a few utilities, but mostly just re-exports the other crates. I.e. `async-opcua-types` is re-exported under `opcua::types`.
* [async-opcua-client](https://crates.io/crates/async-opcua-client) contains a fully featured OPC-UA client.
* [async-opcua-server](https://crates.io/crates/async-opcua-server) contains a flexible SDK for building OPC-UA servers.
* [async-opcua-core](https://crates.io/crates/async-opcua-core) contains common primitives and tools for implementing the OPC-UA communication protocol.
* [async-opcua-core-namespace](https://crates.io/crates/async-opcua-core-namespace) contains generated code for the entire OPC-UA core namespace.
* [async-opcua-crypto](https://crates.io/crates/async-opcua-crypto) contains common cryptographic tooling for the OPC-UA protocol using libraries from [Rust Crypto](https://github.com/rustcrypto).
* [async-opcua-macros](https://crates.io/crates/async-opcua-macros) contains a few macros used to create custom extensions to the OPC-UA standard.
* [async-opcua-nodes](https://crates.io/crates/async-opcua-nodes) contains an in-memory representation of OPC-UA nodes, used by the server.
* [async-opcua-types](https://crates.io/crates/async-opcua-types) contains the framework used by serialization and deserialization to OPC-UA Binary and JSON, and deserialization from OPC-UA XML. It also contains generated code defining types from the OPC-UA standard, and manual implementations of a number of core types.
* [async-opcua-xml](https://crates.io/crates/async-opcua-xml) contains an implementation of XML decoding for certain XML schemas relevant to OPC-UA.

# Samples

The `async-opcua` github repo contains a number of samples that may be used as reference when writing your own clients and servers.

1. [simple-server](../samples/simple-server) - an OPC-UA server that adds 4 variables v1, v2, v3 and v4 and updates them from a timer via push and pull mechanisms.
2. [simple-client](../samples/simple-client) - an OPC-UA client that connects to a server and subscribes to the values of v1, v2, v3 and v4.
3. [discovery-client](../samples/discovery-client) - an OPC-UA client that connects to a discovery server and lists the servers registered on it.
4. [chess-server](../samples/chess-server) - an OPC-UA server that connects to a chess engine as its back end and updates variables representing the state of the game.
5. [demo-server](../samples/demo-server) - an OPC-UA server that is more complex than the simple server and can be used for compliance testing.
6. [mqtt-client](../samples/mqtt-client) - an OPC-UA client that subscribes to some values and publishes them to an MQTT broker.
7. [event-client](../samples/event-client) - an OPC-UA client that will connect to a server and subscribe to alarms / events.
8. [custom-codegen](../samples/custom-codegen) - an OPC-UA server that implements an OPC-UA companion standard generated using `async-opcua-codegen`.
