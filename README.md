# Introduction

[![crates.io](https://img.shields.io/crates/v/async-opcua.svg)](https://crates.io/crates/async-opcua)
[![Build Status](https://github.com/freeopcua/async-opcua/workflows/OPC%20UA%20for%20Rust/badge.svg)](https://github.com/freeopcua/async-opcua/actions/workflows/main.yml)
[![Documentation](https://docs.rs/async-opcua/badge.svg)](https://docs.rs/async-opcua)


This is an [OPC UA](https://opcfoundation.org/about/opc-technologies/opc-ua/) server / client API implementation for Rust.

OPC-UA is an industry standard for information modeling and communication. It is used for control systems, IoT, etc.

The OPC-UA standard is very large and complex, and implementations are often flawed. The strictness of Rust makes it a good choice for implementing OPC-UA, and the performance characteristics are useful when creating OPC-UA tooling that will run in constrained environments.

Read the [compatibility](./docs/compatibility.md) page for how the implementation conforms with the OPC UA spec.

Read the [change log](./CHANGELOG.md) for changes per version as well as aspirational / upcoming work.

## This is a fork

This is a fork of [opcua](https://github.com/locka99/opcua) with a broader goal of a generic OPC-UA implementation and a number of different design decisions. See [fork.md](docs/fork.md) for details on this decision and the differences between this library and the original.

# MSRV Policy

We target the latest `stable` rust compiler and make no promises of support for older rust versions. We have use for several recent and upcoming rust features so this is unlikely to change.

# License

The code is licenced under [MPL-2.0](https://opensource.org/licenses/MPL-2.0). Like all open source code, you use this code at your own risk. 

# Setup

Read the [setup](./docs/setup.md) for instructions on building OPCUA for Rust.

Read [cross compilation](./docs/cross-compile.md) for hints for cross compiling OPC UA for Rust to other 
platforms.

# Migration notes

If you're using an earlier version of OPC UA for Rust, read the [migration](./docs/migration.md) notes.

# Design

Read the [design](./docs/design.md) for more in-depth description of implementation.

# Tutorial

Tutorials / user guides are still work in progress. 

* [Client Tutorial](docs/client.md)
* [Server Tutorial](docs/server.md)

# Further Documentation

The API documentation is generated from the latest published crates. This may be some way behind current development. 

<a href="https://docs.rs/async-opcua"><img src="https://docs.rs/async-opcua/badge.svg"></img></a>

# Samples

If you want to get stuck in, there are a number of samples in the samples/ folder. The `simple-client` and the `simple-server` projects are
minimal client and server programs respectively.

```bash
# In one bash
cd samples/simple-server
cargo run
# In another bash
cd samples/simple-client
cargo run
```

The full list of samples:

1. [`simple-server`](samples/simple-server) - an OPC UA server that adds 4 variables v1, v2, v3 and v4 and updates them from a timer via push and pull mechanisms.
2. [`simple-client`](samples/simple-client) - an OPC UA client that connects to a server and subscribes to the values of v1, v2, v3 and v4.
3. [`discovery-client`](samples/discovery-client) - an OPC UA client that connects to a discovery server and lists the servers registered on it.
4. [`chess-server`](samples/chess-server) - an OPC UA server that connects to a chess engine as its back end and updates variables representing the state of the game.
5. [`demo-server`](samples/demo-server) - an OPC UA server that is more complex than the simple server and can be used for compliance testing.
6. [`mqtt-client`](samples/mqtt-client) - an OPC UA client that subscribes to some values and publishes them to an MQTT broker.
7. [`event-client`](samples/event-client) - an OPC UA client that will connect to a server and subscribe to alarms / events.
8. [`node-managers`](samples/node-managers) - an OPC UA server exposing a simple simulated namespace using two custom node managers.
9. [`custom-codegen`](samples/custom-codegen) - an OPC UA server that runs codegen on a companion standard and exposes custom types and a custom namespace.
10. [`custom-structures-client`](samples/custom-structures-client) - an OPC UA client that connects to a server with a few different approaches for supporting custom structures.