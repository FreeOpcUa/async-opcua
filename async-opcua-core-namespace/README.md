# Async OPC-UA Core Namespace

Part of [async-opcua](https://crates.io/crates/async-opcua), a general purpose OPC-UA library in rust.

This library contains generated code for nodes and events defined in the core OPC-UA standard. It is intended to be used with [async-opcua-server](https://crates.io/crates/async-opcua-server), to define the core node manager.

All OPC-UA servers must define the core namespace, which is primarily the core type hierarchy. Version 1.05 of the OPC-UA standard was used to generate this code, using `async-opcua-codegen`.
