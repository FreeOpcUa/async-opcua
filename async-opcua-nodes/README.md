# Async OPC-UA Nodes

Part of [async-opcua](https://crates.io/crates/async-opcua), a general purpose OPC-UA library in rust.

This library defines types used mainly in the [async-opcua-server](https://crates.io/crates/async-opcua-server) library as part of in-memory node managers, but also utilities for importing `NodeSet2` XML files to Rust.

Primarily, this library defines a type for each OPC-UA NodeClass `Object`, `Variable`, `Method`, `View`, `ObjectType`, `VariableType`, `DataType`, and `ReferenceType`, as well as builders for all of these. There's also a common enum over all of these `NodeType`.

A few other common types are also defined here, such as the `TypeTree` trait, used in the server to provide the server with a view of all the types defined on the server, and the `NodeSet2Import` type, used to import `NodeSet2` files into memory.

## Features

 - `xml` adds support for reading NodeSet2 XML files into `NodeType`.
