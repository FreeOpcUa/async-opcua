# Async OPC-UA XML

Part of [async-opcua](https://crates.io/crates/async-opcua), a general purpose OPC-UA library in rust.

This implements parsing of some XML schemas needed for code generation and loading of `NodeSet2` XML files.

Currently, we have support for:

 - XSD files, the subset needed for OPC-UA specs.
 - OPC-UA BSD files.
 - OPC-UA NodeSet2 files.
