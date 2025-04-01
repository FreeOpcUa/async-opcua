#![warn(missing_docs)]

//! This is an [OPC UA](https://opcfoundation.org/about/opc-technologies/opc-ua/)
//! server / client API implementation for Rust.
//!
//! The actual implementation is in other crates, this is a convenient
//! master crate that re-exports the other crates.
//!
//! OPC-UA is an industry standard for information modeling and communication. It is
//! used for control systems, IoT, etc.
//!
//! The OPC-UA standard is very large and complex, and implementations are often flawed.
//! The strictness of Rust makes it a good choice for implementing OPC-UA,
//! and the performance characteristics are useful when creating OPC-UA tooling
//! that will run in constrained environments.

pub use opcua_core::sync;

#[cfg(feature = "server")]
pub use opcua_macros::{Event, EventField};

#[cfg(feature = "client")]
pub use opcua_client as client;
#[cfg(feature = "server")]
pub use opcua_nodes as nodes;
#[cfg(feature = "server")]
pub use opcua_server as server;

pub use opcua_core as core;
pub use opcua_crypto as crypto;
pub use opcua_types as types;

#[cfg(feature = "xml")]
pub use opcua_xml as xml;

#[cfg(feature = "generated-address-space")]
pub use opcua_core_namespace as core_namespace;
