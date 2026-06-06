# Async OPC-UA Macros

Part of [async-opcua](https://crates.io/crates/async-opcua), a general purpose OPC-UA library in rust.

This defines a number of utility macros for encoding, decoding, and defining types to help write server and client software.

Currently defines:

 - `Event`, a macro for deriving the `Event` trait on custom event types.
 - `EventField`, a macro for deriving the `EventField` trait, used for types that can be part of OPC-UA events.
 - `FromXml`, with the `"xml"` feature. Derives conversion from XML objects in `NodeSet2` files.
 - `JsonEncodable`, with the `"json"` feature. Derives streaming serialization using OPC-UA JSON.
 - `JsonDecodable`, with the `"json"` feature. Derives streaming deserialization using OPC-UA JSON.
 - `BinaryEncodable`, derives streaming serialization using OPC-UA Binary.
 - `BinaryDecodable`, derives streaming deserialization using OPC-UA Binary.
 - `UaEnum`, derives the `UaEnum` and a few other traits to make it easier to define custom OPC-UA enums.

 ## Features

 - `json`, adds the `JsonEncodable` and `JsonDecodable` macros.
 - `xml`, adds the `FromXml` macro.
