# Design

## OPC UA

OPC UA is a very large standard. The specification runs across THIRTEEN(!) parts that describe services, address space, security, information model, mappings (communication protocol), alarms, history, discovery, aggregates and more.

This implementation obviously does not implement all that. Instead it is equivalent to the OPC UA Embedded profile, which allows for:

* Communication over opc.tcp://
* Encryption
* Endpoints
* Services
* Subscriptions and monitored items
* Events

As the project proceeds more functionality will be added with a lot of code backfilling.

## Project Layout

OPC UA for Rust is split over several crates which are periodically published:

* [`async-opcua`](../async-opcua) - a mostly empty wrapper crate that re-exports the other crates based on enabled features.
* [`async-opcua-types`](../async-opcua-types) - contains machine generated types and handwritten types
* [`async-opcua-core`](../async-opcua-core) - contains functionality common to client and server such as encoding / decoding chunks.
* [`async-opcua-crypto`](../async-opcua-crypto) - contains all encryption functionality
* [`async-opcua-client`](../async-opcua-client) - contains the client side API
* [`async-opcua-server`](../async-opcua-server) - contains the server side API. The server may optionally use `async-opcua-client` to register the server with a local discovery server.
* [`async-opcua-nodes`](../async-opcua-nodes) - contains the `NodeType` as well as types necessary to define the core namespace.
* [`async-opcua-core-namespace`](../async-opcua-core-namespace) - contains the generated code for populating the core namespace.
* [`async-opcua-xml](../async-opcua-xml) - contains tools for parsing various OPC-UA XML files. Used by async-opcua-codegen and by async-opcua-nodes for loading NodeSet2 files at runtime. Only included with the `xml` feature.
* [`async-opcua-macros`](../async-opcua-macros) - procedural macros for encoding, decoding, events, and likely more in the future.
* [`async-opcua-codegen`](../async-opcua-codegen) - a command line tool for generating code based on OPC-UA XML files.
* [`async-opcua-certificate-creator`](../tools/certificate-creator) - a command-line tool for creating OPC UA compatible public cert and private key.

These are all published on [crates.io](https://crates.io). The API tend to receive breaking changes between releases but the functionality grows and becomes more complete.

The workspace also contains some other folders:

* [`samples`](../samples) - containing various client and server examples.

## Testing

Unit and integration tests will cover all functional aspects of the project. In addition the implementation should be tested with 3rd party OPC UA implementations so the client / server parts can be tested in isolation.

See the [testing](./testing.md) document.

## Minimizing code through convention

OPC UA for Rust uses convention and idiomatic Rust to minimize the amount of code that needs to be written.

Here is a minimal, functioning server.

```rust
use opcua::server::ServerBuilder;
use opcua::types::*;

fn main() {
    let (server, _handle) = ServerBuilder::new_sample().build().unwrap();
    server.run().await.unwrap();
}
```

This server will accept connections, allow you to browse the address space and subscribe to variables.

Refer to the [`samples/simple-server/`](../samples/simple-server) and [`samples/simple-client/`](../samples/simple-client) examples
for something that adds variables to the address space and changes their values.

## Types

OPC UA defines a lot of types. Some of those correspond to Rust primitives while others are types, structures or enums which are used by the protocol. All types are defined in the [`async-opcua-types`](../async-opcua-types) crate.

All types can be encoded / decoded to a stream according to the opc.tcp:// binary transport. They do so by implementing a `BinaryEncodable` and `BinaryDecodable` traits. The three functions on this trait allow a struct to be deserialized, serialized, or the byte size of it to be calculated.

Typically encoding will begin with a structure, e.g. `CreateSubscriptionRequest` whose implementation will encode each member in turn.

Types can also be encoded into `ExtensionObject`s in a simple fashion.

```rust
let operand = AttributeOperand { /* ... */ };
let obj = ExtensionObject::from_message(operand);
```

And out:

```rust
let operand: Box<AttributeOperand> = obj.into_inner_as::<AttributeOperand>().unwrap();
```

### Primitives

OPC UA primitive types are referred to by their Rust equivalents, i.e. if the specification says `Int32`, the signature of the function / struct will use `i32`:

* `Boolean` to `bool`
* `SByte` to `i8`
* `Byte` to `u8`
* `Int16` to `i16`
* `UInt16` to `u16`
* `Int32` to `i32`
* `UInt32` to `u32`
* `Int64` to `i64`
* `UInt64` to `u64`
* `Float` to `f32`
* `Double` to `f64`

### Strings

The OPC UA type `String` is not directly analogous to a Rust `String`. The OPC UA definition maintains a distinction between being a null value and being an empty string. This affects how the string is encoded and could impact on application logic too.

For this reason, `String` is mapped onto a new Rust type `UAString` type which captures this behaviour. Basically it is a struct that holds an optional `String` where `None` means null. The name is `UAString` because `String` is such a fundamental type that it is easier to disambiguate by calling it something else rather than through module prefixing.

### Basic types

All of the basic OPC UA types are implemented by hand.

* `ByteString`
* `DateTime`
* `QualifiedName`
* `LocalizedText`
* `NodeId`
* `ExpandedNodeId`
* `ExtensionObject`
* `Guid`
* `NumericRange`
* `DataValue`
* `Variant`

A `Variant` is a special catch-all enum which can hold any other primitive or basic type, including arrays of the same. The implementation uses a `Box` (allocated memory) for larger kinds of type to keep the stack size down.

### Machine generated types

Machine generated types reside in `async-opcua-types/src/generated/types`. The `enums.rs` holds all of the enumerations. A special `src/impls.rs` contains additional hand written functions that are associated with types.

All these are generated using `async-opcua-codegen`. The configuration used to generate the core namespace is found [here](../code_gen_config.yml).

## Handling OPC UA names in Rust

All OPC UA enums, structs, fields, constants etc. will conform to Rust lint rules where it makes sense. i.e. OPC UA uses pascal case for field names but the impl will use snake case, for example `requestHeader` is defined as `request_header`.

```rust
struct OpenSecureChannelRequest {
  pub request_header: RequestHeader
}
```

Enums are scalar.

```rust
pub enum SecurityPolicy {
  Invalid = 0,
  None = 1
  ...
}
```

The enum will be turned in and out of a scalar value during serialization via a match.

Wherever possible Rust idioms will be used - enums, options and other conveniences of the language will be used to represent data in the most efficient and strict way possible. e.g. here is the node ID `Identifier`:

```rust
#[derive(Eq, PartialEq, Clone, Debug, Hash)]
pub enum Identifier {
    Numeric(u32),
    String(UAString),
    Guid(Guid),
    ByteString(ByteString),
}

/// An identifier for a node in the address space of an OPC UA Server.
#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub struct NodeId {
    /// The index for a namespace
    pub namespace: u16,
    /// The identifier for the node in the address space
    pub identifier: Identifier,
}
```

### Lint exceptions for OPC UA

OPC UA has some really long PascalCase ids, many of which are further broken up by underscores. I've tried converting the name to upper snake and they look terrible. I've tried removing underscores and they look terrible.

So the names and underscores are preserved as-in in generated code even though they generate lint errors. The lint rules are disabled for generated code.

For example:

```rust
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum VariableId {
    //... thousands of ids, many like this or worse
    ExclusiveRateOfChangeAlarmType_LimitState_LastTransition_EffectiveTransitionTime = 11474,
}
```

### Status codes

Status codes are managed by the `StatusCode` struct, which is jsut a wrapper around `u32`. Built in status codes are given as associated constants, and the type contains methods suc has `set_limit` to set flags.

Status code subscription is also available at runtime through `sub_code().description()`.

## Formatting

All code (with the exceptions noted for OPC UA) should be follow the most current Rust RFC coding guidelines for naming conventions, layout etc.

Code should be formatted with rustfmt. CI checks for clean execution of `cargo fmt --all`.

## Encryption

OPC UA for Rust now uses a set of pure rust crates for cryptography.

## Address Space

Each node manager on the server manages an address space. The server contains an implementation of an in-memory address space as `AddressSpace`. This is essentially a big map of `NodeId` to `NodeType`, which is an enum with a variant for each OPC UA node type:

* DataType
* Method
* Object
* ObjectType
* ReferenceType
* Variable
* VariableType
* View

References are managed by a `References` struct which has a map of vectors of outgoing references from a node. Each `Reference` has a reference type id (a `NodeId`) indicating what the refeence is, and the `NodeId` of the target node. `References` also maintains a reverse lookup map so it can tell if a target is referenced by another node.

### Generated nodeset

We define a trait `NodeSetImport` for methods that import namespaces. This is implemented by a struct in each generated nodeset. The built-in namespace is called `CoreNamespace`. An `AddressSpace` struct can import a nodeset by calling `import_node_set`.

`async-opcua-codegen` can be used to generate nodeset imports by parsing `NodeSet2` files. This is mostly useful for namespaces consisting of just types, since we also generate event types. If all you want to do is import a nodeset, it may be easier (and kinder on compile times) to use `NodeSet2Import` from `async-opcua-nodes` to import a `NodeSet2.xml` file at runtime.

## Networking

### Asynchronous I/O

Tokio is used to provide asynchronous I/O and timers.

* Futures based - actions are defined as promises which are executed asynchronously.
* I/O is non-blocking.
* Inherently multi-threaded via Tokio's executor.
* Supports timers and other kinds of asynchronous operation.

The penalty for this is that asynchronous programming can be _hard_. Fortunately Rust has acquired  new `async` and `await` keyword functionality that simplifies the async logic a bit, but it can still get hairy in places.

Tokio provides `tasks` that are scheduled on a thread pool to run in _parallel_. A fundamental design consideration of both the server and client library is that we are _very_ deliberate about when we `spawn` a task, and when we just await multiple futures concurrently using `select` or `join`.

In general, there should be a _very_ good reason to `spawn` by default, and we _never_ spawn tasks that we do not somehow monitor.

The client does, in fact, not spawn anything at all by default. Instead, to drive the connection, it provides an event loop that must be polled in some way to make progress. This can be as easy as just calling `SessionEventLoop::spawn` to spawn a tokio task, or awaiting the future returned by `SessionEventLoop::run`, but users also have the option to consume the `SessionEventLoop::enter` thread to get a view into exactly what the client is doing.

The event loop is a single-threaded state machine. This does mean that the client is fundamentally single-threaded, which greatly simplifies the architecture.

The server has a very different approach to this, instead using a pattern common in web servers, where each incoming message spawns a `task`, and each connection runs on a dedicated `task`.

## Major 3rd party dependencies

* log - for logging / auditing
* serde, server_yaml - for processing config files
* struson - for streamed JSON processing.
* clap - used by sample apps & certificate creator for command line argument processing
* byteorder - for serializing values with the proper endian-ness
* tokio - for asynchronous IO and timers
* futures - for futures used by tokio
* chrono - for high quality time functions
* time - for some types that chrono still uses, e.g. Duration
* random - for random number generation in some places

## 3rd-party servers

### Node

There are also a couple of [node-opcua](https://github.com/node-opcua) scripts in `3rd-party/node-opcua`.

1. `client.js` - an OPC UA client that connects to a server and subscribes to v1, v2, v3, and v4.
2. `server.js` - an OPC UA server that exposes v1, v2, v3 and v4 and changes them from a timer.

These are functionally analogous to `simple-server` and `simple-client` so the Rust code can be tested against an independently written implementation of OPC UA that works in the way it is expecting. This is useful for debugging and isolating bugs / differences.

To use them:

1. Install [NodeJS](https://nodejs.org/) - LTS should do, but any recent version should work.
2. `cd 3rd-party/node-opcua`
3. `npm install`
4. `node server.js` or `node client.js`

### .NET

In `dotnet-tests` we have defined a simple server in [UA-.NET Standard](https://github.com/Opcfoundation/UA-.NETStandard), the official .NET reference SDK, which we use for automated testing.

To run this server, install .NET SDK 8 or later: [here](https://dotnet.microsoft.com/en-us/download), then simply run the server with `dotnet run`.

```
dotnet run --project dotnet-tests/TestServer -- dotnet-tests/TestServer.Config.xml
```

The first argument is the path to the XML config file.

The server is not really designed for running manually like this, it is tightly coupled with the external test harness, and controlled through JSON payloads sent over standard input.