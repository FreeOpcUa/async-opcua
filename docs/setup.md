This is the in-depth documentation about the OPC UA implementation in Rust.

# Setup

Rust supports backends for gcc and MSVC so read the notes about this. Then use [rustup](https://rustup.rs/) to install your toolchain and keep it up to date.

There are some [developer](./developer.md) related notes too for people actually modifying the source code.

## Windows

Rust supports two compiler backends - gcc or MSVC, the choice of which is up to you.

### Visual Studio

1. Install [Microsoft Visual Studio](https://visualstudio.microsoft.com/). You must install C++ and 64-bit platform support.
2. Use rustup to install the `install stable-x86_64-pc-windows-msvc` during setup or by typing `rustup toolchain install stable-x86_64-pc-windows-msvc` from the command line.

32-bit builds should also work by using the 32-bit toolchain but this is unsupported.

### MSYS2

MSYS2 is a Unix style build environment for Windows.

1. Use rustup to install the `stable-x86_64-pc-windows-gnu` toolchain during setup or by typing `rustup toolchain install stable-x86_64-pc-windows-gnu` from the command line.

You should use the MSYS2/MingW64 Shell. You may have to tweak your .bashrc to ensure that the `bin/` folders for both Rust and MinGW64 binaries are on your `PATH`. 

## Linux

1. Use rustup to install the latest stable rust during setup.

That's all you need. `async-opcua` has no dependencies apart from other rust crates.

## Conditional compilation

The OPC UA server crate also provides some other features that you may or may not want to enable:

* `client` - Includes the OPC UA client implementation.
* `server` - Includes the OPC UA server implementation.
* `base-server` - Includes the server implementation without `generated-address-space`.
* `generated-address-space` - When enabled (default is enabled), server will contain generated code containing the core OPC-UA namespace. It is very unlikely that you do not want this feature, so it is enabled by default with the `server` feature. If you need to disable it, you should use the `base-server` feature instead. When disabled, the address space will only contain a root node, but the vast majority of OPC-UA clients will not work with it, and it will not be fully OPC-UA compliant.
* `discovery-server-registration` - When enabled (default is disabled), the server will periodically attempt to  register itself with a local discovery server. The server will use the on the client crate which requires more memory.
* `json` - When enabled (default is disabled), built in types have support for encoding and decoding from JSON. Note that when this feature is enabled, custom types must implement json encoding to be stored in an `ExtensionObject`.
* `xml` - When enabled (default is disabled), built in types implement `FromXml`, which creates them from an OPC-UA XML node. This is _not_ full XML support, but rather only what we need in order to support loading `NodeSet2` files at runtime.

## Workspace Layout

OPC UA for Rust follows the normal Rust conventions. There is a `Cargo.toml` per module that you may use to build the module and all dependencies. e.g.

```bash
$ cd opcua/samples/demo-server
$ cargo build
```

There is also a workspace `Cargo.toml` from the root directory. You may also build the entire workspace like so:

```bash
$ cd opcua
$ cargo build
```
