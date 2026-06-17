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
* `legacy-crypto` - When enabled (default is **disabled**), compiles in support for the deprecated security policies `Basic128Rsa15` and `Basic256`. **As of 0.19 these policies are opt-in.** Without this feature they are not compiled at all; with it, they are still rejected at runtime unless you also set `allow_legacy_crypto: true` (server: `ServerBuilder::allow_legacy_crypto`, client: `ClientBuilder::allow_legacy_crypto`). Only enable this if you must interoperate with legacy endpoints that cannot offer a modern policy.
* `wss` - When enabled (default is **disabled**), compiles in the `opc.wss` (OPC UA over secure WebSocket) transport. TLS is layered via `tokio-rustls` on the in-tree `rustls` 0.23; the crate re-exports that exact `rustls` (`opcua::client::rustls` / `opcua::server::rustls`) so callers of the advanced config APIs cannot version-skew. The WSS/TLS certificate is **separate** from the OPC UA application certificate. Server: `ServerBuilder::websocket_tls(cert_pem, key_pem)` (hardened convenience) or `websocket_rustls_config(Arc<rustls::ServerConfig>)` (full control), served via `run_with_wss`. Client: secure-by-default WebPKI hostname verification, with `ClientBuilder::websocket_ca_pem` / `websocket_rustls_config` for custom trust and a loudly-gated `dangerously_accept_invalid_wss_certs` test-only escape hatch. The WebSocket subprotocol/ALPN is `opcua+uacp`. WSS secures only the transport — the OPC UA `SecurityPolicy` (sign/encrypt, application-cert auth, user tokens) still runs inside the WebSocket exactly as over `opc.tcp`.

## Cryptographic backend (`aws-lc-rs` feature, default on)

The RSA private-key **decrypt** path (OpenSecureChannel + legacy identity-token decryption) has two selectable backends:

* **`aws-lc-rs` (default).** Uses [`aws-lc-rs`](https://crates.io/crates/aws-lc-rs) for **constant-time** RSA decryption — the recommended, secure default (mitigates the "Marvin" RSA timing attack). `aws-lc-rs` builds a small amount of C/assembly, so a working **C compiler** (and on some targets `cmake`/`nasm`) must be on `PATH` when building, including for cross-compilation. See the [`aws-lc-rs` requirements](https://aws.github.io/aws-lc-rs/requirements/index.html).
* **Pure-Rust (disable the feature).** Build with `default-features = false` to drop `aws-lc-rs`; RSA decrypt then falls back to the pure-Rust [`rsa`](https://crates.io/crates/rsa) crate, so the build needs **no C toolchain** and cross-compiles cleanly to targets like `aarch64-unknown-linux-musl`. Trade-off: the `rsa` crate's RSA decryption is **not constant-time** (RUSTSEC-2023-0071). This is irrelevant for deployments that use `SecurityPolicy::None` or a trusted network (the decrypt path is never exercised), but for secured endpoints on an untrusted network prefer the default `aws-lc-rs` backend.

Example C-free client build:

```toml
async-opcua = { version = "0.19", default-features = false, features = ["client"] }
```

The choice is a feature on every crate that pulls crypto (`async-opcua`, `-core`, `-client`, `-server`): `aws-lc-rs` is in their `default`, so omitting `default-features` keeps the constant-time backend; `default-features = false` selects the pure-Rust path.

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
