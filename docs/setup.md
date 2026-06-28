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
* `ecc` - When enabled, compiles in the pure-Rust NIST elliptic-curve security policies `ECC_nistP256` (P-256 / SHA-256 / AES-128) and `ECC_nistP384` (P-384 / SHA-384 / AES-256), with both `Sign` and `SignAndEncrypt` message modes. These use ephemeral-ephemeral ECDH + HKDF for session keys and ECDSA for the handshake signature (no C toolchain; via the RustCrypto `p256`/`p384`/`ecdsa`/`hkdf` crates). It is **default-enabled on `-core`/`-client`/`-server`/`-crypto`** but **opt-in on the umbrella `async-opcua` crate** — add `features = ["ecc"]` there to use ECC. With the feature off, the ECC policy URIs are still *recognized* but report **unsupported** and are rejected (`BadSecurityPolicyRejected`); RSA/None are byte-identical. An ECC endpoint requires an **EC** application certificate: because a server has a single application instance certificate (RSA *or* EC), a server is ECC-only or RSA-only — to offer both, run RSA and ECC on separate endpoints/hosts (one-server mixed RSA+ECC multi-cert is a future enhancement).
* `wss` - When enabled (default is **disabled**), compiles in the `opc.wss` (OPC UA over secure WebSocket) transport. TLS is layered via `tokio-rustls` on the in-tree `rustls` 0.23; the crate re-exports that exact `rustls` (`opcua::client::rustls` / `opcua::server::rustls`) so callers of the advanced config APIs cannot version-skew. The WSS/TLS certificate is **separate** from the OPC UA application certificate. Server: `ServerBuilder::websocket_tls(cert_pem, key_pem)` (hardened convenience) or `websocket_rustls_config(Arc<rustls::ServerConfig>)` (full control), served via `run_with_wss`. Client: secure-by-default WebPKI hostname verification, with `ClientBuilder::websocket_ca_pem` / `websocket_rustls_config` for custom trust and a loudly-gated `dangerously_accept_invalid_wss_certs` test-only escape hatch. The WebSocket subprotocol/ALPN is `opcua+uacp`. WSS secures only the transport — the OPC UA `SecurityPolicy` (sign/encrypt, application-cert auth, user tokens) still runs inside the WebSocket exactly as over `opc.tcp`.

### ECC endpoint deployment

For the umbrella crate, enable ECC explicitly:

```toml
async-opcua = { version = "0.19", features = ["client", "server", "ecc"] }
```

ECC secure-channel endpoints must use an EC ApplicationInstance certificate whose curve matches the
policy being validated. The demo server includes a separate ECC profile and launcher that provision
an EC certificate before startup:

```bash
cd samples/demo-server
./run-conformance.sh ecc        # ECC profile with a P-256 certificate on :4856
./run-conformance.sh ecc p384   # ECC profile with a P-384 certificate on :4856
```

See `samples/demo-server/sample.server.ecc.conf` and `docs/ctt-conformance.md` for the full UACTT
workflow. Do not reuse the RSA sample keypair for ECC endpoints; RSA certificates cannot produce
ECDSA signatures. Current server instances have one ApplicationInstance certificate, so mixed RSA
and ECC deployments should run separate profiles/instances until multi-certificate selection is
implemented.

## Cryptographic backend (`aws-lc-rs` feature, default on)

The RSA private-key **decrypt** path (OpenSecureChannel + legacy identity-token decryption) has two selectable backends:

* **`aws-lc-rs` (default).** Uses [`aws-lc-rs`](https://crates.io/crates/aws-lc-rs) for **constant-time** RSA decryption — the recommended, secure default (mitigates the "Marvin" RSA timing attack). `aws-lc-rs` builds a small amount of C/assembly, so a working **C compiler** (and on some targets `cmake`/`nasm`) must be on `PATH` when building, including for cross-compilation. See the [`aws-lc-rs` requirements](https://aws.github.io/aws-lc-rs/requirements/index.html).
* **Pure-Rust (disable the feature).** Build with `default-features = false` to drop `aws-lc-rs`; RSA decrypt then falls back to the pure-Rust [`rsa`](https://crates.io/crates/rsa) crate, so the build needs **no C toolchain** and cross-compiles cleanly to targets like `aarch64-unknown-linux-musl`. Trade-off: the `rsa` crate's RSA decryption is **not constant-time** (RUSTSEC-2023-0071). This is irrelevant for deployments that use `SecurityPolicy::None` or a trusted network (the decrypt path is never exercised), but for secured endpoints on an untrusted network prefer the default `aws-lc-rs` backend.

Example C-free client build:

```toml
async-opcua = { version = "0.19", default-features = false, features = ["client"] }
```

The choice is a feature on every crate that pulls crypto (`async-opcua`, `-core`, `-client`, `-server`): `aws-lc-rs` is in their `default`, so omitting `default-features` keeps the constant-time backend; `default-features = false` selects the pure-Rust path.

### Cross-compiling to musl (e.g. `aarch64-unknown-linux-musl`) — keeping constant-time crypto

You do **not** have to give up the constant-time `aws-lc-rs` backend to cross-compile to a musl target (a common need for a stripped-down SoftPLC/embedded-Linux image). The blocker is only that `aws-lc-sys` builds C/assembly and so wants a C **cross**-toolchain. [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild) supplies that toolchain from Zig's bundled `clang`, so no `gcc-aarch64-linux-gnu`-style cross-toolchain is needed:

```bash
# one-time
rustup target add aarch64-unknown-linux-musl
cargo install cargo-zigbuild      # the cargo-zigbuild wrapper
# install Zig (https://ziglang.org/download/) and put `zig` on PATH; also install `cmake`
#   (aws-lc-sys uses cmake; Zig provides the C compiler/linker)

# build — DEFAULT features, i.e. the constant-time aws-lc-rs backend, over musl:
cargo zigbuild --target aarch64-unknown-linux-musl -p async-opcua --features client,server
```

Verified with `zig` 0.16 + `cargo-zigbuild` 0.19 + `cmake` 3.28: `aws-lc-sys`/`aws-lc-rs`
compile and link cleanly for `aarch64-unknown-linux-musl` with **no** `CC`/`AR`/`CMAKE_*`
env overrides and **no** in-repo `.cargo/config.toml`. This is the recommended path for a
**secured** deployment on an untrusted network: it keeps the audited, constant-time crypto and
only changes the *build pipeline* (Zig as the C cross-compiler), not the dependency set.

**Choosing between the two C-toolchain-free routes:**

| Goal | Route |
|------|-------|
| Secured endpoint, untrusted network, but no C cross-toolchain on the build host | **`cargo-zigbuild` + default `aws-lc-rs`** (above) — proven constant-time, Zig provides the C compiler |
| `SecurityPolicy::None` / trusted network, want zero C in the build | `default-features = false` → pure-Rust `rsa` (not constant-time; fine when the decrypt path isn't exercised) |

## Embedded-Linux deployment (low-jitter runtime + size-optimized build)

For long-lived deployments on resource-constrained embedded-Linux devices (Raspberry Pi /
Pi Zero class, including musl images), two configuration choices matter beyond the crypto
backend above: the async runtime flavor and the build profile.

### Recommended runtime: single-threaded (`current_thread`)

The biggest lever for **low latency jitter** on a multi-core SBC is to run the Tokio runtime
in its `current_thread` (single-threaded) flavor rather than the default multi-threaded
work-stealing scheduler:

```rust
#[tokio::main(flavor = "current_thread")]
async fn main() {
    // build and run the async-opcua server/client as usual
}

// or, building the runtime explicitly:
let rt = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap();
rt.block_on(async { /* ... */ });
```

Why it helps on an SBC:

- **No cross-core work-stealing.** The multi-threaded scheduler can allocate a task's data on
  one core and free it on another; those cross-core frees, plus scheduler synchronization, are
  a source of latency jitter that is especially visible on a 2–4 core SBC. A single-threaded
  runtime keeps each connection's work (and its allocator activity) on one core.
- **Lower memory and code footprint.** One worker thread instead of one-per-core means fewer
  stacks and less scheduler state.

**Trade-off:** a single-threaded runtime serializes CPU-bound work across all connections, so
peak multi-connection throughput is lower. For a typical embedded SoftPLC/gateway role
(a handful of sessions, periodic publishes, modest request rates) the jitter and footprint win
outweighs the throughput ceiling. If you are CPU-bound across many concurrent sessions, keep
the default multi-threaded runtime.

This pairs with the steady-state allocation work in the library itself (pooled notification
buffers on the publish path), which keeps per-publish-tick allocation constant rather than
proportional to the notification count — so the single-threaded runtime sees a near-flat
allocation rate at steady state.

### Size-optimized build profile

The workspace defines an opt-in `embedded` profile (see the root `Cargo.toml`) tuned for a
small binary and resident footprint:

```bash
# size-optimized, feature-minimal build over musl (constant-time crypto kept):
cargo zigbuild --profile embedded --target aarch64-unknown-linux-musl \
    -p async-opcua --no-default-features --features server,aws-lc-rs
```

The profile sets `opt-level = "z"` (size), `lto = true`, `codegen-units = 1`, and
`strip = true`. It deliberately keeps `panic = "unwind"` — **do not** switch this server to
`panic = "abort"`: a malformed chunk must drop only the offending connection, and `abort`
would turn that recoverable drop into a whole-process exit (a denial of service for every
other client). Trim the dependency surface with `--no-default-features` plus only the features
you use (e.g. `server`; add `json`/`xml` only if you need those encodings). Use `opt-level =
"s"` instead of `"z"` if profiling shows you need more throughput headroom.

### Deployment limit profiles

Ready-to-edit server configurations for constrained and standard deployments live under
`samples/profiles/`: `micro.conf`, `gateway.conf`, and `server.conf`. Their `limits:` blocks
mirror the tiers described in `deploy-profiles.md`, including bounded non-zero
`max_notifications_per_publish` values to avoid unlimited publish responses by default.

**Behavior change (feature 011):** the default `max_notifications_per_publish` is now a bounded
`1000` (was `0` = unlimited), and a configuration that sets **both** `max_chunk_count` and
`max_message_size` to `0` is now rejected at validation (that combination previously meant
"unbounded" and allowed unbounded chunk buffering). Set explicit bounded values if you were relying
on the old unlimited defaults.

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
