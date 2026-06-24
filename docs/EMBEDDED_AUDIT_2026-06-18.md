# async-opcua — Embedded-Suitability Audit

**Date:** 2026-06-18
**Target:** async-opcua workspace (OPC UA protocol library: types, core, crypto, client, server, pubsub).
**Audit type:** Embedded-systems readiness review. The question driving this audit: *can this library
run on the small systems an industrial automation driver tends to land on — a Raspberry Pi Zero, or a
bare-metal microcontroller like an RP2040 "Pico"?* Scope is resource footprint (flash/RAM/heap),
`no_std`/`alloc` coupling, the dynamic-allocation profile on multi-core SBCs, panic/abort surface,
recursion/stack bounds, and toolchain/cross-compilation constraints.
**Companion documents:** [`CODE_REVIEW_2026-06-16.md`](./CODE_REVIEW_2026-06-16.md),
[`SECURITY_AUDIT_2026-06-16.md`](./SECURITY_AUDIT_2026-06-16.md),
[`PERFORMANCE_AUDIT_2026-06-16.md`](./PERFORMANCE_AUDIT_2026-06-16.md).

> **Note on dating.** The audit was performed across 2026-06-17/18. Several findings below were
> *acted on in the same session* (footprint defaults, crypto-backend optionality, allocation
> elimination, the highest-severity remote panics). Each finding is tagged with its current status
> and the PR that addressed it, so this document doubles as a remediation ledger.

---

## 1. Verdict (TL;DR)

| Target class | Example HW | Verdict | Why |
|--------------|-----------|---------|-----|
| **Embedded Linux** | Pi Zero / Zero 2 W, BeagleBone, any `*-unknown-linux-{gnu,musl}` | ✅ **Viable** | Full `std`, an allocator, and `tokio` are all present on the platform. Footprint is the only real concern, and the defaults are now embedded-sane. |
| **Bare-metal MCU** | RP2040 "Pico", STM32, ESP32-no-std | ❌ **Not feasible** (no near-term path) | Hard, pervasive dependencies on `std` (`std::net`, `std::time`, `std::sync`), a heap allocator, `tokio` (needs an OS scheduler + `std`), `chrono`, and `aws-lc-rs` (default crypto builds C/asm). None of this is `no_std`. |

**Bottom line:** target embedded *Linux*, not bare metal. Making this stack `no_std` would be a
ground-up rewrite of the I/O, time, and async layers — out of scope and not recommended. The
productive embedded work is reducing footprint and allocation churn on the Linux SBCs, which is where
this session's effort went.

---

## 2. Methodology

| Activity | Method | Result |
|----------|--------|--------|
| `std`/`alloc` coupling | grep for `std::net`, `std::time`, `std::sync`, `tokio`, global-allocator assumptions across all crates | Pervasive; no `#![no_std]` anywhere; no `alloc`-only abstraction layer |
| Cross-compilation | `cargo tree`/build against `aarch64-unknown-linux-musl` with and without default features | Default pulls `aws-lc-rs` → `aws-lc-sys` (C/asm) → needs a C toolchain; pure-Rust path is C-free (see §4.2) |
| Footprint defaults | review of `config/limits.rs`, sample configs | Several defaults sized for servers, not devices (see §4.1) |
| Allocation profile | trace the per-connection RX/TX hot paths for per-message/per-chunk heap traffic | Per-chunk RX decrypt allocated+freed a `Vec` per secured chunk (see §4.3) |
| Panic/abort surface | grep `unwrap`/`expect`/`panic!`/`unreachable!`/indexing/`as usize`, cross-referenced against remote-input reachability | 4 remote-reachable CRITICAL/HIGH panics found & fixed; **full sweep not completed** (see §5.1) |
| Recursion/stack bounds | review of recursive decode (nested ExtensionObject/Variant/Array) | Depth-bounding relevant on small stacks (see §5.2) |

---

## 3. Embedded-guideline scorecard

Mapped against the embedded MUST/MUST-NOT guidelines (resource frugality, bounded dynamic allocation,
no unbounded recursion, deterministic error handling, no panics on untrusted input):

| Guideline | Status | Notes |
|-----------|--------|-------|
| Minimize flash/code size | ◐ Partial | `default-features=false` + feature gating helps; no dedicated size profile documented. |
| Minimize RAM / bounded buffers | ◐ Improved | Footprint defaults reduced (§4.1) and hot-path buffers are pre-allocated/reused. But the TCP frame decoder does not enforce `max_message_size` (§5.4), and the GDS registries are unbounded (§5.5). |
| Bounded dynamic allocation | ◐ Improved | Per-chunk RX alloc eliminated (§4.3); per-request `Box`+`spawn` and decode copies remain (§5.3). |
| No unbounded recursion | ◐ Partial | Decode recursion is limited by message-size/decoding limits, not an explicit depth counter (§5.2). |
| No panics on untrusted input | ◐ **Targeted, not complete** | The 4 discovered remote-reachable panics are fixed; the surface as a whole has not been exhaustively swept (§5.1). |
| Deterministic error handling | ✅ Mostly | Decode paths return `Result`; the gaps are the panic sites in §5.1. |
| No floating point in hot paths | ✅ N/A | Protocol is integer/byte oriented. |
| Cross-compiles without host-specific toolchain | ✅ Now optional | Pure-Rust crypto path is C-free (§4.2). |
| Misleading capability claims | ✅ Fixed | `categories = ["embedded"]` removed from crypto crate — it implied bare-metal support that does not exist. |

---

## 4. Findings — ADDRESSED this session

### 4.1 Server footprint defaults sized for servers, not devices — ✅ FIXED (PR #17)
`max_monitored_items_per_sub` defaulted to **100,000** and the client inflight-message cap to
**1,000,000** — each multiplies into per-subscription/per-session memory that a Pi-class device cannot
spare. Reduced to **10,000** and **1,024** respectively, with sample config updated. These are
defaults, not ceilings; large deployments can raise them.

### 4.2 Default crypto backend forces a C toolchain on cross-builds — ✅ FIXED (PR #14, issue #13)
The default `aws-lc-rs` backend compiles C/assembly (`aws-lc-sys`), so cross-compiling to
`aarch64-unknown-linux-musl` for a SoftPLC needs a C cross-toolchain. Made `aws-lc-rs` an **optional**
default feature: building with `default-features = false` selects the **pure-Rust `rsa`** decrypt path
and the build is C-free. Trade-off documented (the `rsa` crate's decrypt is not constant-time,
RUSTSEC-2023-0071) — irrelevant for `SecurityPolicy::None`/trusted-network deployments, but secured
endpoints on untrusted networks should keep the default. The misleading `categories = ["embedded"]`
was also removed.

**Note (2026-06-24):** `aws-lc-rs` is now the **accepted** default for consumers (it provides
constant-time crypto, preferable for SignAndEncrypt endpoints), so the C-free path is an *option*,
not a requirement. The pure-Rust path still works when wanted: `cargo build --target
aarch64-unknown-linux-musl -p async-opcua --no-default-features --features client,ecc` cross-compiles
C-free (pure `rsa`/`p256`/`p384`) — subject to the `rsa` non-constant-time caveat above.

### 4.2b PubSub `lapin` pulled an unused `rustls`/`ring` TLS stack — ✅ FIXED (2026-06-24)
Independent of the C-toolchain question, `async-opcua-pubsub` compiled a transport stack it never
used: `lapin` (AMQP) shipped with default features on, dragging in `rustls` → `ring` (and a
`rustls-webpki` with prior CVE history) even though the transport is **plaintext AMQP only**. Set
`lapin = { default-features = false }` — the same hygiene fix already applied to `rumqttc` in that
manifest — dropping `rustls`/`ring` entirely (`Cargo.lock` -285 lines, smaller binary, fewer CVE
surfaces, faster builds). Still compiles; plaintext AMQP unchanged.

### 4.3 Per-chunk RX decrypt allocation (multi-core jitter) — ✅ FIXED (PR #19)
`decrypt_chunk` allocated `vec![0u8; …]` for **every received secured chunk**, then dropped it. On a
multi-core SBC this is the worst kind of churn: with `tokio`'s work-stealing the free can land on a
different core than the alloc, triggering cross-core allocator contention and TLB-shootdown IPIs that
perturb *other* cores' latency. Reworked to decrypt into a **reusable per-connection `BytesMut`**
(`DecryptedChunkStorage`) and hand back a zero-copy `split_to().freeze()` slice. The scratch buffer is
owned by the connection's own task, so allocs and frees stay on one core. (The rare OPN/asymmetric
open-secure-channel path still allocates — accepted, it is not on the steady-state data path.)

---

## 5. Findings — STILL OPEN

> **Reconciliation — feature 010 (Embedded Hardening & Allocation), 2026-06-19.** All five
> §5 findings have been worked through SpecKit feature `010-embedded-hardening-allocation`.
> §5.1, §5.2, §5.4, §5.5 are **RESOLVED**; §5.3 is **partially resolved** (the deployment/profile
> levers shipped; the two architectural allocation rewrites M2/M4 are **deferred measure-first**
> with recorded rationale). Per-item status is noted inline below; see
> `specs/010-embedded-hardening-allocation/` (tasks.md, research.md R6/R7) for detail.

### 5.1 Panic surface is *targeted-fixed*, not *completely* swept — ✅ RESOLVED in 010
**Status (010):** Panic-surface `#![deny(clippy::unwrap_used, expect_used, indexing_slicing, panic)]`
gates added to `-types`/`-core`/`-crypto` (crate-level) and to the decode/transport modules of
`-server`/`-client`, driven to zero with `Result`/checked replacements (justified `#[allow]` only).
A panic-hunting fuzz pass over `fuzz_comms`/`fuzz_deserialize`/`fuzz_dynamic_struct` ran clean **and
found a previously-unknown remote allocation DoS** (a crafted `Argument.value_rank` ≈ 2.1e9 drove an
8.45 GB `resize` from a 30-byte message) — now fixed (bound `value_rank` by `max_array_length`) with a
regression test and re-verified (45 s / 3M fuzz runs, peak RSS ~436 MB). Not `panic = "abort"` (a bad
chunk drops one connection, never the process).

*(Original finding, retained for context:)*
**This is the honest answer to "do we still need to fix the panic surface completely?": yes.**

What was done: a panic-safety audit found and fixed **4 remote-reachable** panics — 2 CRITICAL
(secure-channel/crypto message-range arithmetic underflow; PR #15) and 2 HIGH (unbounded
ExtensionObject body allocation; `TransferSubscriptions` out-of-bounds indexing; PR #16) — each with a
regression test.

What was **not** done: a line-by-line classification of *every* `unwrap`/`expect`/`panic!`/
`unreachable!`/slice-index/`as usize` against remote-input reachability. Raw counts across the
network-facing crates are in the hundreds, but they are heavily inflated by inline `#[cfg(test)]`
modules (which a path-glob cannot exclude) and by genuinely-safe sites (lock-poison `unwrap`s,
builder/config code, decode of values already bounds-checked upstream). The residue that is *both*
production and remote-reachable is far smaller — but it has **not been enumerated and proven empty**.

Recommended follow-up (in priority order):
1. Add `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]`
   to the decode/network crates (`-types`, `-core`, `-crypto`) and drive the count to zero with
   `Result`-returning replacements, allowing explicit `#[allow]` only on proven-safe sites with a
   justifying comment.
2. Set `panic = "abort"` consideration for embedded *profiles* is **not** advised for a network
   library — a panic should be a recoverable connection drop, not a process kill. The fix is removing
   the panics, not converting them to aborts.
3. Extend the existing fuzz targets (`fuzz_comms`, `fuzz_deserialize`, `fuzz_dynamic_struct`) with a
   panic-hunting harness run under ASAN/`-C panic=abort` to flush out reachable panics empirically.

### 5.2 Recursion depth not explicitly bounded — ✅ RESOLVED in 010
**Status (010):** `max_decode_depth` added to `DecodingOptions` (safe default) with a `DepthGauge`/
`DepthLock` counter applied at the recursive nesting points; exceeding it returns a clean decode error
(regression test: at-limit succeeds, one beyond fails — no stack overflow).

Nested decode (ExtensionObject → Variant → Array → ExtensionObject …) recurses with depth limited only
indirectly by message-size/decoding limits. On a Pi-class device with small per-task stacks this is a
thinner margin than on a server. Recommend an explicit decode-depth counter in `DecodingOptions`
(cheap, deterministic) rather than relying on the size limit as a proxy.

### 5.3 Remaining dynamic-allocation churn — ◐ PARTIALLY RESOLVED in 010
**Status (010):**
- **Event-notification publish path — ✅ FIXED.** The per-publish-tick `Vec<EventFieldList>`
  allocation was eliminated by extending the `DataChangeNotificationVecPool` to the event path
  (clear-on-draw, capacity-checked reuse, bounded free-list, reclaim via the `Arc::into_inner`
  unique-ownership gate). Measured: per-tick event-path construction is **constant — 2 allocs / 56 B
  at both 1000 and 5000 events** (was proportional). Wire output byte-identical (98 integration tests).
- **`current_thread` runtime + size-optimized profile — ✅ DONE** (see §5.3 "Deployment lever" and rec
  #5/#8; now documented in `docs/setup.md` + opt-in `[profile.embedded]`).
- **M2 (per-request `Box`+`tokio::spawn`) — ⏸ DEFERRED measure-first.** The spawn is the request-level
  panic-isolation boundary; an inline fast-path would remove it (tension with the §5.1 hardening) for a
  narrow, data-dependent saving. Rationale: `specs/.../research.md` R6.
- **M4 (zero-copy decode) — ⏸ DEFERRED measure-first.** The decode traits are `std::io::Read`-generic
  workspace-wide and messages are chunked (no contiguous `Bytes` to slice for multi-chunk messages); a
  zero-copy path is a breaking trait change with single-chunk-only benefit. The real decode-path DoS was
  fixed in §5.1. Rationale: `specs/.../research.md` R7.

Two larger allocation sources remain on the hot path, both bigger/architectural than §4.3:
- **Per-request `Box` + `tokio::spawn` dispatch (M2).** Each inbound request is boxed and spawned.
  Eliminating this changes the request-dispatch/panic-isolation model — not a drop-in win.
- **Non-zero-copy `ByteString`/`String` decode (M4).** Decode still copies bytes into an owned `Vec`
  before wrapping; true zero-copy requires the decode path to carry the source `Bytes` — a
  `-types`-wide refactor.
- **Deployment lever (not code):** running the consumer on a `current_thread` tokio runtime removes
  work-stealing entirely, which is the single biggest reduction in cross-core frees for a
  jitter-sensitive SBC. Worth documenting as the recommended embedded runtime config.

### 5.4 TCP frame decoder does not enforce `max_message_size` — ✅ RESOLVED in 010
**Status (010):** `TcpCodec::decode` now rejects a declared `message_size > max_message_size` with
`BadTcpMessageTooLarge` before buffering toward it, and `MessageHeader::decode` honors the
`DecodingOptions` it is passed (no longer `_:`). Regression test added.

*(Added 2026-06-18 from the memory-stability follow-up; verified at source.)*

`TcpCodec::decode` (`async-opcua-core/src/comms/tcp_codec.rs:93`) reads the 8-byte message header,
takes `message_size = message_header.message_size` (an attacker-controlled `u32`, up to 4 GB), and then
only checks `buf.len() >= message_size` before splitting the frame out. It **never rejects an
over-limit `message_size`**, and `MessageHeader::decode` (`tcp_types.rs:98`) is handed
`DecodingOptions` but **ignores it** (`_:`). The negotiated `max_message_size` / `max_chunk_size` from
the Hello/Ack handshake is therefore not enforced at this layer.

**Correction to an earlier characterization:** the decoder does **not** `reserve(message_size)` on the
header, so a header alone cannot make `FramedRead` pre-allocate gigabytes. The buffer only grows as
fast as the peer actually transmits bytes. The real (milder) exposure is that a peer *willing to stream
data* can drive a single connection's read buffer toward its declared `message_size` before any frame
or error is produced. Existing mitigations (per-message `max_chunk_count`, request timeouts) bound chunk
*count* and stall duration but not single-frame *size*.

**Fix (small, localized):** in `TcpCodec::decode`, once the header is read, return
`BadTcpMessageTooLarge` immediately if `message_size > max_message_size` (when nonzero), and have
`MessageHeader::decode` actually use the `DecodingOptions` it receives. Drops the connection before any
oversized buffering.

### 5.5 GDS certificate-management registries are unbounded — ✅ RESOLVED in 010
**Status (010):** Each GDS push/pull registry is now bounded with a defined FIFO-evict-oldest overflow
(cap `GDS_REGISTRY_CAPACITY = 1024`): `signing_requests` (HashMap + insertion-order companion queue),
`created_requests`/`rejected`/`updated`/`finished` (VecDeque, pop_front before push_back). Eviction
tests added; getters still return `Vec`.

*(Added 2026-06-18; explorer-reported, not exhaustively re-verified.)*

The optional GlobalDiscoveryServer push/pull method handlers accumulate state with no cap or cleanup:
- `gds/push_methods.rs:57` — `signing_requests: HashMap<NodeId, …>` and `created_requests: Vec<…>`.
- `gds/pull_methods.rs:45` — `rejected_certificates`, `updated_certificates`,
  `finished_signing_requests` (three unbounded `Vec`s).

A long-lived server with active GDS traffic grows without bound. **Lower priority:** these paths
require the GDS feature and authenticated/privileged calls, so they are not anonymous-remote-reachable.
Fix: cap each registry (oldest-evict or reject-when-full) and/or attach a TTL, mirroring how the
subscription queues and the history continuation-point LRU are already bounded.

> For contrast, the rest of the long-running state **is** properly bounded: subscription notification
> queues, per-monitored-item queues, the retransmission/republish queue, pending-publish queue,
> continuation points (history via LRU+TTL), and the client inflight-request map (1024).

---

## 6. Recommendations summary

All eight were taken into feature `010-embedded-hardening-allocation`. Status as of 2026-06-19:

| # | Action | Effort | Priority | Status (010) |
|---|--------|--------|----------|--------------|
| 1 | Complete the panic-surface sweep via clippy lints + fuzzing on `-types`/`-core`/`-crypto` (§5.1) | Medium | **High** | ✅ Done (+ fuzz found & fixed an 8.45 GB `value_rank` DoS) |
| 2 | Enforce `max_message_size` in `TcpCodec::decode`; make `MessageHeader::decode` use `DecodingOptions` (§5.4) | Low | **High** | ✅ Done |
| 3 | Add explicit decode-recursion depth bound to `DecodingOptions` (§5.2) | Low | Medium | ✅ Done |
| 4 | Cap / TTL the GDS signing-request & certificate registries (§5.5) | Low | Medium | ✅ Done (FIFO-evict, cap 1024) |
| 5 | Document `current_thread` runtime as the recommended embedded config (§5.3) | Low | Medium | ✅ Done |
| 6 | Zero-copy `ByteString`/`String` decode — M4 (§5.3) | High | Low–Medium | ⏸ Deferred measure-first (research.md R7) |
| 7 | Per-request dispatch without per-request `Box`+spawn — M2 (§5.3) | High | Low | ⏸ Deferred measure-first (research.md R6) |
| 8 | Publish a documented size-optimized build profile (LTO, `opt-level="z"`, feature-minimal) | Low | Low | ✅ Done (`[profile.embedded]`) |

**Not recommended:** pursuing `no_std`/bare-metal (RP2040 etc.). The `std`/`tokio`/heap coupling is
foundational; target embedded Linux instead.
