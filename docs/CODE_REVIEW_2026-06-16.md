# async-opcua — Codebase Review

**Date:** 2026-06-16
**Scope:** Full workspace review, weighted toward security-critical and recently-changed code
(secure-channel/chunking refactor, the "008" legacy-crypto feature, server session/subscription
handling, the untrusted-input decode surface, and the client connection state machine).
**Method:** Manual review of hand-written code across `async-opcua-core`, `-crypto`, `-server`,
`-client`, and `-types`. Generated code (`async-opcua-types/src/generated`, ~88k LOC) was
excluded except where it emits a notable pattern. All findings below were verified by reading the
referenced source.

---

## Executive summary

The library is well-engineered overall: the secure-channel handshake correctly rejects unknown,
unsupported, and (unless explicitly opted in) deprecated security policies *before* doing any
crypto; legacy crypto is runtime-gated off by default; client server-certificate validation is
correct and on by default; HMACs and the bulk of length-prefixed decoding are properly bounded;
and the recent "fix lock-across-await" work holds up in the session path.

The highest-priority issues cluster in three places:

1. **Unauthenticated remote DoS.** Several network-reachable panics and unbounded-resource paths.
   The decode layer has three stack-overflow recursion bugs reachable from a single crafted
   message; the legacy identity-decrypt path has two reachable panics that directly contradict the
   "panic-free identity paths" goal of the 008 work; the server has no per-connection in-flight
   request cap, no per-IP connection cap, and a global session limit that a single unauthenticated
   client can exhaust.
2. **Session-theft on `SecurityPolicy::None` endpoints** via cross-channel transfer of activated
   sessions.
3. **Repo hygiene / information disclosure.** Twelve throwaway developer-debris files are tracked
   in the repo root, including shell scripts that SSH to hardcoded public hosts as root with host-key
   checking disabled, and a config script containing a committed password hash.

Severity legend: **Critical** = unauthenticated remote crash/compromise or trivial full-service DoS;
**High** = security control bypass or reachable crash with preconditions; **Medium** = exploitable
under specific config / hardening gap; **Low** = latent / defense-in-depth.

---

## Critical

### C1 — Three unbounded-recursion stack overflows on the decode path (`async-opcua-types`)
A single crafted message of a few hundred KB triggers a stack overflow → process abort,
**unauthenticated**. The `DepthGauge` infrastructure exists and is threaded through `Context`, but
three decode functions never consult it:

- **`DiagnosticInfo::decode`** — `src/diagnostic_info.rs:231-267`. The `HAS_INNER_DIAGNOSTIC_INFO`
  branch recurses with no depth lock; ~1 attacker byte per level. Reachable directly (DiagnosticInfo
  is a field of many responses) and via `Variant` (the inline comment at `variant/mod.rs:632`
  falsely claims it is depth-checked).
- **`DataValue` ↔ `Variant` cycle** — `src/data_value.rs:213-219` + `src/variant/mod.rs:630-631`.
  `DataValue::decode` takes no lock and decodes a `Variant`; the `Variant` `DATA_VALUE` branch calls
  `DataValue::decode` back. ~2 bytes per level. Only the `Variant::Variant` case is depth-locked.
- **Dynamic struct decode** — `src/custom/custom_struct.rs:451-458`, `decode_type_inner`. Recurses
  through struct fields and calls `ctx.load_from_binary(...)` directly, bypassing the one guard on
  this path (`ExtensionObject::decode`). This is exactly the surface fuzzed by
  `fuzz/fuzz_targets/fuzz_dynamic_struct.rs`.

**Fix:** add `let _lock = ctx.options().depth_lock()?;` at the top of `DiagnosticInfo::decode`,
`DataValue::decode`, and `decode_type_inner` (or depth-lock the `DATA_VALUE`/`DIAGNOSTIC_INFO`
branches in `decode_variant_value`). One line each; the plumbing already exists.

### C2 — Two reachable panics in legacy identity-token decrypt (`async-opcua-crypto`)
Both are unauthenticated remote DoS via the ActivateSession path
(`async-opcua-server/src/session/negotiate.rs:29-51` → `legacy_secret_decrypt`), and both directly
contradict commit 60d1ee21 ("panic-free identity paths"):

- **Non-block-aligned ciphertext** — `src/user_identity.rs:248-261` →
  `src/aes/rsa_private_key.rs:240-273`. `private_decrypt` slices the input in fixed RSA-block-size
  chunks with no check that `secret.len()` is a non-zero multiple of the block size → out-of-bounds
  slice panic. The sibling OAEP path (`identity/rsa_oaep.rs:46-51`) *does* guard this with
  `is_multiple_of(block_size)`; the legacy path was missed.
- **Nonce-extraction underflow** — `src/user_identity.rs:291-301`. `plaintext_size` is read from
  attacker-decryptable bytes (the client encrypts arbitrary plaintext with the server's public key);
  `nonce_begin = actual_size - nonce_len` underflows (panic in debug, huge value → slice panic in
  release) when the crafted `plaintext_size + 4 < server_nonce.len()`.

**Fix:** reject empty / non-block-multiple input before slicing in `legacy_secret_decrypt` /
`private_decrypt`; validate `actual_size >= nonce_len + 4` before computing `nonce_begin`. Return
`BadIdentityTokenInvalid` / `BadSecurityChecksFailed`.

### C3 — Single connection can exhaust server memory: unbounded in-flight request queue (`async-opcua-server`)
`src/session/controller.rs:601-642`, queue at `:87`. Every async service request is pushed into an
**uncapped** `FuturesUnordered`, and `poll()` keeps reading new requests while prior ones are
pending. One client can pipeline requests faster than they complete, growing the boxed-future heap
without bound. No per-connection concurrency limit exists anywhere in the path.
**Fix:** apply backpressure — stop polling the transport for new messages past a configurable
in-flight limit, or reject with `BadTooManyOperations`.

### C4 — Single unauthenticated client can exhaust the global session pool (`async-opcua-server`)
`src/session/manager.rs:179-181, 278-279`; default `MAX_SESSIONS = 20` (`src/lib.rs:163`). The only
cap is one global `max_sessions`, and a session counts toward it at **CreateSession** time, before
activation/identity validation. Anonymous `SecurityPolicy::None` reaches CreateSession, so one
client can claim all 20 slots and lock out the entire server; unactivated sessions then live the
full `max_session_timeout_ms` (default 60s) with no short activation deadline.
**Fix:** add a per-secure-channel cap on unactivated sessions plus a short (few-second) unactivated
timeout, independent of the global cap.

---

## High

### H1 — `SecurityPolicy::None` sessions can be hijacked across secure channels (`async-opcua-server`)
`src/session/manager.rs:498-505, 525-531`. The channel-binding check is skipped once a session
`is_activated()` (to allow legitimate reconnect/transfer) — but the client-signature verification
that normally authenticates that transfer is *also* skipped when `security_policy == None`. The only
remaining protection is the 256-bit auth token, which travels in cleartext on every None-security
request. Any party that observes the token (passively, anywhere on path) can attach the activated
session to a new channel from a different connection and take it over.
**Fix:** for sessions created under `None`, refuse to transfer an already-activated session to a
different `secure_channel_id` (drop the `!is_activated()` short-circuit when no client signature can
be verified). At minimum, document that None endpoints offer no session-theft protection.

### H2 — Request-timeout cap is inverted: `max_timeout_ms` acts as a floor, not a ceiling (`async-opcua-server`)
`src/session/controller.rs:581` — `let timeout = max_timeout.max(timeout);`. Documented as a maximum
(`src/config/server.rs:273-279`), but `.max()` returns the *larger* of cap and client-requested
`timeout_hint`. A client requesting a 24h hint gets it. This defeats the server's
maximum-request-time protection and amplifies C3 (hung requests stay in the unbounded queue).
**Fix:** `if timeout == 0 { max_timeout } else { timeout.min(max_timeout) }`.

### H3 — No per-IP connection limit (`async-opcua-server`)
`src/server.rs:76-84, 474`; default `MAX_CONNECTIONS = 100`, hello timeout 5s. Only a global cap
exists, so a single IP can take all 100 slots, and can slowloris by opening connections and never
sending HELLO (recycled every 5s).
**Fix:** track and cap connections per remote IP; consider an accept rate limit.

### H4 — Per-subscription monitored-item limit is bypassable and unlimited by default (`async-opcua-server`)
`src/subscriptions/session_subscriptions.rs:285-322`; default `max_monitored_items_per_sub = 0`
(unlimited, `src/config/limits.rs:384`). The cache-level insert never checks the cap; the only check
is a service-layer pre-check evaluated before the cache lock is re-taken, so two concurrent
`CreateMonitoredItems` both pass. Each item is scanned every tick → memory/CPU exhaustion.
**Fix:** enforce the limit inside `create_monitored_items` (check `sub.len() + accepted`), and ship
a non-zero default.

### H5 — Server never validates client-certificate hostname or application URI (`async-opcua-server`)
`src/session/manager.rs:215-220` calls `validate_or_reject_application_instance_cert(&cert, policy,
None, None)` — both `hostname` and `application_uri` are `None`, and the corresponding checks in
`certificate_store.rs:404-411` only run when the argument is `Some`. Any cert in the trust store can
impersonate any application/host. OPC UA Part 4 expects the cert's application URI to match the
CreateSession request.
**Fix:** pass the client's declared `application_uri` (and endpoint hostname where applicable) into
the validation call.

### H6 — RSA PKCS#1 v1.5 (Basic128Rsa15) decrypt is a Bleichenbacher / padding-oracle surface (`async-opcua-crypto`)
`src/policy/aes.rs:254-266, 389-396`; distinguishable errors in `user_identity.rs:281-303`. The
`rsa` crate's PKCS1v15 decryption is not fully constant-time, and the layered distinguishable error
returns ("decrypt failed" vs "invalid plaintext size" vs "invalid nonce" vs "non-zero padding")
form a validity oracle. This is why Basic128Rsa15 is deprecated. Currently gated off by
`allow_legacy_crypto` (good).
**Fix:** keep it disabled by default; return a single uniform error with uniform timing on all
decrypt-failure paths; document the residual risk; discourage enabling it.

### H7 — Two reachable client-side panics from a malicious server (`async-opcua-client`)
- **`delete_subscriptions` index panic** — `src/session/services/subscriptions/service.rs:1931-1932`.
  Returns `result[0]` without validating the server returned a non-empty `results` array (unlike its
  siblings). A server returning `Good` + empty/null results panics the client.
- **Re-polling a completed `disconnect_fut`** — `src/session/event_loop.rs:181-223`. On the
  keep-alive/subscription-failure close path, `disconnect_fut` is a `BoxFuture` that is not fused and
  not replaced after completion; if the channel-closed race is lost, the next loop iteration polls
  the completed future → "polled after completion" panic.

**Fix:** guard with `.into_iter().next().ok_or(...)` and add a results-length check in
`DeleteSubscriptions::send`; set `disconnect_fut = futures::future::pending().boxed()` after the
disconnect arm fires (the sentinel already used at `event_loop.rs:264`).

### H8 — Non-constant-time comparison of the decrypted secret nonce (`async-opcua-crypto`)
`src/user_identity.rs:297` — `if nonce != server_nonce`. Plain `[u8]` `PartialEq` short-circuits;
this gates acceptance of an encrypted password and is part of the RSA-decrypt oracle surface (H6).
**Fix:** use `subtle::ConstantTimeEq::ct_eq` (as already done for HMACs via `verify_slice`).

---

## Medium

### M1 — Divide-by-zero / underflow panic on the transmit path (`async-opcua-core`)
`src/comms/chunker.rs:159` (`div_ceil`) rooted in `src/comms/message_chunk.rs:322`. When an OPN
chunk carries a large local certificate (up to `MAX_CERTIFICATE_LENGTH = 32767`) and the negotiated
chunk size is near `MIN_CHUNK_SIZE`, `aligned_max_chunk_size - header_size - signature_size -
minimum_padding` underflows, producing `max_body_per_chunk == 0` → `div_ceil(0)` panic. The
`max_chunk_size > 0` guard does not prevent it.
**Fix:** use checked subtraction in `body_size_from_message_size`, returning an error
(`BadRequestTooLarge`/`BadTcpInternalError`) when the headers don't fit; this also guarantees
`max_body_per_chunk >= 1`.

### M2 — Silent zero-padding masks any `byte_len()`/`encode()` mismatch as wire corruption (`async-opcua-core`)
`src/comms/chunker.rs:282-301`. `flush` zero-fills the final chunk to the predicted `byte_len()`
size instead of erroring when `encode()` wrote fewer bytes. The chunk header counts those zeros as
body, so the receiver mis-parses rather than failing cleanly. Bug-for-bug parity with the old buffer,
but it turns a contract violation into silent corruption.
**Fix:** treat a short plaintext encode as an error (or at minimum a debug assertion / metric).

### M3 — Key/secret material is not zeroized (`async-opcua-crypto`)
`src/aes/aeskey.rs:25-39`, `src/policy/aes.rs:19-40`, decrypted password `Vec<u8>` in
`user_identity.rs`, RSA private key. Session keys, signing keys, IVs, and decrypted passwords are
dropped without zeroization, leaving secrets recoverable in freed heap / core dumps.
**Fix:** wrap secret buffers in `zeroize::Zeroizing` / `ZeroizeOnDrop`; enable the `zeroize` feature
on the `rsa`/`aes` crates.

### M4 — `AesKey` derives `Debug` that prints raw key bytes (`async-opcua-crypto`)
`src/aes/aeskey.rs:25-26`. Any `{:?}` of a struct embedding an `AesKey` (e.g. via `tracing`) dumps
the session key. `PKey`/`X509` deliberately implement redacting `Debug`; `AesKey` does not.
**Fix:** custom redacting `Debug` impl.

### M5 — Notification pool blocks a tokio worker on a condvar under the subscription read lock (`async-opcua-server`)
`src/subscriptions/pool.rs:114-126` (parking_lot `Condvar::wait`), called from
`subscription.rs:553`, while `periodic_tick` holds `trace_read_lock!(self.inner)` for the whole loop
(`subscriptions/mod.rs:234-244`). With a small operator-configured `max_notification_pool_size` and
concurrent ticks, `acquire()` blocks an OS worker thread and stalls all writers to `inner` (no new
sessions/subscriptions). Blocking a tokio worker is an anti-pattern regardless.
**Fix:** make pool exhaustion non-blocking (fall back to a fresh allocation / `try_acquire`); never
hold `inner` while a tick can block.

### M6 — Username authentication is a timing oracle for user enumeration (`async-opcua-server`)
`src/authenticator.rs:232-273, 357-365`. Argon2 runs only when a matching username with a stored
hash exists; unknown usernames return immediately. The timing difference reveals valid usernames.
**Fix:** always run a dummy Argon2 verification against a fixed decoy hash on the not-found path.

### M7 — `max_queued_notifications` is not a hard bound; full-queue drops break republish (`async-opcua-server`)
`src/subscriptions/subscription.rs:580-588`. A single tick that produces multiple
`NotificationMessage`s can exceed the cap by (messages − 1); and when full, the oldest *already
sequence-numbered but never sent* message is dropped with only a `warn!`, creating an
unrecoverable gap in `available_sequence_numbers` that the client cannot republish.
**Fix:** truncate the queue from the front to the cap after the enqueue loop; surface the drop as a
status-change/diagnostic so clients handle the gap.

### M8 — Client discovery is unauthenticated and the selected endpoint cert is not pinned (`async-opcua-client`)
`src/session/client.rs:258-333, 591-619`, `src/session/connection.rs:333-346`. GetEndpoints runs
over an unsecured channel; a MITM can rewrite offered endpoints (cert, `security_level`).
Standalone the attack still fails because the default trust store rejects the unknown cert — but it
is the enabling half of M9, and the client trusts the server-reported `security_level`.
**Fix:** offer an API to pin an expected server cert/thumbprint, checked before connect; document
that discovery endpoints are untrusted until validated.

### M9 — `trust_server_certs = true` auto-trusts any unknown server cert, and the samples enable it (`async-opcua-client`)
`src/certificate_store.rs:341-344` writes an unknown cert straight into the trusted folder. Default
is `false` (safe), but in-tree samples set `.trust_server_certs(true)` (`config.rs:659`, shown in
`lib.rs:54` docs), which users copy into production. Combined with M8 this is a clean MITM.
**Fix:** `warn!` when enabled (mirroring the legacy-crypto warning); stop using it in sample/doc code.

### M10 — Secure-channel renewal hardcodes a 30s timeout and doesn't tear down on failure (`async-opcua-client`)
`src/transport/channel.rs:185-198` (`Duration::from_secs(30)` at :189). Ignores configured request
timeout and `channel_lifetime`; if `channel_lifetime < 30s` the token can expire before renewal
times out, and a stalling server can wedge the client into repeated 30s renewal timeouts because the
channel isn't closed on failure.
**Fix:** derive the timeout from channel lifetime/config; close/flag the channel on renewal failure
so the event loop reconnects.

### M11 — Client accepts unbounded chunks when `max_chunk_count == 0`; unguarded `u32` sequence increment (`async-opcua-client`)
`src/transport/core.rs` (~247-387). The intermediate-chunk guard only fires when
`max_chunk_count > 0`, but 0 legally means "unlimited", so a malicious server can stream unbounded
chunks for one request id (memory DoS); `merge_chunks` uses `expect_sequence_number += 1` on
attacker-controlled values (debug overflow panic).
**Fix:** enforce a hard cap derived from `max_message_size`; use `wrapping_add`/`checked_add`.
(Confirm exact line numbers before patching.)

### M12 — `legacy-crypto` compiled in by default and `async-opcua-client` can't opt out (hygiene/feature)
`async-opcua-crypto/Cargo.toml:47-53` sets `default = ["legacy-crypto"]`, and
`async-opcua-client/Cargo.toml:37` depends on `async-opcua-crypto` *without*
`default-features = false` and exposes no `legacy-crypto` feature of its own. So a security-conscious
build using `default-features = false` on the umbrella crate still compiles SHA-1/Basic128Rsa15 into
the client path. Note: this is compile-time presence only — the runtime `allow_legacy_crypto` flag
defaults to `false` and the handshake/endpoint layers correctly enforce it, so default builds do not
*serve or negotiate* legacy crypto. Also, legacy minimum RSA key length is 1024 bits
(`policy/aes.rs:604`).
**Fix:** add a `legacy-crypto` feature to the client crate forwarding to
`async-opcua-crypto/legacy-crypto`, and set `default-features = false` on the dependency. Consider
raising the legacy minimum key length above 1024.

### M13 — History continuation points ignore the configured maximum (`async-opcua-server`)
`src/session/instance.rs:263-274`. Unlike browse/query continuation points, history ones insert
unconditionally and the returned `Result` is meaningless, so `max_history_continuation_points` is a
no-op and client-driven history reads can grow per-session memory.
**Fix:** enforce the cap and return `Err(())` when exceeded, mirroring browse/query.

### M14 — `subscription_priority` sorted ascending — lowest priority served first (`async-opcua-server`)
`src/subscriptions/session_subscriptions.rs:645` (`sort_by_key(|s1| s1.1)`). OPC UA Part 4 requires
higher-priority subscriptions serviced first when publish requests are scarce; this is inverted.
**Fix:** `sort_by_key(|s| Reverse(s.1))`.

---

## Low

- **L1 — `unsafe impl Send`/`unsafe impl Sync` on 305 generated types** (`async-opcua-types/src/generated/types/*.rs`).
  Currently *sound* — every generated struct is plain owned data (no raw pointers, `Rc`, `Cell`,
  `PhantomData`; verified by grep) and would auto-derive both traits, so the impls are redundant.
  The hazard: `unsafe impl` opts out of the compiler's automatic field-driven check and replaces it
  with hand-emitted `where Field: Send` bounds. If a future schema/codegen change introduces a
  generic parameter, a non-`Send` field, or a stale bound list, the `unsafe impl` will force
  `Send`/`Sync` where the auto-derive would correctly refuse — real unsoundness with no compiler
  error. **Fix:** stop emitting these from codegen and rely on auto-derivation.

- **L2 — `SecureChannel.allow_deprecated` defaults to `true`** (`async-opcua-core/src/comms/secure_channel.rs:102,147`).
  Safe today only because the server controller calls `set_allow_deprecated(config.allow_legacy_crypto)`.
  Fail-open default; any alternate construction path that forgets the call silently re-enables
  deprecated policies. **Fix:** default to `false`.

- **L3 — Underflow panic in `verify_padding` on crafted ciphertext** (`secure_channel.rs:1060,1083`).
  `padding_end - padding_size - 2` underflows when attacker-controlled `padding_size` is large;
  network-reachable on the receive path. **Fix:** `checked_sub` → `BadSecurityChecksFailed`.

- **L4 — `verify_signature_data` ignores the signature's declared algorithm** (`async-opcua-crypto/src/lib.rs:158-183`).
  Not exploitable (policy selects the verifier), but a forged `algorithm` field is silently accepted.
  Validate it for defense-in-depth.

- **L5 — Private key written to disk without `0o600`** (`async-opcua-crypto/src/gds_reload.rs:36-39`,
  `certificate_store.rs:590-603`). On multi-user hosts the key may be group/world readable.
  **Fix:** set mode `0o600` via `OpenOptions` + `PermissionsExt`.

- **L6 — JWT validator does not check `nbf`** (`async-opcua-crypto/src/identity/jwt_validator.rs:184-205`).
  `exp` is checked, `nbf` is not, so a not-yet-valid token is accepted. (`alg` is correctly pinned to
  RS256 — no `alg:none` bypass.) **Fix:** validate `nbf`.

- **L7 — Empty-password accounts authenticate any empty password** (`async-opcua-server/src/authenticator.rs:243-248`).
  A configured user with no stored hash accepts any empty password — effectively passwordless.
  Make explicit/gated and document.

- **L8 — Reachable `panic!` on invalid `password_security_policy` if config validation is bypassed**
  (`async-opcua-server/src/config/endpoint.rs:272-278`, `authenticator.rs:377,393`). Unreachable for
  a validated config, but `ServerInfo`/`ServerConfig` can be assembled programmatically without
  validation, in which case a client-triggered username login panics. **Fix:** return a default /
  `Result` instead of `panic!` on a request hot path.

- **L9 — Server-signature failure silently degrades to a null signature** (`async-opcua-server/src/session/manager.rs:234-250`).
  On `create_signature_data` failure during CreateSession, the server substitutes
  `SignatureData::null()` rather than failing; a non-validating client proceeds unauthenticated.
  **Fix:** fail closed on a secured endpoint.

- **L10 — Issued-token policy-ID constants collide with username/password constants**
  (`async-opcua-server/src/identity_token.rs:15-18`). Identical strings ("userpass_none", …);
  harmless in `DefaultAuthenticator` but a latent bug if issued-token auth is added. **Fix:** give
  issued-token policies distinct IDs.

- **L11 — Unchecked array-dimension multiplications** — `custom/custom_struct.rs:495` (`u32`) and
  `array.rs:139` (`usize`). Debug panic / release wrap; the primary untrusted variant-decode path is
  already hardened with `checked_mul`, so impact is limited. **Fix:** use `checked_mul` for
  consistency.

- **L12 — Misc client robustness:** `DeleteSubscriptions::send` lacks the result-length validation
  its siblings have (`subscriptions/service.rs:802-842`); deprecation warning only fires on the
  retrying `connect()` path, not `connect_no_retry`; `max_failed_keep_alive_count == 0` silently
  disables disconnect-on-keepalive-failure (`event_loop.rs:175-176`); double/compounded reconnect
  backoff if callers use `connect` instead of `connect_no_retry` (`transport/channel.rs:240-262`).

- **L13 — `revised_max_keep_alive_count * 3` overflow** under operator misconfiguration
  (`session_subscriptions.rs:543`). Not client-controllable. **Fix:** `saturating_mul`.

- **L14 — `Thumbprint::new` panics on a non-20-byte digest** (`async-opcua-crypto/src/thumbprint.rs:31-38`).
  A `pub fn` with a latent panic; not currently reachable from untrusted input. **Fix:** return a
  `Result`.

---

## Repo hygiene / information disclosure

Twelve throwaway developer-debris files are **tracked in git** in the repo root (leftovers from an
AI-assisted legacy-crypto refactor). None belong in a published library. `.gitignore` does not cover
them.

| File | What it is | Concern |
|------|-----------|---------|
| `orchestrate.sh`, `deploy.sh` | SSH/SCP to hardcoded **public IPv6 hosts as root** with `StrictHostKeyChecking=no`, `killall`, `nohup` | **Highest priority.** Disables host-key verification (MITM), discloses infra topology, destructive remote `killall` |
| `fix_server_conf.sh` | Writes a server config to `/server.conf` | Contains a committed **argon2id password hash** for `sample1`, a hardcoded LAN IP, overwrites an absolute root path |
| `client.py`, `server.py` | Ad-hoc `asyncua` test scripts | Hardcode `opc.tcp://192.168.150.205:4840`; `server.py` is broken (uses `asyncua.ua` without importing) |
| `fix_crypto.py`, `fix_assertions.py`, `fix_tests.py`, `fix_use.py` | One-shot string-replacement refactor scripts on `*.rs` | `fix_crypto.py` produces invalid double `#[cfg(...)]` attributes; directly conflict with the project's "no ad-hoc string parsing" guideline |
| `pr231.diff` (27 KB), `pr_reviews.json` (12 KB), `pr_comments.txt` (0 B) | Saved diff / GitHub review dumps | Stale artifacts |

**Suggested cleanup (run when ready):**
```
git rm fix_crypto.py fix_assertions.py fix_tests.py fix_use.py fix_server_conf.sh \
       client.py server.py orchestrate.sh deploy.sh pr231.diff pr_comments.txt pr_reviews.json
```
Add `fix_*.py`, `pr_*.json`, `pr_*.txt`, `*.diff` to `.gitignore` to prevent recurrence. Treat the
committed password hash as compromised if it was ever reused.

### Dependency notes
- `serde_yaml = "^0.9"` (`Cargo.toml:52`) is **unmaintained** (acknowledged in the repo's own
  `pr_reviews.json`); plan a migration.
- `thiserror = "^1"` (`Cargo.toml:56`) — v2 available.
- `env_logger = "^0.10"` is behind current.

---

## Verified clean (notable negatives — no action needed)

- **Secure-channel policy enforcement.** The handshake rejects `Unknown`, unsupported, and (unless
  opted in) deprecated policies *before* any crypto, and enforces it consistently across discovery,
  OpenSecureChannel, and ActivateSession — the classic "filter the advertised list but still accept
  the connection" bug is **not present**. Endpoint matching requires exact policy+mode equality, so
  no security-mode downgrade. `allow_legacy_crypto` defaults to `false`.
- **Lock-across-await.** The "fix lock-across-await bugs" work holds: session-path `parking_lot`
  guards are confined to non-await blocks, and key material is cloned out before `.await`. No tokio
  guard held across await found in the reviewed session/transport code.
- **Client server-cert validation** is correct and on by default (trust-folder membership, on-disk
  byte equality, key length, time validity, hostname, application URI, plus server-signature
  verification over client cert + nonce). MITM with an arbitrary cert is rejected by default.
- **Bounded decoding.** `UAString`/`ByteString`/array/`Option<Vec>` decode all check the length
  prefix against the configured maximum *before* allocating; negative lengths rejected; `read_exact`
  throughout. `Variant` array-dimension product uses `checked_mul`. `ExtensionObject::decode` is
  correctly depth-locked.
- **Session auth tokens** are 256-bit CSPRNG values looked up via hash map (not byte-compared);
  CreateSession session-count check is atomic under the manager write lock (no TOCTOU); actor
  cleanup removes tokens on panic via `catch_unwind`.
- **Crypto basics:** nonces from `rand::thread_rng()` (CSPRNG) with policy-correct lengths and
  receive-side length enforcement; HMAC verification is constant-time (`verify_slice`); asymmetric
  signature verification cannot be bypassed by a "None" algorithm.
- **Core receive path:** chunk counts bounded by callers before `Chunker::decode`; sequence-number
  wraparound logic (including the legacy "<1024 after wrap" case) is correct and well-tested.

---

## Suggested remediation order

1. **C1, C2** — the decode recursion guards (one line each) and the two legacy-decrypt input checks.
   Cheapest fixes, unauthenticated remote crashes, and C2 directly closes a stated 008 goal.
2. **C3, C4, H2, H3, H4** — server resource limits (in-flight cap, per-IP cap, session pool, timeout
   inversion, monitored-item cap). Together these close trivial single-client/single-IP DoS.
3. **H1, H5** — None-session transfer hardening and client-cert URI/hostname binding.
4. **H7, M10, M11** — client robustness against a malicious server.
5. **Repo hygiene** — `git rm` the 12 debris files (start with `orchestrate.sh`/`deploy.sh`).
6. Remaining Medium/Low items as normal hardening, ideally each with a regression test per the
   project's own `.einarmo_guidelines.md` convention ("tests for bugs").
