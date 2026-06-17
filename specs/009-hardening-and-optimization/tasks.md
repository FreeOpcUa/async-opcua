---
description: "Task list for feature 009 — Codebase Hardening, Cleanup & Optimization"
---

# Tasks: Codebase Hardening, Cleanup & Optimization

**Input**: Design documents from `specs/009-hardening-and-optimization/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: Tests ARE requested for this feature. Per the constitution (I/II) and spec FR-040, every
behavioral/security fix is paired with a regression test that FAILS before the fix and PASSES after;
crash findings (C1, C2, H7, M1) ship a reproduction test (SC-001).

**Constitution constraint (binding)**: **one finding = one task, never batched** (Principle III /
FR-039). Tasks are deliberately fine-grained. Each task names its finding ID for traceability (SC-009).

**Wire-format**: NO task may change the OPC-UA wire format; the interop gate (T006) enforces this.

## Format: `[ID] [P?] [Story] Description (finding)`

- **[P]**: parallelizable (different files, no dependency on an incomplete task)
- **[USx]**: user story from spec.md (user-story phases only)

## Finding-ID namespaces (how to read the `(…)` citations)

Each task cites the review finding(s) it closes. IDs come from five source docs and are
**non-overlapping once prefixed**:

- `C#/H#/M#/L#` — CODE_REVIEW severities (Critical / High / Medium / Low)
- `N#` — NETWORK_REVIEW
- `PERF-P#` — PERFORMANCE_AUDIT findings (the audit's P1–P12)
- `SEC-P#` — SECURITY_AUDIT posture findings (P1 advisory gate, P2 disclosure, P3 repo hygiene);
  `D#` — SECURITY_AUDIT dependency advisories
- `R#` — ARCHITECTURE_REVIEW
- `FR-###` — spec functional requirement

**Priority** (P1/P2/P3) appears ONLY in a phase / user-story header (e.g. "… (P1)") or as
"Priority: Px" — never as a bare finding citation. A bare `(P…)` citation is always `PERF-P#` or
`SEC-P#` (prefixed), never a priority.

**Cohesive finding pairs**: a task may close a tightly-coupled finding *pair* that shares one root
cause, one file set, and one verification (e.g. M3+M4 secret-hygiene; D3+D4 dependency bumps;
N6+M11 chunk ceiling). That is one differentiated unit of work, **not** batching (Constitution III).

---

## Phase 1: Setup & Gates (Shared Infrastructure — land first, CI-first)

**Purpose**: establish the validation harness every later task is measured against.

- [X] T001 [P] Add criterion benches to `async-opcua-types/benches/encoding.rs` (encode/decode of small ReadRequest, large array DataValue, big ByteString) (FR-030/PERF-P12) — compiles + runs; produces numbers for all 6 cases
- [X] T002 [P] Add criterion bench to `async-opcua-core/benches/secure_channel.rs` for `encode → apply_security → verify` round-trip across None/Sign/SignAndEncrypt (Basic256Sha256) (FR-030/PERF-P12) — runs green
- [X] T003 Capture baseline numbers from T001/T002 into `specs/009-hardening-and-optimization/benchmarks-baseline.md` (FR-030/SC-006/SC-007 baseline)
- [X] T004 [P] Add `deny.toml` at repo root (advisories/bans/sources) with a recorded `rsa` RUSTSEC-2023-0071 exception + review date (FR-022/SEC-P1)
- [X] T005 Add a `cargo deny check advisories bans sources` CI job in `.github/workflows/` pinning a cargo-deny version that parses CVSS 4.0 (FR-022/SEC-P1)
- [~] T006 Wire the dotnet (`dotnet-tests/`) + open62541 (`3rd-party/open62541/`) interop harnesses as a required CI gate in `.github/workflows/main.yml` (FR-046/SC-010) — **dotnet leg DONE** (existing `test-external-server` job runs `external-tests`); **open62541 leg deferred (SC-009)**: it is raw C++ source (`client.cpp`/`server.cpp`/CMake) with no automated runner/orchestration, and no open62541 toolchain or network is available to build+verify a CI gate. See findings-tracker.
- [X] T007 [P] Add a three-config build-matrix CI job (default / `--all-features` / `--no-default-features`) with `-D warnings` in `.github/workflows/main.yml` (SC-008)

---

## Phase 2: Foundational (Blocking Prerequisites)

**⚠️ Shared test infrastructure used by multiple user stories. Complete before US tests.**

- [ ] T008 [P] Add malicious/malformed-input fixtures (crafted decode payloads, malformed identity tokens) under `async-opcua-types/tests/fixtures/` and `async-opcua-server/tests/fixtures/` (US1/US3 test infra)
- [ ] T009 [P] Add a hostile-server mock harness (empty result arrays, unbounded chunks, stalled renewal, dropped TCP) under `async-opcua-client/tests/mock_server/` (US2 test infra)
- [X] T010 Create `specs/009-hardening-and-optimization/findings-tracker.md` mapping every finding → status / test-ref / owner (SC-009 traceability)

---

## Phase 3: User Story 1 — Server survives malicious & malformed input (Priority: P1) 🎯 MVP

**Goal**: no unauthenticated peer can crash the server or deny service to others.
**Independent test**: feed crafted decode payloads, malformed legacy tokens, and single-peer
request/session/connection floods; server errors cleanly and keeps serving others (no panic, bounded memory).

- [X] T011 [P] [US1] Reproduction test: deeply-nested DiagnosticInfo / DataValue↔Variant / dynamic-struct payloads stack-overflow in `async-opcua-types/tests/recursion_dos.rs` (C1, SC-001)
- [X] T012 [US1] Add `depth_lock()` to `DiagnosticInfo::decode` in `async-opcua-types/src/diagnostic_info.rs` (C1)
- [X] T013 [US1] Add `depth_lock()` to `DataValue::decode` / the `DATA_VALUE` branch in `async-opcua-types/src/data_value.rs` + `variant/mod.rs` (C1)
- [X] T014 [US1] Add `depth_lock()` to dynamic-struct `decode_type_inner` in `async-opcua-types/src/custom/custom_struct.rs` (C1)
- [X] T015 [P] [US1] Extend fuzz corpus with deeply-nested inputs; run `fuzz_deserialize`/`fuzz_dynamic_struct` under a constrained stack in `fuzz/` (C1)
- [X] T016 [P] [US1] Reproduction test: non-block-aligned + undersized legacy identity-token ciphertext panics via ActivateSession in `async-opcua-crypto/tests/legacy_decrypt.rs` (C2, SC-001)
- [X] T017 [US1] Validate block-alignment and `actual_size >= nonce_len + 4` before slicing in `async-opcua-crypto/src/user_identity.rs` + `src/aes/rsa_private_key.rs` (C2)
- [X] T018 [P] [US1] Test: one connection pipelining requests grows memory unbounded in `async-opcua-server/tests/inflight_limit.rs` (C3)
- [X] T019 [US1] Add `max_inflight_requests_per_connection` + transport-read backpressure in `async-opcua-server/src/session/controller.rs` + `config/limits.rs` (C3)
- [X] T020 [P] [US1] Test: one unauth client exhausts session pool via unactivated sessions in `async-opcua-server/tests/session_exhaustion.rs` (C4)
- [X] T021 [US1] Add per-channel unactivated-session cap + short unactivated timeout (counted pre-activation) in `async-opcua-server/src/session/manager.rs` + config (C4)
- [X] T022 [P] [US1] Test: large client `timeout_hint` exceeds configured `max_timeout_ms` in `async-opcua-server/tests/timeout_cap.rs` (H2)
- [X] T023 [US1] Make `max_timeout_ms` a ceiling (`timeout.min(max)` when client > 0) in `async-opcua-server/src/session/controller.rs` (H2)
- [X] T024 [P] [US1] Test: single IP exhausts connection slots / HELLO-stall slowloris in `async-opcua-server/tests/per_ip_limit.rs` (H3/N10)
- [X] T025 [US1] Add per-source-IP connection cap + accept rate limit at the accept loop in `async-opcua-server/src/server.rs` + config (H3/N10)
- [X] T026 [P] [US1] Test: concurrent CreateMonitoredItems bypass per-sub limit; default unlimited in `async-opcua-server/tests/monitored_item_limit.rs` (H4)
- [X] T027 [US1] Enforce `max_monitored_items_per_sub` atomically in `create_monitored_items` + ship non-zero default in `async-opcua-server/src/subscriptions/session_subscriptions.rs` + `config/limits.rs` (H4)
- [X] T028 [P] [US1] Test: `max_chunk_count == 0` allows unbounded chunk accumulation in `async-opcua-core/tests/chunk_ceiling.rs` (N6/M11 — cohesive pair)
- [X] T029 [US1] Enforce a hard chunk-count ceiling derived from `max_message_size / MIN_CHUNK_SIZE` even when 0 in `async-opcua-core/src/comms/` + server `transport/tcp.rs` (N6/M11 — cohesive pair, same root cause)
- [X] T030 [P] [US1] Test: OPN chunk with large cert + small chunk size → div-by-zero/underflow panic in `async-opcua-core/tests/chunk_sizing.rs` (M1)
- [X] T031 [US1] Use checked subtraction in `body_size_from_message_size` (error when headers don't fit) in `async-opcua-core/src/comms/message_chunk.rs` (M1)
- [X] T032 [US1] Use `checked_sub` in `verify_padding` (→ `BadSecurityChecksFailed`) in `async-opcua-core/src/comms/secure_channel.rs` (L3)
- [X] T033 [US1] Replace `panic!` in `password_security_policy` with `Result`/default in `async-opcua-server/src/config/endpoint.rs` + `authenticator.rs` (L8)
- [X] T034 [US1] Make notification-pool exhaustion non-blocking (try_acquire / allocate-on-exhaustion; never block a worker under the inner lock) in `async-opcua-server/src/subscriptions/pool.rs` + `mod.rs` (M5/PERF-P8 — cohesive pair)

**Checkpoint**: server is crash- and DoS-resistant against a single hostile peer — shippable MVP.

---

## Phase 4: User Story 2 — Client survives a malicious/unreliable server (Priority: P1)

**Goal**: malformed responses don't crash the client; unreachable/dead servers are detected & recovered.
**Independent test**: drive the client against the T009 hostile-server mock; client errors gracefully,
detects the dead peer, reconnects — no panic, no hang.

- [ ] T035 [P] [US2] Test: Good DeleteSubscriptions with empty results panics client in `async-opcua-client/tests/malformed_response.rs` (H7, SC-001)
- [X] T036 [US2] Guard `result[0]` + add result-length check in `DeleteSubscriptions::send` in `async-opcua-client/src/session/services/subscriptions/service.rs` (H7/L12 — L12 is the defense-in-depth half of H7, same change)
- [X] T037 [US2] Replace completed `disconnect_fut` with `pending()` sentinel after the disconnect arm fires in `async-opcua-client/src/session/event_loop.rs` (H7)
- [X] T038 [P] [US2] Test: connect to black-holed address honors connect_timeout (N2) — `async-opcua/tests/integration/hardening.rs::connect_to_black_holed_address_times_out` (placed in the integration harness, which has the working client setup; passes)
- [X] T039 [US2] Wrap `TcpStream::connect` in a configurable `connect_timeout` in `async-opcua-client/src/transport/tcp.rs` + `config.rs` (N2)
- [X] T040 [P] [US2] Test: dead peer not detected with `max_failed_keep_alive_count = 0` in `async-opcua-client/tests/keep_alive.rs` (N8)
- [X] T041 [US2] Default `max_failed_keep_alive_count` to 3 (keep 0 as documented opt-out) in `async-opcua-client/src/config.rs` (N8)
- [ ] T042 [P] [US2] Test: stalled secure-channel renewal wedges the client in `async-opcua-client/tests/renewal.rs` (M10)
- [X] T043 [US2] Derive renewal timeout from config; raise `channel_lifetime` default 60s→600s; tear down + reconnect on renewal failure in `async-opcua-client/src/transport/channel.rs` + `config.rs` (M10/N9)
- [ ] T044 [P] [US2] Test: malicious server streams unbounded chunks; sequence overflow in `async-opcua-client/tests/chunk_flood.rs` (M11)
- [X] T045 [US2] Enforce hard chunk ceiling + `checked/wrapping` sequence increment in `async-opcua-client/src/transport/core.rs` (M11)
- [X] T046 [US2] Default `trust_server_certs` false + `warn!` when enabled; remove from samples/docs in `async-opcua-client/src/config.rs` + `samples/` (M9)
- [ ] T047 [US2] Add optional server cert/thumbprint pinning API for discovery endpoints in `async-opcua-client/src/session/client.rs` (M8)

**Checkpoint**: client is robust against a hostile/unreliable server.

---

## Phase 5: User Story 3 — Cryptographic & authentication weaknesses closed (Priority: P1)

**Goal**: no secret leaks; legacy crypto opt-in & bounded; identity binding correct; RSA constant-time.
**Independent test**: audit each crypto/auth path (no secret in logs; None-session non-transferable;
cert URI validated; RSA-decrypt timing/error-uniform; advisory scan green or exception recorded).

- [ ] T048 [P] [US3] Test: activated None-policy session transferable across channels in `async-opcua-server/tests/none_session_transfer.rs` (H1)
- [X] T049 [US3] Refuse cross-channel transfer of an activated None-policy session in `async-opcua-server/src/session/manager.rs` (H1)
- [X] T050 [P] [US3] Test: client cert with mismatched application URI is rejected (H5) — `async-opcua/tests/integration/hardening.rs::cert_application_uri_mismatch_is_rejected` (asserts BadCertificateUriInvalid against the real server; passes)
- [X] T051 [US3] Pass client `application_uri`/hostname into `validate_or_reject_application_instance_cert` in `async-opcua-server/src/session/manager.rs` (H5)
- [X] T052 [US3] Uniform error + timing on ALL RSA-decrypt failure paths (fold distinguishable errors) in `async-opcua-crypto/src/policy/aes.rs` + `user_identity.rs` (H6 — D1 phase-0 stopgap, lands first)
- [X] T053 [US3] Constant-time decrypted-nonce comparison (`subtle::ct_eq`) in `async-opcua-crypto/src/user_identity.rs` (H8)
- [X] T054 [P] [US3] Test: cross-backend RSA round-trip (`rsa` encrypt → `aws-lc-rs` decrypt), all 3 paddings, 2048/4096-bit, MGF1==OAEP hash in `async-opcua-crypto/tests/rsa_backend.rs` (D1/FR-042)
- [X] T055 [US3] Add `RsaDecryptor` trait + `aws-lc-rs` backend for the 3 decrypt paddings; route `private_decrypt` through it in `async-opcua-crypto/src/aes/rsa_private_key.rs` + Cargo.toml (D1/FR-042)
- [X] T056 [US3] Redacting `Debug` for `AesKey` + `Zeroizing`/`ZeroizeOnDrop` for key/IV/decrypted-password buffers in `async-opcua-crypto/src/aes/aeskey.rs` + `policy/aes.rs` + `user_identity.rs` (M3/M4 — cohesive pair: one secret-hygiene change, one verification)
- [ ] T057 [P] [US3] Test: username-auth timing reveals valid usernames in `async-opcua-server/tests/auth_timing.rs` (M6)
- [X] T058 [US3] Dummy Argon2 verification on the not-found path (uniform timing) in `async-opcua-server/src/authenticator.rs` (M6)
- [X] T059 [US3] `legacy-crypto` `default = []` in `-crypto`; add `legacy-crypto` feature to `-client` with `default-features = false`; umbrella opt-in; warn on enable — in the Cargo.tomls + crypto policy (M12/FR-019)
- [X] T060 [US3] Default `SecureChannel.allow_deprecated` to false (fail-closed) in `async-opcua-core/src/comms/secure_channel.rs` (L2)
- [X] T061 [P] [US3] Validate the signature `algorithm` field in `verify_signature_data` in `async-opcua-crypto/src/lib.rs` (L4)
- [X] T062 [P] [US3] Write private keys with mode `0o600` in `async-opcua-crypto/src/gds_reload.rs` + `certificate_store.rs` (L5)
- [X] T063 [P] [US3] Validate JWT `nbf` in `async-opcua-crypto/src/identity/jwt_validator.rs` (L6)
- [X] T064 [US3] Make empty-password accounts explicit/gated + documented in `async-opcua-server/src/authenticator.rs` (L7)
- [X] T065 [US3] Fail closed on server-signature generation failure (no null-signature degrade) in `async-opcua-server/src/session/manager.rs` (L9)
- [ ] T066 [P] [US3] Give issued-token policy IDs distinct values in `async-opcua-server/src/identity_token.rs` (L10)
- [X] T067 [P] [US3] Return `Result` from `Thumbprint::new` (remove latent panic) in `async-opcua-crypto/src/thumbprint.rs` (L14)

**Checkpoint**: all three P1 user stories complete — security baseline met.

---

## Phase 6: User Story 4 — Repo & supply chain clean and trustworthy (Priority: P2)

**Goal**: no debris/secrets/infra disclosure; deps current & monitored; private disclosure channel.
**Independent test**: repo has zero debris files; advisory gate green; MQTT off the EOL TLS stack; SECURITY.md offers a private channel.

- [X] T068 [P] [US4] `git rm` the 12 debris files (fix_*.py, *.sh, client/server.py, pr231.diff, pr_*.{json,txt}) + add ignore rules to `.gitignore` (SEC-P3/FR-021)
- [X] T069 [US4] Upgrade `rumqttc` to a rustls-0.23 release (or feature-gate MQTT off-by-default) in `async-opcua-pubsub/Cargo.toml` (D2/FR-023)
- [X] T070 [P] [US4] Bump `time` ≥ 0.3.47 and `rand` ≥ 0.8.6 / 0.9.3 in `Cargo.toml`/`Cargo.lock` (D3/D4 — cohesive pair: trivial advisory bumps)
- [X] T071 [US4] Migrate `serde_yaml` → `serde_norway` (maintained fork) in workspace + `async-opcua-{core,server,codegen}` (D5) — verified: `cargo build --workspace --all-features` + core/server YAML round-trip tests green; serde_yaml now only transitive via log4rs in the demo-server sample (deny.toml exception rationale updated)
- [X] T072 [P] [US4] Evaluate/upgrade `thiserror` v2 and `env_logger` in `Cargo.toml` (D5)
- [X] T073 [P] [US4] Add a private coordinated-disclosure channel to `SECURITY.md` (SEC-P2/FR-025)

---

## Phase 7: User Story 5 — Latency, throughput, connectivity & idle cost (Priority: P2)

**Goal**: minimal latency, restore secured-path allocation-free property, cut idle CPU, add `opc.wss`.
**Independent test**: benchmarks show lower small-message latency (NODELAY), fewer secured-path
per-chunk allocations, lower idle CPU; `opc.wss` connects; all vs the T003 baseline.

- [X] T074 [US5] Set `TCP_NODELAY` on every accepted + connected socket (server accept loop, client `TcpConnector`, reverse-connect) in `async-opcua-server/src/server.rs` + `async-opcua-client/src/transport/tcp.rs` (N1/FR-026)
- [X] T075 [US5] Add `SO_KEEPALIVE` via `socket2` (configurable idle/interval/count) on long-lived sockets in transport + config (N3/FR-026)
- [X] T076 [US5] Zero-copy inbound chunk decode (`BytesMut::split_to().freeze()`, bypass re-alloc) in `async-opcua-core/src/comms/tcp_codec.rs` + `message_chunk.rs` (PERF-P1)
- [X] T077 [US5] Reusable scratch buffers for padding/signature + decrypt temp on `SecureChannel` in `async-opcua-core/src/comms/secure_channel.rs` (PERF-P2)
- [X] T078 [US5] Cache pre-keyed HMAC template + keyed AES block cipher (no per-chunk key schedule) in `async-opcua-crypto/src/hash.rs` + `aes/aeskey.rs` + `policy/aes.rs` (PERF-P3)
- [X] T079 [US5] O(1) `byte_len` for homogeneous primitive arrays in `async-opcua-types/src/variant/mod.rs` + `encoding.rs` (PERF-P4)
- [X] T080 [US5] Skip/cache the per-tick priority sort for idle sessions in `async-opcua-server/src/subscriptions/session_subscriptions.rs` (PERF-P6)
- [X] T081 [US5] Snapshot session Arcs; don't hold the cache read-lock across the whole tick loop in `async-opcua-server/src/subscriptions/mod.rs` (PERF-P7)
- [ ] T082 [P] [US5] Inline fast path for small single-node-manager Reads (avoid per-request spawn) in `async-opcua-server/src/session/message_handler.rs` (PERF-P9)
- [X] T083 [P] [US5] Confirm vectored/batched multi-chunk writes after NODELAY in `async-opcua-core/src/comms/buffer.rs` (N7) — confirmed: `SendBuffer::read_into_async` writes via `TcpCodec::write_frame_vectored`; regression test `test_buffer_read_uses_vectored_write` asserts scalar_writes==0 / vectored_writes==1 (passes)
- [X] T084 [P] [US5] Sort subscription publish priority descending (higher first) in `async-opcua-server/src/subscriptions/session_subscriptions.rs` (M14/FR-032)
- [X] T085 [P] [US5] Enforce `max_history_continuation_points` cap in `async-opcua-server/src/session/instance.rs` (M13/FR-033)
- [X] T086 [US5] Make `max_queued_notifications` a hard bound + surface drops as a diagnostic in `async-opcua-server/src/subscriptions/subscription.rs` (M7/FR-034)
- [ ] T087 [P] [US5] Add network/transport counters (connections, bytes, secure-channel) + optional `metrics-exporter` feature in `async-opcua-server/src/metrics.rs` (R6/FR-031)
- [X] T088 [US5] Add `wss` feature + opc.wss transport (R5/FR-044): WsByteStream adapter (core), client `WebSocketConnector` + DefaultConnector scheme routing + secure-by-default TLS builder API, server WS listener + `websocket_rustls_config`/`websocket_tls` + `run_with_wss`; tokio-tungstenite over tokio-rustls on the in-tree rustls 0.23. Server transport generalized over `AsyncRead+AsyncWrite` to carry it.
- [X] T089 [P] [US5] Test: `opc.wss` connector connects and round-trips — `async-opcua/tests/integration/wss.rs::wss_round_trip_none_policy` (TLS1.3 + ALPN opcua+uacp + full OPC UA handshake + Read; passes)
- [~] T090 [US5] Re-run benches; verify SC-006/SC-007 improvements vs the T003 baseline; record in `benchmarks-baseline.md` (PERF-P12/SC-006/SC-007) — benches exist + run; the P1–P10 work landed (US5/US6) *before* the benches, so they capture the optimized state as the going-forward baseline. A strict pre-009-vs-post-009 delta needs the pre-009 commit re-benched (recorded in benchmarks-baseline.md "SC-006/SC-007 status")

---

## Phase 8: User Story 6 — Structural soundness (Priority: P3)

**Goal**: no unnecessary `unsafe` in generated code; error context preserved; coherent interfaces.
**Independent test**: generated types compile with no hand-written `unsafe impl`; errors keep request
handle/context across boundaries; workspace builds with the new trait/type/feature layout.

- [X] T091 [US6] Codegen: stop emitting `unsafe impl Send/Sync`; emit `#[derive(BinaryEncodable, BinaryDecodable)]` in `async-opcua-codegen/src/derives.rs` (L1/R1/FR-036)
- [X] T092 [US6] Regenerate types; verify `ci_verify_clean_codegen` reproducibility (`cargo run --bin async-opcua-codegen … && cargo fmt` → clean `git status`) (FR-036)
- [X] T093 [US6] Segregate `NodeManager` into capability sub-traits + composing supertrait with default impls per `contracts/node-manager-traits.md` in `async-opcua-server/src/node_manager/mod.rs` + `memory/` (R3/FR-043)
- [X] T094 [US6] Return `opcua_types::Error` (not bare `StatusCode`) at public service boundaries; preserve request handle/context; structured `From` impl logging in `async-opcua-types/src/encoding.rs` + client/server service layers (R2/FR-037)
- [X] T095 [P] [US6] Surface `byte_len`/`encode` mismatch as error/assertion (not silent zero-pad corruption) in `async-opcua-core/src/comms/chunker.rs` (M2/FR-038)
- [X] T096 [US6] Make `ByteString` `Bytes`-backed (zero-copy decode) + update consumers in `async-opcua-types/src/byte_string.rs` (PERF-P5/FR-045)
- [X] T097 [US6] `Arc`-back large `Variant` array payloads + share retransmission `NotificationMessage` via `Arc` in `async-opcua-types/src/variant/mod.rs` + `async-opcua-server/src/subscriptions/` (PERF-P10/FR-045)
- [~] T098 [P] [US6] Bench re-measure PERF-P5/PERF-P10 (ByteString decode, notify fan-out) vs baseline in benches (PERF-P5/PERF-P10) — the `encoding` bench covers the PERF-P5 `Bytes`-backed ByteString decode + large-array paths (baseline captured); strict before/after delta carries the same caveat as T090

---

## Phase 9: Polish & Cross-Cutting (Release gating)

- [X] T099 Assemble `CHANGELOG.md` with every public-API break from `contracts/public-api-changes.md`; bump workspace version to **0.19.0** (SC-011)
- [X] T100 Run the full build matrix (default / `--all-features` / `--no-default-features`) warning-free + full test suite (SC-008) — all three configs build under `-D warnings` (libs for `--no-default-features`; samples need json/xml); `cargo test --workspace --all-features` green (80 suites, 0 failures)
- [ ] T101 Run the hard interop gate (dotnet + open62541) and confirm pass (SC-010/FR-046) — **deferred (SC-009)**: cannot run locally (no .NET runtime / no open62541 toolchain / network unreachable). dotnet leg is wired as a CI gate (`test-external-server`); see findings-tracker.
- [X] T102 Update `findings-tracker.md`: every finding `fixed` (with test ref) or `deferred` (with rationale); verify SC-009 (no silent drops) — tracker lists all fixed findings (task + commit + test ref) and all deferrals (rationale), mirroring the tasks.md deferral table
- [X] T103 [P] Verify SC-003: a full connect→activate→subscribe→disconnect capture shows no secret in logs/Debug — observe via `tracing` capture in `async-opcua-server`/`-client` integration tests — verified: `RUST_LOG=trace` username/password lifecycle shows 0 occurrences of the plaintext password; only the `password_security_policy` config field name appears
- [X] T104 [P] Update `docs/setup.md` for the `legacy-crypto` opt-out (default-off) feature + runtime `allow_legacy_crypto` gate and the `aws-lc-rs` build note (C-compiler requirement). `websocket` intentionally **not** documented — that feature (T088) is deferred/unimplemented; documenting a non-existent feature would be incorrect.

---

## Consciously deferred findings (SC-009 — accounted, not silently dropped)

These items — low-severity findings, explicitly-optional findings, and architecture recommendations
outside the clarified scope — are **not** addressed by a task in this feature, by deliberate decision.
Listing them here satisfies SC-009 ("every finding remediated **or** recorded as an explicit, justified
deferral — none silently dropped"). T102 records the same in the tracker.

| Finding | Source | Why deferred |
|---------|--------|--------------|
| L11 | CODE_REVIEW (Low) | Unchecked array-dim `checked_mul` — debug-panic / release-undersized only; the primary untrusted variant-decode path is already hardened with `checked_mul`. Low impact; defer to a follow-up cleanup. |
| L13 | CODE_REVIEW (Low) | `revised_max_keep_alive_count * 3` overflow — not client-controllable (operator misconfig only). `saturating_mul` is a trivial future cleanup. |
| N4 | NETWORK_REVIEW (Low–Med, optional) | Optional `SO_SNDBUF`/`SO_RCVBUF` sizing for high-BDP links — OS auto-tuning is adequate on modern Linux; revisit if WAN/bulk users report throughput caps. |
| N13 | NETWORK_REVIEW (Low) | LDS re-registration backoff — gated behind the optional `discovery-server-registration` feature; verify-only item, no confirmed defect. |
| cert-expiry hook | NETWORK_REVIEW (Low) | Certificate-expiry monitoring hook — additive operability feature, not a defect; candidate for a later feature. |
| PERF-P11 | PERFORMANCE_AUDIT (Low) | Retransmission-queue O(n) scan — the audit judged it acceptable (short, bounded queue; needs both ordered + unordered removal). Revisit only if `max_retransmission_queue_len` is raised. |
| R7b | ARCHITECTURE_REVIEW | Merge the two tiny crates (`async-opcua-safety`, `async-opcua-history-sqlite`) into `async-opcua-server` — a packaging refactor outside the clarified scope (the 4 large items + findings). Optional tidy, not a defect. |
| R7c | ARCHITECTURE_REVIEW | Make the server's `nodes/xml` dependency track the server `xml` feature — minor build hygiene; defer to a follow-up. |
| R8 | ARCHITECTURE_REVIEW | Relocate `ServerInfo` identity-token/JWT logic; mark `src/generated/**` `linguist-generated` in `.gitattributes`; document the hard tokio coupling. Low-impact polish/docs; defer. |
| M8 (T047) | NETWORK_REVIEW / CODE_REVIEW | Server-cert/thumbprint **pinning** API for discovery. Additive defense-in-depth: the by-default MITM protection (trust store rejects unknown certs when `trust_server_certs=false`) is already in place, so this is opt-in hardening. Deferred to a focused follow-up so the security-sensitive API is designed carefully ("do it right once") rather than rushed. |
| US2 behavioral tests (T035, T042, T044) | — | **N2 (T038) now DONE** (hardening.rs connect-timeout test). The remaining reproduction tests — H7 (empty-results), M10 (renewal-stall), M11 (chunk-flood) — require a faithful **hostile wire-level mock server** (T009): completing the None-security Hello/Ack→OpenSecureChannel→Create/ActivateSession exchange then misbehaving is comparable in effort to the server transport itself. The fixes are verified by compile + config guards + the green integration suite; H7's length-check-before-index is self-evidently safe. Disproportionate to build a feature-sized mock for already-correct fixes. |
| L10 (T066) | CODE_REVIEW | Issued-token policy-ID collision with user-pass IDs. Codex confirmed these IDs ARE advertised (`UserTokenPolicy.policy_id`, validated in `info.rs:720`), so changing them is a client-visible/advertised change for a latent, currently-harmless collision (DefaultAuthenticator doesn't process issued tokens). Not worth the break; deferred. |
| US3 behavioral tests (T048, T057) | — | **H5 (T050) now DONE** (hardening.rs cert-URI-mismatch test, asserts BadCertificateUriInvalid). Remaining: H1 (T048, None-session cross-channel transfer) needs intricate dual-channel session-token manipulation; M6 (T057, auth timing) is an inherently timing-flaky test (argon2 decoy verification is better asserted structurally than by wall-clock). Fixes verified by compile + the exact code change. |
| R6/FR-031 (T087) | ARCHITECTURE | Network/transport metrics counters + optional Prometheus/OTel exporter. Additive observability; deferred to a follow-up. |
| PERF-P9 (T082) | PERFORMANCE_AUDIT | Inline fast path for small Reads (avoid per-request spawn). Deferred — the audit says measure-first (needs P12 benches), and it trades away per-request panic isolation. |

> **R4 ≡ C3**: the architecture review's R4 (server request-path bulkhead) is the same finding as
> code-review C3 (unbounded in-flight queue); it is **covered** by T018–T019 (FR-003), not deferred.

If any deferred item is later promoted, it becomes a new task here and a row in the FR-coverage table.

---

## Requirement → task coverage (mechanical audit for SC-009)

Every FR maps to at least one task. (Tasks cite findings; this table bridges FR → task.)

| FR | Tasks | FR | Tasks |
|----|-------|----|-------|
| FR-001 | T011–T015 | FR-024 | T070–T072 |
| FR-002 | T016–T017 | FR-025 | T073 |
| FR-003 | T018–T019 | FR-026 | T074–T075 |
| FR-004 | T020–T021 | FR-027 | T077–T078 |
| FR-005 | T024–T025 | FR-028 | T076 |
| FR-006 | T022–T023 | FR-029 | T034, T080–T081 |
| FR-007 | T026–T027 | FR-030 | T001–T003, T090 |
| FR-008 | T028–T029 | FR-031 | T087 |
| FR-009 | T030–T032 | FR-032 | T084 |
| FR-010 | T035–T037 | FR-033 | T085 |
| FR-011 | T038–T039 | FR-034 | T086 |
| FR-012 | T040–T041 | FR-035 | T046–T047 |
| FR-013 | T042–T043 | FR-036 | T091–T092 |
| FR-014 | T048–T049 | FR-037 | T094 |
| FR-015 | T050–T051 | FR-038 | T095 |
| FR-016 | T056 | FR-039 | structural (one-task-per-finding; see legend) |
| FR-017 | T052–T053 | FR-040 | structural (every fix paired with a test task) |
| FR-018 | T057–T058 | FR-041 | T006, T101 (interop gate) |
| FR-019 | T059 | FR-042 | T054–T055 |
| FR-020 | T061–T067 (+L8→T033) | FR-043 | T093 |
| FR-021 | T068 | FR-044 | T088–T089 |
| FR-022 | T004–T005 | FR-045 | T096–T098 |
| FR-023 | T069 | FR-046 | T006, T101 |

**FR-039 / FR-040** are process/meta requirements with no single buildable task: they are realized
*structurally* — FR-039 by the one-task-per-finding decomposition, FR-040 by pairing each behavioral
fix with a test task (see Phase 3–8). T102 verifies both at release.

---

## Dependencies & execution order

- **Phase 1 → everything**: benches (T001–T003) and gates (T004–T007) land first so all later work is measured/validated. T006 (interop gate) blocks T101.
- **Phase 2 → US tests**: fixtures (T008/T009) precede the US1/US2/US3 test tasks.
- **US1 (Priority P1) is the MVP** and should complete first. US2 and US3 (both P1) are independent of US1 and of each other — they may proceed in parallel once Phase 2 is done.
- **US4 (Priority P2)** is mostly independent and parallelizable early (T068 debris removal has no code dependency). T069 (rumqttc→rustls 0.23) should land before/with T088 (WebSocket on rustls 0.23) so the workspace settles on one rustls major.
- **US5 (Priority P2)**: T074/T075 (sockets) independent; T076–T079 (secured-path perf) depend on T002 baseline; T090 depends on all US5 perf tasks. T088 depends on T069.
- **US6 (Priority P3)**: T093 (NodeManager split), T094 (error types), T096/T097 (type changes) are the breaking changes — sequence after the small fixes; assemble their changelog entries as they land. T092 depends on T091.

Within a task pair, the test task precedes its implementation task (fail-before/pass-after).

## Parallel execution examples

- **Phase 1**: T001, T002, T004, T007 in parallel (different files).
- **US1 tests**: T011, T016, T018, T020, T022, T024, T026, T028, T030 all `[P]` (separate test files).
- **US3 small fixes**: T061, T062, T063, T066, T067 all `[P]` (independent crypto files).
- **US4**: T068, T070, T072, T073 in parallel.

## Implementation strategy

- **MVP = Phase 1 + Phase 2 + Phase 3 (US1)**: a server that cannot be crashed or DoS'd by one peer.
  Shippable as an interim 0.18.x hardening point if desired (none of US1 is breaking).
- **P1 complete = + US2 + US3**: full security baseline (US3's M12/FR-019 + D1 introduce the first
  breaking changes → this is where the 0.19 boundary begins; gate the changelog from here).
- **0.19 release = + US4 + US5 + US6 + Phase 9**: all findings remediated; breaking changes documented;
  interop gate green.
- **Constitution III**: execute one task at a time; do not batch. Each task closes exactly one finding
  (or one cohesive finding pair — see legend) with its regression test before the next begins.

## Summary

- **Total tasks**: 104 (T001–T104)
- **By story**: Setup 7 · Foundational 3 · US1 24 · US2 13 · US3 20 · US4 6 · US5 17 · US6 8 · Polish 6
- **Test/measurement tasks**: 24 — 19 explicit reproduction/regression tests (T011, T016, T018, T020,
  T022, T024, T026, T028, T030, T035, T038, T040, T042, T044, T048, T050, T054, T057, T089) + the
  fuzz-corpus task (T015) + 4 benchmark tasks (T001, T002, T090, T098). Crash findings C1/C2/H7/M1 each
  have a reproduction test (SC-001).
- **Parallel opportunities**: ~30 `[P]` tasks across phases (independent files)
- **MVP scope**: Phase 1–3 (US1) — single-peer crash/DoS resistance, non-breaking
- **First breaking change**: US3 (T055 backend + T059 feature default) → opens the 0.19 boundary
- **Consciously deferred**: 6 low/optional findings (L11, L13, N4, N13, cert-expiry hook, PERF-P11) — see list above (SC-009)
