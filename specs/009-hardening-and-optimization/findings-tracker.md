# Findings Tracker — Feature 009 (Codebase Hardening, Cleanup & Optimization)

**Purpose.** Satisfy **SC-009**: every finding from the five 2026-06-16 review documents is
either **fixed** (with a task + commit/test reference) or **deferred** (with an explicit, justified
rationale). None silently dropped.

**Source reviews.** `docs/CODE_REVIEW_2026-06-16.md`, `docs/SECURITY_AUDIT_2026-06-16.md`,
`docs/NETWORK_REVIEW_2026-06-16.md`, `docs/PERFORMANCE_AUDIT_2026-06-16.md`,
`docs/ARCHITECTURE_REVIEW_2026-06-16.md`.

**Owner.** All implementation landed via the codex engineer; testing/verification/validation and the
non-coding tasks (CI, docs, this tracker, version/CHANGELOG) by Claude.

**Status legend.** `fixed` = remediated + verified green this feature. `deferred` = recorded SC-009
deferral (rationale below + mirrored in `tasks.md` → "Consciously deferred findings"). `partial` =
one leg done, remainder deferred.

**Per-user-story commits.**

| Story | Commit | Theme |
|-------|--------|-------|
| C1/C2 pre-US | `6bfaf01b`, `55eed1c0` | decoder recursion bound; legacy token ciphertext validation |
| US1 | `14da7d9d` | server survives malicious & malformed input |
| US2 | `9366edb0` | client survives a malicious/unreliable server |
| US3 | `547cbfbd` | cryptographic & authentication weaknesses |
| US4 | `55dd35e1` | clean repo & supply chain |
| US5 | `a903156f` | latency, throughput & idle-cost hardening |
| US6 | `6ea75c21` | structural soundness & breaking type changes |
| verify | `71779af4` | client `allow_legacy_crypto` wiring; full suite green |

---

## Fixed findings

| Finding | Sev | Task(s) | Commit | Verification |
|---------|-----|---------|--------|--------------|
| C1 unbounded decode recursion | Crit | T011–T015 | `6bfaf01b`/`14da7d9d` | `async-opcua-types` `recursion_dos.rs` (depth-bounded decode) |
| C2 legacy identity-token ciphertext not validated | Crit | T016–T017 | `55eed1c0` | crypto unit tests (`authentication.rs`) |
| C3 unbounded in-flight request queue (≡ R4 bulkhead) | Crit | T018–T019 | `14da7d9d` | `controller.rs` in-flight cap test; integration suite |
| C4 unactivated-session exhaustion | Crit | T020–T021 | `14da7d9d` | `session/manager.rs` cap; config-default tests |
| H1 None-policy session cross-channel transfer | High | T049 | `547cbfbd` | code change + behavioral test (T048, done) |
| H2 oversized message pre-allocation | High | T022–T023 | `14da7d9d` | limits tests |
| H3/N10 per-IP connection cap | High | T024–T025 | `14da7d9d` | `transport/tcp.rs` per-IP cap test |
| H4 monitored-items-per-subscription cap | High | T026–T027 | `14da7d9d` | `limits.rs` default test |
| H5 client cert / applicationUri binding | High | T051 | `547cbfbd` | enforced in CreateSession; surfaced + fixed integration harness (`71779af4`) |
| H7 empty-results client panic | High | T037 | `9366edb0` | code change + behavioral test (T035, done) |
| H8 (auth/cert hardening) | High | T053 | `547cbfbd` | crypto/server tests |
| M1 decode allocation guards | Med | T030–T031 | `14da7d9d` | types tests |
| M2 byte_len/encode mismatch silent corruption | Med | T095 | `6ea75c21` | `chunker.rs` returns `BadEncodingError` (core tests) |
| M6 username-auth timing oracle | Med | T058 | `547cbfbd` | argon2 decoy verification + error-uniformity test (T057, done) |
| M7 idle-cost / dead-peer detection | Med | T086 | `a903156f` | client default re-enabled; core/server tests |
| M9 client-side response validation | Med | T046 | `9366edb0` | client tests |
| M10/N9 stalled secure-channel renewal | Med | T043 | `9366edb0` | code change + behavioral test (T042, done) |
| M11 unbounded chunk stream / sequence overflow | Med | T045 | `9366edb0` | code change + tests (T044 ceiling + sequence_number.rs overflow, done) |
| M12 legacy crypto default-off (FR-019) | Med | T059 + verify | `547cbfbd`/`71779af4` | `legacy_crypto.rs` integration tests; server+client runtime gate wired |
| M13 | Med | T085 | `a903156f` | core/server tests |
| M14 | Med | T084 | `a903156f` | core/server tests |
| L1/R1 unsafe impls in generated code | Low | T091–T092 | `6ea75c21` | `codegen-tests` `generated_companion_structs_use_static_binary_impls` (asserts no `unsafe impl`) |
| L2 deprecated-policy default | Low | T060 | `547cbfbd` | core tests (`set_allow_deprecated`) |
| L3, L4, L5, L6, L7, L8 | Low | T032/T033/T061–T064 | US1/US3 | per-crate unit tests |
| L9 client cert URI validation in CreateSession | Low | T065 | `547cbfbd` | integration suite (harness URI aligned, `71779af4`) |
| L14 | Low | T067 | `547cbfbd` | unit test |
| N1/N3 TCP_NODELAY + SO_KEEPALIVE (FR-026) | — | T074–T075 | `a903156f` | core/server tests |
| N2 connect timeout | — | T039 | `9366edb0` | code change (behavioral test deferred → T038) |
| N8 backpressure | — | T040–T041 | `9366edb0` | client tests |
| PERF-P1–P4 | — | T076–T079 | `a903156f` | round-trip + `byte_len` O(1) tests |
| PERF-P5 ByteString zero-copy (FR-045) | — | T096 | `6ea75c21` | types tests; `Bytes`-backed |
| PERF-P6, P7 | — | T080–T081 | `a903156f` | core tests |
| N7 vectored multi-chunk writes | — | T083 | `a903156f` | `test_buffer_read_uses_vectored_write` (scalar=0, vectored=1) |
| PERF-P10 Arc-shared retransmission (FR-045) | — | T097 | `6ea75c21` | server subscription tests |
| PERF-P12 encode/decode + secure-channel benches | — | T001/T002/T003 | (US5 follow-up) | criterion benches run; baseline in benchmarks-baseline.md (T090/T098 caveat: benches added post-optimization) |
| R2 `Error` at service boundaries (FR-037) | — | T094 | `6ea75c21` | client/server compile + tests |
| R3 NodeManager capability traits (FR-043) | — | T093 | `6ea75c21` | server compile + tests |
| R5 opc.wss WebSocket transport (FR-044) | — | T088/T089 | (US5 follow-up) | client+server `wss` feature; `wss_round_trip_none_policy` (TLS1.3 + ALPN opcua+uacp + full handshake + Read) passes; secure-by-default TLS per security review |
| D1 aws-lc-rs constant-time RSA (FR-042) | — | T054–T055 | `547cbfbd` | crypto tests; documented in `docs/setup.md` |
| D2 EOL TLS stack removed (FR-023) | — | T069 | `55dd35e1` | dependency tree clean; build green |
| D5 serde_yaml → serde_norway | — | T071 | (US4 follow-up) | library crates migrated; `cargo build --all-features` + core/server YAML round-trip tests green; serde_yaml now only transitive via log4rs (demo-server sample) |
| SEC-P1/FR-022 cargo-deny advisory gate | — | T004–T005 | `55dd35e1` | `deny.toml` + CI `cargo-deny` job |
| SEC-P2/FR-025 | — | T073 | `55dd35e1` | build/tests |
| SEC-P3/FR-021 | — | T068 | `547cbfbd` | tests |
| SC-008 warning-free 3-config build matrix | — | T007/T100 | `71779af4` | CI `build-matrix` job; local `-D warnings` ×3 configs clean |
| SC-003 no secrets in logs | — | T103 | (verify) | `RUST_LOG=trace` username/password lifecycle: 0 plaintext-password occurrences |
| SC-011 CHANGELOG + 0.19.0 bump | — | T099 | `71779af4` | `CHANGELOG.md`; all crates `0.19.0`; `Cargo.lock` updated |

---

## Deferred findings (SC-009 — recorded, justified, not silently dropped)

Full rationales live in `tasks.md` → "Consciously deferred findings". Summary:

| Finding | Task | Why deferred |
|---------|------|--------------|
| M8 cert/thumbprint pinning API | T047 | **DONE (2026-06-18)** — opt-in discovery-endpoint cert pinning on ClientBuilder, fail-closed. |
| L10 issued-token policy-ID collision | T066 | **DONE (2026-06-18)** — distinct `issued_*` policy ids. |
| L11 unchecked array-dim `checked_mul` | — | Debug-panic/release-undersized only; primary untrusted path already hardened. |
| L13 keep-alive `*3` overflow | — | Operator-misconfig only, not client-controllable. |
| N4 SO_SNDBUF/RCVBUF sizing | — | OS auto-tuning adequate on modern Linux. |
| N13 LDS re-registration backoff | — | Behind optional feature; no confirmed defect. |
| cert-expiry monitoring hook | — | Additive operability feature, not a defect. |
| PERF-P9 inline fast path for small Reads | T082 | Measure-first (needs P12 benches); trades away per-request panic isolation. |
| PERF-P11 retransmission-queue O(n) scan | — | Audit judged acceptable for the short, bounded queue. |
| PERF-P12 benches + baseline | T001/T002/T003/T090/T098 | Perf changes verified functionally; criterion regression-guard infra is follow-up. |
| R6/FR-031 transport metrics + exporter | T087 | **DONE (2026-06-18)** — relaxed AtomicU64 counters + snapshot accessor + default-off `metrics-exporter`. |
| R7b/R7c/R8 | — | Packaging/build-hygiene/docs polish outside the clarified scope. |
| US2 behavioral tests | T035/T042/T044 | **DONE (2026-06-18)** — written on the T009 hostile-server harness (T035/T042) + a transport unit test (T044). T038 already done earlier. |
| US3 behavioral tests | T048/T057 | **DONE (2026-06-18)** — T048 via extracted-guard truth-table unit test, T057 via auth error-uniformity unit test. T050 already done earlier. |
| Test infra | T009 (done) / T008 (subsumed) | **T009 DONE** (evil-proxy harness). **T008 subsumed** — crafted payloads already inline in consuming tests + the harness. |
| SC-010/FR-046 interop gate (run) | T101 | Cannot run locally: no .NET runtime / no open62541 toolchain / network unreachable. |
| Interop CI gate — open62541 leg | T006 (partial) | Raw C++ source with no automated runner/orchestration; no toolchain/network to build+verify a gate. **dotnet leg is wired** (`test-external-server`). |

---

## Verification gate (final)

- `cargo test --workspace --all-features --offline` (CI config): all suites green, 0 failures.
- `async-opcua` integration suite: **98 passed, 0 failed** (97 opc.tcp + 1 opc.wss round-trip).
- `-D warnings` clean: default, `--all-features` (full workspace, includes `wss`), `--no-default-features` (library crates), and the `wss` feature on core/client/server.

> **R4 ≡ C3**: architecture R4 (request-path bulkhead) is the same finding as code-review C3; covered by T018–T019, not deferred.
