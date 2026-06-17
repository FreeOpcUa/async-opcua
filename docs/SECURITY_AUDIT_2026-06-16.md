# async-opcua — Security Audit

**Date:** 2026-06-16
**Target:** async-opcua workspace (OPC UA protocol library: client, server, crypto, pubsub).
**Audit type:** Source-level security audit + software-composition analysis (SCA). This is a
*library/protocol stack*, not a deployed web app, so the web-app pentest phases (Shodan, live SQLi/XSS,
Burp, Metasploit) do not apply — there is no running endpoint in scope. The audit is therefore
scoped to: (1) the network attack surface of the protocol implementation, (2) cryptographic
correctness, (3) third-party dependency vulnerabilities, and (4) security process/posture.
**Companion document:** protocol-level code findings are detailed in
[`CODE_REVIEW_2026-06-16.md`](./CODE_REVIEW_2026-06-16.md); this audit consolidates the
security-relevant subset and adds the supply-chain and posture analysis.

---

## 1. Methodology & tooling

| Activity | Tool / method | Result |
|----------|---------------|--------|
| Dependency CVE scan | RustSec advisory DB (queried directly) | 4 applicable advisories (see §4) |
| `cargo deny check advisories` | cargo-deny (installed) | **Failed to run** — aborts on a CVSS-4.0 advisory it can't parse; no `deny.toml` present |
| `cargo audit` | — | **Not installed** |
| SAST | manual review of hand-written decode/crypto/auth paths | findings in §5 / companion doc |
| Fuzzing review | `fuzz/fuzz_targets/` | 3 targets exist (`fuzz_comms`, `fuzz_deserialize`, `fuzz_dynamic_struct`) — good coverage of the decode surface, but did **not** catch the stack-overflow recursion bugs (§5, V1) |

A key process observation up front: **the project ships no automated dependency-vulnerability gate.**
None of the four CI workflows (`ci_clippy.yml`, `ci_code_coverage.yml`, `ci_verify_clean_codegen.yml`,
`main.yml`) run `cargo audit` or `cargo deny`, there is no `deny.toml`, and the one locally-installed
`cargo deny` is currently broken against the live advisory DB. Vulnerable dependencies therefore enter
unnoticed (see §4, §6-P1).

---

## 2. Attack surface / threat model

The trust boundary is the network. Two principal threat actors:

- **Malicious / unauthenticated OPC UA client** → attacks the **server** crate. Pre-authentication
  reachable surface: TCP HELLO, `OpenSecureChannel` (asymmetric crypto), the binary decoder (every
  field of every request), `CreateSession`/`ActivateSession`, and the identity-token decrypt path.
  This is the highest-value surface — anything reachable before authentication.
- **Malicious / MITM server** → attacks the **client** crate. Reachable surface: the binary decoder
  on every response, the discovery (`GetEndpoints`) flow (typically unauthenticated), the secure
  channel, and service responses.
- **Local / on-host** → key material on disk, secrets in memory/logs.

The decoder (`async-opcua-types`) and the crypto/handshake layer (`async-opcua-core`,
`async-opcua-crypto`) are the most exposed components because they process attacker-controlled bytes
*before* authentication completes.

OWASP mapping (where applicable to a protocol stack): **A02 Cryptographic Failures** (§4-D1, §5 crypto),
**A04 Insecure Design** (DoS limits, None-policy session transfer), **A06 Vulnerable & Outdated
Components** (§4), **A07 Identification & Authentication Failures** (§5 auth), **A09 Security Logging
& Monitoring Failures** (§6).

---

## 3. Risk summary

| ID | Severity | Category | Finding |
|----|----------|----------|---------|
| D1 | **High** | Crypto / components | `rsa 0.9.10` — Marvin timing attack (RUSTSEC-2023-0071), **no fix available**; used directly for all RSA operations |
| V1 | **Critical** | DoS | Three unauthenticated stack-overflow recursion bugs in the decoder |
| V2 | **Critical** | DoS | Two unauthenticated reachable panics in legacy identity-token decrypt |
| V3 | **Critical** | DoS / Insecure design | Single client/IP can exhaust server request queue, session pool, connection slots |
| V4 | **High** | AuthN | `SecurityPolicy::None` activated sessions hijackable across channels |
| V5 | **High** | AuthZ | Server does not validate client-cert hostname / application URI |
| D2 | **Medium** | Components | MQTT/pubsub path pins an **EOL TLS stack** (rustls 0.21 / webpki 0.101) via `rumqttc` |
| C1 | **Medium** | Crypto | Secrets not zeroized; `AesKey` `Debug` leaks key bytes; non-constant-time nonce compare |
| D3 | **Low** | DoS | `time 0.3.36` RFC-2822 stack-exhaustion (RUSTSEC-2026-0009) — likely unreachable |
| D4 | **Low** | Soundness | `rand 0.8.5/0.9.2` unsoundness (RUSTSEC-2026-0097) — narrow trigger |
| D5 | **Low** | Maintenance | `serde_yaml` + several transitive crates unmaintained |
| P1 | **Medium** | Process | No CI dependency-vuln gate; `cargo deny` broken; no `deny.toml` |
| P2 | **Low** | Process | `SECURITY.md` directs reporters to file a **public** issue (no coordinated/private disclosure) |
| P3 | **Medium** | Hygiene | Tracked debris discloses infra & a password hash (see companion doc) |

---

## 4. Software composition analysis (dependency vulnerabilities)

Verified against the RustSec advisory database, filtered to the **actually-affected locked versions**.
Many crates matched an advisory by name only but are already on a patched version and are **not**
affected (notably `ring 0.17.14`, `rustls 0.21.12`/`0.23.40`, `rusqlite 0.31`, `tokio 1.49`,
`chrono`, `base64`, `smallvec`, `tungstenite 0.21`) — these were checked and cleared.

### D1 — `rsa 0.9.10` · RUSTSEC-2023-0071 "Marvin Attack" · **High** · CVE-2023-49092
- **No patched version exists.** The RustCrypto `rsa` crate's RSA decryption is not constant-time;
  private-key information leaks through timing observable over the network, enabling key recovery.
- **Usage:** `async-opcua-crypto/Cargo.toml:39` depends on `rsa` directly. It backs every asymmetric
  operation — `OpenSecureChannel` asymmetric decrypt and the user-identity-token decrypt
  (`user_identity.rs`, `aes/rsa_private_key.rs`). Both are reachable by an unauthenticated client and
  involve the server's private key, so the timing oracle is network-exposed exactly as the advisory
  warns against.
- This is the supply-chain root of the code-review findings on the Bleichenbacher/PKCS#1v1.5 oracle
  and non-constant-time secret comparison (companion doc H6/H8).
- **Remediation:** there is no clean fix while on the `rsa` crate. Options, best-first: (a) migrate
  RSA operations to a constant-time backend (`aws-lc-rs`/`ring`-based, or OpenSSL via `openssl`),
  which the project already pulls `ring`/`rustls` so a backend exists; (b) at minimum, ensure all
  RSA-decrypt failure paths return a single uniform error with uniform timing (mitigates the
  application-level oracle even if the primitive remains variable-time); (c) document the residual
  risk in `SECURITY.md`. Track the advisory and pin a fixed `rsa` release when published.

### D2 — `rustls-webpki 0.101.7` (+ `rustls 0.21.12`) · EOL TLS stack · **Medium**
- Pulled transitively by **`rumqttc 0.23`**, which `async-opcua-pubsub/Cargo.toml:32` depends on
  directly (i.e. not just samples — the pubsub MQTT transport is on this stack), and by the
  `mqtt-client` sample.
- The 0.101 webpki line is end-of-life and carries unfixed advisories on that line:
  RUSTSEC-2026-0098/0099/0104 (X.509 name-constraint handling — URI/IP/DNS constraints
  incorrectly accepted). These are **low individual impact** (reachable only after signature
  verification, require a misissued certificate, and webpki exposes no URI-name assertion API), but
  the broader issue is that the MQTT/pubsub path rides an EOL TLS stack that will not receive future
  fixes. (Note: rustls 0.21.12 itself is *not* affected by RUSTSEC-2024-0399 — that bug is in the
  0.23.13–0.23.17 `Acceptor` path — but 0.21 is EOL regardless.)
- **Remediation:** upgrade `rumqttc` to a release built on rustls 0.23 / webpki 0.103+ (or feature-gate
  the MQTT transport so non-pubsub users don't compile it). Confirm the pubsub TLS path moves off the
  0.21/0.101 stack.

### D3 — `time 0.3.36` · RUSTSEC-2026-0009 · **Low** · CVE-2026-25727
- Stack-exhaustion DoS when parsing untrusted input with the **RFC 2822** format. Patched in 0.3.47.
- **Reachability:** low — OPC UA uses its own binary/`DateTime` encoding; the RFC-2822 parser is not
  on the protocol decode path as far as reviewed. Still, `time` is a transitive dep worth bumping.
- **Remediation:** bump the transitive `time` to ≥ 0.3.47 (`cargo update -p time`).

### D4 — `rand 0.8.5` & `rand 0.9.2` · RUSTSEC-2026-0097 (informational/unsound) · **Low**
- Unsoundness (UB) only when a *custom `log` logger* re-enters `rand::rng()`/`thread_rng()` during
  reseed — a narrow, unusual condition not met by this codebase's nonce generation.
- **Note:** `rand` is the CSPRNG behind nonce generation (`async-opcua-crypto/Cargo.toml:38`); the
  randomness *quality* is fine. This advisory is about reentrancy UB, not weak randomness.
- **Remediation:** bump to `rand` ≥ 0.8.6 / ≥ 0.9.3.

### D5 — Unmaintained crates · **Low**
- **`serde_yaml 0.9.34+deprecated`** — deprecated and unmaintained; used for config parsing.
  Acknowledged in the repo's own notes. Migrate to a maintained YAML crate (e.g. `serde_yml` or
  `serde_norway`) or drop YAML config.
- Transitive unmaintained crates (mostly via `rumqttc`): `instant`, `humantime`, `dirs`,
  `atomic-polyfill`, `tempdir`. Low risk individually; resolve by upgrading the parents.

---

## 5. Application-layer security findings (from source review)

Full detail and line references are in the companion code-review document; the security-relevant
subset, restated with audit severities:

- **V1 (Critical, DoS) — Decoder stack-overflow via unbounded recursion.** Three network-reachable
  paths abort the process from a single crafted message of a few hundred KB: `DiagnosticInfo`
  (`diagnostic_info.rs`), the `DataValue`↔`Variant` cycle (`data_value.rs` / `variant/mod.rs`), and
  dynamic-struct decode (`custom/custom_struct.rs`). The `DepthGauge` guard exists but isn't applied
  to these three. **The fuzz suite (`fuzz_deserialize`, `fuzz_dynamic_struct`) did not catch these** —
  recommend running the fuzzers with a constrained stack / ASAN and longer corpus to surface
  recursion DoS. *Fix: one-line `depth_lock()` in each.*
- **V2 (Critical, DoS) — Reachable panics in legacy identity-token decrypt.** Non-block-aligned
  ciphertext (OOB slice) and nonce-extraction underflow in `user_identity.rs` /
  `aes/rsa_private_key.rs`, reachable unauthenticated via `ActivateSession`. Directly contradicts the
  "panic-free identity paths" goal of the recent 008 work. *Fix: validate block alignment and
  `actual_size >= nonce_len + 4` before slicing.*
- **V3 (Critical, DoS / insecure design) — No resource limits against a single peer.** Unbounded
  per-connection in-flight request queue (`session/controller.rs`); a single unauthenticated client
  can claim all `max_sessions` (default 20) at `CreateSession` *before* activation; no per-IP
  connection cap (default 100 global); inverted request-timeout cap (`max_timeout_ms` acts as a floor).
  Together these allow trivial full-server denial of service from one connection/IP.
- **V4 (High, AuthN) — `SecurityPolicy::None` session hijack.** Activated None-policy sessions can be
  transferred to a new secure channel without a client-signature check; the only protection is the
  cleartext auth token (`session/manager.rs`). Any passive observer can steal the session.
- **V5 (High, AuthZ) — Client-cert identity not bound.** The server validates the client certificate
  against the trust store but passes `None` for hostname and application URI
  (`session/manager.rs:215-220`), so any trusted cert can impersonate any application/host (OPC UA
  Part 4 expects the cert application URI to match the CreateSession request).
- **C1 (Medium, Crypto hygiene) —** session keys / signing keys / decrypted passwords / RSA private
  key are not zeroized on drop; `AesKey` derives a `Debug` that prints raw key bytes (log-leak risk);
  the decrypted-secret nonce is compared with short-circuiting `!=` rather than constant-time.
- Plus the legacy-crypto compile-time exposure (client crate can't opt out of `legacy-crypto`),
  fail-open `allow_deprecated`/`trust_server_certs` defaults, private key files written without
  `0o600`, JWT `nbf` not checked, and several username-auth timing/enumeration issues — see companion
  doc M3/M4/M6/M8/M9/M12, L2/L5/L6/L7.

**Verified-clean (positive results):** the secure-channel handshake rejects unknown/unsupported/
(unless opted-in) deprecated policies before any crypto; `allow_legacy_crypto` defaults off and is
enforced consistently across discovery/OpenSecureChannel/ActivateSession (no advertise-but-accept
downgrade); the client validates server certificates correctly by default; length-prefixed decoding
(strings, byte strings, arrays) is bounded against configured maxima before allocation; HMAC
verification is constant-time; session auth tokens are 256-bit CSPRNG values.

---

## 6. Security process & posture

- **P1 (Medium) — No dependency-vulnerability gate in CI.** Add a `cargo deny check advisories`
  (or `cargo audit`) job to `main.yml`, and commit a `deny.toml`. The locally-installed `cargo deny`
  currently **aborts** on a CVSS-4.0 advisory in the DB — pin/upgrade `cargo-deny` to a version that
  parses CVSS 4.0 so the gate actually runs. Without this, D1–D5 would have shipped silently.
- **P2 (Low) — Disclosure policy invites public 0-day.** `SECURITY.md` asks reporters to "raise an
  open issue with the 'security' label" describing repro and a fix — i.e. public disclosure before a
  patch exists. Provide a private channel (GitHub private security advisories / a security email) and
  a coordinated-disclosure window.
- **P3 (Medium) — Repo hygiene / information disclosure.** Twelve tracked debris files in the repo
  root (detailed in the companion doc) include `orchestrate.sh`/`deploy.sh` that SSH to hardcoded
  public hosts as root with `StrictHostKeyChecking=no`, and `fix_server_conf.sh` containing a
  committed argon2id password hash. Remove and untrack them; treat the hash as compromised if reused.
- **Positive:** the project fuzzes the decode surface (3 targets), gates experimental/non-spec
  features behind cargo features, and the recent hardening work fixed real lock-across-await bugs.

---

## 7. Remediation roadmap (priority order)

1. **Stop the unauthenticated crashes (V1, V2):** add `depth_lock()` to the three decode functions;
   add input validation to the legacy decrypt path. Cheapest, highest-impact. Add regression tests.
2. **Close the DoS amplifiers (V3):** per-connection in-flight cap, per-IP connection cap, count
   sessions at activation (not creation) with a short unactivated timeout, and fix the inverted
   `max_timeout_ms`.
3. **Address the crypto supply chain (D1):** plan migration of RSA to a constant-time backend; in the
   interim uniform-error/uniform-timing all RSA-decrypt failures and document the residual Marvin risk.
4. **AuthN/AuthZ hardening (V4, V5):** forbid cross-channel transfer of activated None-policy sessions;
   pass application URI / hostname into client-cert validation.
5. **Dependency hygiene (D2–D5):** upgrade `rumqttc` off the EOL rustls 0.21/webpki 0.101 stack; bump
   `time`, `rand`; migrate off `serde_yaml`.
6. **Process (P1, P2, P3):** add the CI advisory gate + `deny.toml`; fix the disclosure policy;
   `git rm` the debris files.
7. **Crypto hygiene (C1):** zeroize secrets, redact `AesKey` `Debug`, constant-time the nonce compare.

---

*This audit reviewed source and dependency metadata only; it did not execute exploits against a
running instance. The decoder recursion (V1) and legacy-decrypt panics (V2) are the most urgent —
both are unauthenticated, trivially triggerable, and fixed with a handful of lines.*
