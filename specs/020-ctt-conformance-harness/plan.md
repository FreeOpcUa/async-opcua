# Implementation Plan: OPC UA Conformance Test Harness (CTT)

**Branch**: `020-ctt-conformance-harness` | **Date**: 2026-06-22 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/020-ctt-conformance-harness/spec.md`

## Summary

Three deliverables: (US1) a CI-runnable **conformance smoke** that drives our server with our client
across the full (security policy × mode × identity-token) matrix — built on the existing `Tester` harness
(RSA via `default_server`, ECC via `new_ecc`) — running Read/Browse/Write/Subscribe per valid cell and
asserting invalid cells reject correctly; (US2) a separate **ECC demo-server profile** (config + EC cert,
selected by arg/env, RSA default unchanged) since one server can't serve RSA+ECC; (US3) a **UACTT run
guide + launch script** — now directly actionable since the user can run the real UACTT on a Windows VM —
with cross-trust steps and an expected-results/known-gaps table; (US4) the smoke documents its proxy
nature/coverage. The real UACTT stays out of CI (Windows/proprietary); the smoke is the Linux regression
proxy.

## Technical Context

**Language/Version**: Rust (workspace edition 2021).
**Primary Dependencies**: existing test harness (`async-opcua/tests/utils` `Tester`), `async-opcua`
client+server, `opcua_crypto` (EC cert via `X509::cert_and_pkey_ecc`). No new library dependency.
**Storage**: N/A (PKI dirs on disk for the demo-server profiles, as today).
**Testing**: `cargo test -p async-opcua --test integration_tests --features ecc` — the conformance smoke,
authored + run by Claude. Run single-threaded/isolated for reliability.
**Target Platform**: smoke runs on Linux/CI; the real UACTT runs on the user's Windows VM (manual).
**Project Type**: library + samples.
**Performance Goals**: N/A (smoke is sequential; generous timeouts).
**Constraints**: one cert per server → ECC is a separate instance/profile (012 mixed-cert deferred);
default demo-server behavior unchanged; reliable under parallel-load flakiness (isolated run);
`clippy --all-targets --all-features` clean; existing suites pass.
**Scale/Scope**: ~1 new integration test module + 1 demo config + small main.rs profile-selection + EC cert
provisioning + 1 doc + 1 shell script.

## Constitution Check

- **I. Correctness Over Completion**: the smoke exercises REAL client↔server services across the matrix and
  fails on any broken cell (no hiding); the guide's known-gaps are anchored to actual Tier 3 behavior. ✅
- **IV. Security Is Paramount**: the smoke covers the secured policies/modes + all identity-token types and
  asserts bad credentials/mismatches are rejected with the correct StatusCode (no silent accept). ✅
- **II/III. Do It Right Once / Discipline**: reuse the proven `Tester` harness; demo profile honors the
  single-cert constraint rather than faking multi-cert; one commit per story. ✅
- **V. Leave It Better**: a permanent CI conformance regression guard + a reproducible real-CTT path. ✅
- **Verification division**: the smoke IS the conformance test → Claude authors/runs it; codex does the
  demo ECC profile/selection + launch script. ✅

**Gate: PASS** — no violations; no Complexity Tracking entries.

## Project Structure

### Documentation (this feature)

```
specs/020-ctt-conformance-harness/
├── spec.md  plan.md  research.md  data-model.md  quickstart.md
├── contracts/api-surface.md
└── checklists/requirements.md
```

### Source Code (repository root)

```
async-opcua/tests/integration/
└── conformance.rs        # US1 (Claude): matrix smoke over Tester (RSA default_server + ECC new_ecc),
                          #   per cell: connect+activate, Read, Browse, Write, Subscribe+MI; negatives.
                          #   US4: coverage/limitations doc-comment.
async-opcua/tests/integration_tests.rs (or integration/mod)  # register `mod conformance;`
samples/demo-server/
├── sample.server.ecc.conf  # US2 (codex): ECC_nistP256/P384 Sign+SignAndEncrypt, all token types
└── src/main.rs             # US2 (codex): select config via arg/env; default = RSA conf; EC cert provision
docs/ctt-conformance.md     # US3 (Claude): UACTT download + Windows-VM run guide, cross-trust, test
                            #   groups, expected-results/known-gaps table
samples/demo-server/run-conformance.sh (or tools/)  # US3 (codex/Claude): boot a profile w/ clean PKI,
                            #   print endpoint URLs + server cert thumbprints
```

**Structure decision**: smoke as an integration test reusing `Tester`; demo-server gains a second config
+ arg/env selection (default unchanged); docs + shell script for the real UACTT. No new crate/dep.

## Complexity Tracking

No constitution violations; no entries.
