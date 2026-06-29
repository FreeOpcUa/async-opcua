# Research: Minimal Deployment Footprint

## Decision: Re-export server APIs for `base-server`

**Rationale**: The umbrella crate already defines `base-server` as the feature that includes the server SDK without the generated address space, but `opcua::server` is gated behind the full `server` feature. Changing the re-export gate to accept either `server` or `base-server` makes the documented facade path work without changing the full `server` feature.

**Alternatives considered**:

- Tell users to depend on `async-opcua-server` directly. Rejected because it bypasses the public umbrella crate and leaves the documented `base-server` feature misleading.
- Make `server` stop implying `generated-address-space`. Rejected because it would be a breaking behavior change for existing users and compliance expectations.

## Decision: Add a tiny anonymous minimal-server sample

**Rationale**: A sample binary is the smallest durable proof that downstream users can build through the facade with the base server only. Keeping it anonymous and config-free avoids local PKI and generated namespace requirements.

**Alternatives considered**:

- Modify `samples/simple-server` to use `base-server`. Rejected because that sample intentionally demonstrates the default server with the default node set.
- Add only a compile test. Rejected because a real sample doubles as documentation and a target for CI size reporting.

## Decision: CI reports size but does not enforce a threshold yet

**Rationale**: Binary size varies by Rust version, linker, and runner image. The first useful guard is ensuring the minimal profile compiles and that the size is visible in PR logs. A hard threshold can be added once several stable CI baselines exist.

**Alternatives considered**:

- Fail CI when size exceeds a fixed byte limit. Rejected for this increment because it risks flaky failures before the baseline is established.
- Run `cargo-bloat` in CI. Rejected because it adds install time and is not needed for a basic build guard.

## Decision: Defer crypto/auth feature splitting

**Rationale**: Splitting anonymous-only auth, RSA/X.509, OCSP, or SecurityPolicy::None-only builds is a deeper dependency-surface change with security review implications. The facade/sample/CI slice is independent, low risk, and directly addresses the largest immediate usability issue found in the audit.

**Alternatives considered**:

- Include crypto feature splitting in this feature. Rejected to keep the task reviewable and avoid mixing footprint usability with cryptographic dependency design.
