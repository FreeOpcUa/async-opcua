# Implementation Plan: First-Class Legacy Crypto Support

**Branch**: `008-first-class-legacy` | **Date**: 2026-06-12 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/008-first-class-legacy/spec.md`

## Summary

Move legacy security policy (Basic128Rsa15/Basic256) availability from a
compile-time decision to a runtime decision: the `legacy-crypto` feature
becomes default-on, panics become errors, the existing-but-dead
`ServerConfig.allow_legacy_crypto` switch is enforced at config validation,
endpoint advertisement, and secure-channel establishment, and the client
gains a matching `allow_legacy_crypto` opt-in. Deprecation warnings are
logged whenever a legacy policy is actually used.

## Technical Context

**Language/Version**: Rust, latest stable (1.96 in CI)
**Primary Dependencies**: existing rustcrypto stack (sha1/hmac already in tree behind the feature)
**Testing**: cargo test (config validation units, end-to-end legacy connect matrix in the umbrella integration tests, dotnet cross-implementation matrix)
**Constraints**: secure-by-default (no legacy without explicit runtime opt-in on each side); `default-features = false` builds must stay panic-free and CI-linted
**Scale/Scope**: ~6 crates touched (crypto, core, server, client, umbrella, dotnet harness) + docs

## Constitution Check

- **Test-First**: acceptance tests per user story before wiring (config
  validation tests, protocol rejection test, client opt-in test).
- **Library-First**: gating helpers live on `SecurityPolicy`
  (`is_deprecated()` as single source of truth, FR-007).
- **Simplicity / YAGNI**: reuse the existing config field and existing
  feature; no new abstraction layers.
- **Observability**: `warn!` deprecation logs on actual legacy use.

## Design Decisions (Phase 0 research)

1. **Feature default flip**: `async-opcua-crypto` gets
   `default = ["legacy-crypto"]`. The umbrella `async-opcua` forwards it via
   a default `legacy-crypto` feature (already exists as opt-in passthrough
   from the CI work; it becomes part of the umbrella default set). Crates
   that want minimal builds use `default-features = false` (CI's
   `--no-default-features` clippy variants keep covering this).
2. **Panic removal**: the `call_with_policy!` no-feature arm currently
   panics. Methods that can fail get routed through fallible variants where
   they already return `Result`; for infallible accessors (`uri`, `as_str`,
   `is_deprecated`) the no-feature arm returns inert values
   (URI/name still resolvable — these are constants and need no crypto).
   Concretely: string/URI tables and `is_deprecated()` move OUT of the
   gated macro so they work in all builds; crypto operations keep the gate
   but return `Err(StatusCode::BadSecurityPolicyRejected)` instead of
   panicking. `from_uri`/`from_str` recognize legacy URIs in ALL builds
   (returning the enum variant) so remote input can be *named* in errors
   and rejected deliberately rather than treated as Unknown.
3. **Server enforcement points** (FR-003/FR-004):
   - `ServerEndpoint::validate` + `ServerConfig::validate`: error when a
     legacy policy (endpoint or password_security_policy) is configured
     without `allow_legacy_crypto`.
   - `ServerInfo::new_endpoint_descriptions` (GetEndpoints/CreateSession):
     filter `is_deprecated()` endpoints when not allowed.
   - Secure channel open (`verify_and_remove_security_server` /
     `SecureChannel` policy adoption in core, called from server transport):
     the server passes an `allow_legacy` flag; legacy URI + not allowed →
     `BadSecurityPolicyRejected` error response, connection stays sane.
4. **Client opt-in** (FR-005): `ClientConfig.allow_legacy_crypto`
   (serde default false) + builder setter; enforced in
   `client_identity_token`-adjacent validation, `connect_to_*` endpoint
   matching (SessionBuilder) and `AsyncSecureChannel::connect` before any
   socket I/O.
5. **Warnings** (FR-006): one `warn!` at secure-channel establishment on
   each side when `security_policy.is_deprecated()`.
6. **Test/CI simplification** (FR-008): the dev-self-dep `legacy-crypto`
   plumbing added for CI becomes redundant once defaults include the
   feature, but is left in place (harmless, explicit). The dotnet harness
   drops its explicit feature in favor of the default and sets the new
   runtime switches in its config fixtures.

## Project Structure

```text
specs/008-first-class-legacy/
├── spec.md
├── plan.md              # This file
└── tasks.md

async-opcua-crypto/      # feature default, panic removal, URI tables ungated
async-opcua-core/        # secure channel legacy rejection hook
async-opcua-server/      # config validation, endpoint filtering, OSC rejection, warn
async-opcua-client/      # config + builder opt-in, connect-time enforcement, warn
async-opcua/             # umbrella default feature set
dotnet-tests/            # fixture updates (runtime opt-in instead of feature)
docs/crypto.md, docs/compatibility.md
```

## Complexity Tracking

No violations. The only API-visible changes are additive
(`ClientConfig.allow_legacy_crypto`) plus the feature-default flip, which is
release-notes-worthy but not code-breaking.
