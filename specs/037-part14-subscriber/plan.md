# Implementation Plan: Part 14 Subscriber Runtime

**Branch**: `037-part14-subscriber` | **Date**: 2026-06-28 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/037-part14-subscriber/spec.md`

## Summary

Implement the production subscriber half of OPC UA Part 14 PubSub for broker-less UADP over UDP. The design extends existing ReaderGroup/DataSetReader configuration, UADP decode, and message-security code with a cancellation-safe UDP receive loop, DataSetReader filtering, field-to-target Variable application, per-reader state/diagnostics, and explicit fail-closed boundaries for unsupported message forms.

## Technical Context

**Language/Version**: Rust 1.75+  
**Primary Dependencies**: tokio, bytes, existing async-opcua-core/address-space/pubsub crates, existing PubSub security codec  
**Storage**: N/A  
**Testing**: cargo test with focused async unit and loopback UDP integration tests  
**Target Platform**: Linux server and library consumers using the workspace crates  
**Project Type**: Rust workspace library crate  
**Performance Goals**: Reject malformed datagrams without panics; bound field counts and datagram sizes; avoid partial target writes; keep receive-loop cancellation deterministic  
**Constraints**: No unbounded decode allocation; no locks held across await points; secured datagrams must verify before decode or target mutation; unsupported Part 14 surfaces must fail closed  
**Scale/Scope**: One process may host multiple PubSubConnections, ReaderGroups, and DataSetReaders; first delivery target is standards-correct UADP/UDP subscriber behavior

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Correctness over completion**: Pass. The spec narrows implementation to UADP/UDP key-frame receive and requires explicit unsupported errors for brokered transports, JSON, TSN hardware, RawData, delta, event, and full method-surface gaps.
- **Individual task discipline**: Pass. Tasks are grouped by independently testable user stories and must remain atomic after analysis.
- **Security paramount**: Pass. Secured UADP messages are verified, decrypted, and replay-checked before payload decode or AddressSpace mutation.
- **Leave it better than you found it**: Pass. Existing docs that say subscriber support is decode-only must be corrected when runtime support lands.
- **No panic network decode**: Pass. Requirements include malformed-datagram tests, bounded decode behavior, and fail-closed mutation semantics.

## Project Structure

### Documentation (this feature)

```text
specs/037-part14-subscriber/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── checklists/
│   └── requirements.md
├── contracts/
│   └── subscriber-runtime.md
└── tasks.md
```

### Source Code (repository root)

```text
async-opcua-pubsub/
├── src/
│   ├── config.rs
│   ├── engine.rs
│   ├── lib.rs
│   ├── pubsub_model.rs
│   ├── subscriber.rs
│   ├── security/
│   └── transport/
└── tests/
    ├── datasetreader_tests.rs
    ├── interop_tests.rs
    ├── message_security_tests.rs
    ├── subscriber_plain_uadp_tests.rs
    ├── subscriber_security_tests.rs
    └── subscriber_status_tests.rs

docs/
└── pubsub.md
```

**Structure Decision**: Work stays inside the existing `async-opcua-pubsub` crate, using the existing UADP codec, security codec, config types, engine lifecycle, transport module, and PubSub information-model reflection. Tests live beside current PubSub tests. Documentation updates are limited to existing PubSub docs.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

No constitution violations to track.
