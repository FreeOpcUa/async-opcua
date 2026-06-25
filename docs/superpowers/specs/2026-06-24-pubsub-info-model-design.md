# Part 14 PubSub Information Model (read-only reflection) — Design

Date: 2026-06-24
Status: approved (brainstorm); consumer-requirements cross-check pending (QuackPLC/QuackDCS queries)

## Purpose

Expose the server's configured OPC UA PubSub topology as standard **Part 14 instance objects** in the
address space, so they are browsable, readable, and **referenceable by NodeId**. This is the
foundation the FX (Field eXchange) work needs: an FX Connection references `DataSetWriter`/
`DataSetReader` objects by NodeId, which today do not exist as nodes (the PubSub engine is driven only
by Rust `PubSubConnectionConfig` structs). It also unblocks the production `DataSetReader` sub-project.

This first slice is **read-only reflection**: engine config → address-space objects, one-way, at
setup. Writable configuration (clients/FX creating PubSub via the address space) is a later slice.

## Scope

**In scope**
- A reflection function that materializes, from `&[PubSubConnectionConfig]`, the standard instance
  objects rooted at the Server `PublishSubscribe` object (i=14443): `PubSubConnection` →
  `WriterGroup` → `DataSetWriter`, and `ReaderGroup` → `DataSetReader` when present.
- Setting the FX-referenceable properties on those instances (PublisherId, WriterGroupId,
  DataSetWriterId, names, transport address) and `HasTypeDefinition` to the already-generated PubSub
  ObjectTypes.
- A returned `config-id → assigned NodeId` map so callers/FX/tests can locate the objects.

**Out of scope** (later slices)
- Write / AddNodes handlers (writable config), the PubSub config Methods (AddConnection/…).
- Live re-sync when config changes at runtime (this is a setup-time snapshot).
- Every optional Part-14 property; only the FX-referenceable identity/name/address set.
- The production `DataSetReader` runtime (separate sub-project) and online connection management.

## Architecture

A `pubsub_model` module in `async-opcua-pubsub` (which already depends on `async-opcua-server`)
reflects the engine's configuration into the server `AddressSpace`. The Part 14 PubSub ObjectTypes
(`PublishSubscribeType`, `PubSubConnectionType`, `WriterGroupType`, `DataSetWriterType`,
`ReaderGroupType`, `DataSetReaderType`, `PublishedDataSetType`) are already generated in ns0, so this
creates **instances + references**, not type definitions. The engine keeps publishing from the same
config, untouched — the reflection is a passive view.

```
PubSubConnectionConfig[]
      │  reflect_pubsub_config(address_space, namespaces, type_tree, &configs)
      ▼
Server.PublishSubscribe (i=14443)
   └─ PubSubConnection "<name>"            (HasPubSubConnection, type=PubSubConnectionType)
        ├─ WriterGroup "<name>" (WriterGroupId)        (HasComponent, type=WriterGroupType)
        │    └─ DataSetWriter "<name>" (DataSetWriterId) (HasDataSetWriter, type=DataSetWriterType)
        └─ ReaderGroup / DataSetReader (when configured)
```

## Components (one responsibility each)

1. **`reflect_pubsub_config(address_space, namespaces, type_tree, &[PubSubConnectionConfig]) ->
   PubSubModelMap`** (new module `pubsub_model` in `async-opcua-pubsub`). Ensures the
   `PublishSubscribe` object exists; for each connection/group/writer/reader, builds the instance
   object (server-allocated NodeId), sets identity/name/address properties, wires the standard
   references (`HasComponent`/`HasPubSubConnection`/`HasDataSetWriter`/…) and `HasTypeDefinition`.
   Returns `PubSubModelMap { connections: Vec<(connection_id, NodeId)>, writers: Vec<(dataset_writer_id, NodeId)>, readers: ... }`.
2. **`PubSubModelMap`** — the locator returned to callers (FX, tests) to resolve config → NodeId.
3. **Wiring point** — wherever a server + `PubSubEngine` are set up together, call
   `reflect_pubsub_config` after the config is assembled.

## Data flow

`PubSubConnectionConfig[]` → `reflect_pubsub_config` → instance objects under
`Server.PublishSubscribe` → browse/read/translate resolve them; FX/clients reference a `DataSetWriter`
or `DataSetReader` by its assigned NodeId.

## Error handling

- Idempotent: re-reflecting an already-present topology replaces/skips rather than duplicating.
- Empty config → a valid, empty `PublishSubscribe` object (no children).
- NodeIds are server-allocated to avoid collisions; the `PublishSubscribe` root is i=14443 if absent.

## Testing (Claude authors, independent of the codex implementation)

Integration test: configure a `PubSubConnectionConfig` with a WriterGroup + DataSetWriter (and a
ReaderGroup + DataSetReader), call `reflect_pubsub_config`, then assert:
- `PublishSubscribe` (i=14443) is present;
- a `PubSubConnection` child with the configured BrowseName;
- a `WriterGroup` carrying the configured `WriterGroupId`;
- a `DataSetWriter` carrying the configured `DataSetWriterId`, findable **by its NodeId** via the
  returned map, with `HasTypeDefinition` → `DataSetWriterType`;
- the reader side equivalently.
This is the concrete "FX can reference a DataSetWriter by NodeId" proof.

## Implementation split

Per project workflow: **codex implements** the `pubsub_model` reflection (feature code); **Claude
authors/validates** the independent test. One codex task, no-git guardrail, branch verified after.

## Consumer requirements cross-check

Cross-project `claude -p` queries (run in the QuackPLC and QuackDCS repos) returned:

**QuackPLC (controller/field side):** primarily a Server (read/write-gated) + a Client for C2C; uses
Data Access + Subscriptions today; **no Methods/A&C/History yet**. PubSub needs **both publisher and
subscriber, UADP first**, published fields sourced from a **projection** (`opcua.example.toml`,
NodeId→region/offset) off a **scan-boundary ring snapshot** (not the live address space), cadence
bounded by scan period + a no-lap generation rule (ADR-0070), per-publish cost bounded (#192).
**PubSub/opcua is Increment 5 (last), gated**; "the DCS wants Channel A (Methods/RW/A&C) before PubSub."
Build: static aarch64-musl, **C-toolchain-free**; loads a **DCS-supplied NodeSet2** (does not author).

**QuackDCS (supervisory side):** **client-only today** (async-opcua 0.18 fork, `features=["client"]`);
uses Call/Write/CreateSubscription. Contract wants the PLC as a **full Server (Method + A&C + PubSub
pub+sub)**; runtime is Client + A&C/PubSub **Subscriber**. PubSub = **UADP-over-UDP unicast MVP, both
pub+sub, preconfigured (topic registry, no online SKS)**; datasets = per-class StructuredType status
(deadband), setpoint mirrors, sequence telemetry; freshness envelope (epoch+sequence+max_staleness).
**Currently DEFERRED (DRIFT-06 / ADR-0071):** the pinned fork lacks the `pubsub` feature → runtime
uses MonitoredItems (pull) as the interim. Build: deployment is Podman/Quadlet x86 (no musl config
checked in), pure-Rust is *policy* (ADR-0068) **but `ring 0.17` (cc/libc) is transitively pulled by
`async-opcua-crypto`** → no-C static-musl is **not currently satisfiable** without vendoring `ring`
or swapping to RustCrypto. UADP MessageSecurity is WriterGroup-scoped (open questions O2/O3).

**Implication (reprioritization).** This PubSub-info-model design is sound and remains the right first
FX slice, but **both consumers defer PubSub/FX**, and both flag a higher-priority, fixable-now blocker:
the **no-C / static-musl build-gate (`ring` transitive dep)** prevents async-opcua from being used in
their target deployment at all. Recommend addressing the build-gate audit **before** this slice; this
spec stays as the FX foundation for when PubSub work is scheduled (their Increment 5 / post-DRIFT-06).
