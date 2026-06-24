# OPC UA FX Spike — Design

Date: 2026-06-24
Status: approved (brainstorm)

## Purpose

A time-boxed **learning spike** to prove, end-to-end and verified, that async-opcua can:

1. **Host the OPC UA FX information model** (OPC 10000-80/81/83) — load the UAFX nodesets into a
   server address space and expose the AutomationComponent / FunctionalEntity model; and
2. **Do preconfigured controller-to-controller (C2C) data exchange** between two AutomationComponents
   over UADP PubSub.

The spike answers three questions before we commit to a full FX implementation: does the FX
information model load cleanly on async-opcua, what does the C2C publish path look like with the real
PubSub engine, and exactly where the subscriber/reader side needs building.

## Scope

**In scope**
- Loading the FX information model (`opc.ua.fx.data`, `opc.ua.fx.ac`, `opc.ua.fx.cm`) + its DI
  dependency into two in-process AutomationComponents.
- A single preconfigured UADP PubSub link (AC1 publishes one process value, AC2 consumes it) over UDP
  loopback.
- An automated assertion that the value AC2 receives equals what AC1 published, and that the FX type
  model resolves after load.

**Out of scope** (deliberately — these become the follow-on FX sub-projects)
- Online connection management: `EstablishConnections`, `Connection` objects, the ConnectionManager.
- ControlGroups, Health, AutomationComponentCapabilities, `VerifyAsset`.
- PubSub security on the C2C link (signing/encryption).
- Codegen of typed FX Rust structs (the spike uses the runtime nodeset importer instead).

## Architecture

One in-process integration test stands up two AutomationComponents — AC1 (publisher) and AC2
(subscriber) — linked by a preconfigured UADP-over-UDP-loopback PubSub channel.

```
AC1 (server address space + UAFX model)            AC2 (server address space + UAFX model)
  FunctionalEntity variable (process value)
        |  DataSetWriter / WriterGroup (PubSubEngine)
        v
   UADP NetworkMessage --- UDP loopback ---> receive datagram
                                              decode_subscriber_uadp_message  (the #123-hardened codec)
                                                     |
                                              extract DataSetMessage field
                                                     v
                                      assert value == what AC1 published
```

## Components

1. **FX nodeset loading.** Vendor the UAFX nodesets and the DI nodeset they require, and load them
   into each AC's address space via the existing `import_node_set` / `nodeset_loader`, in dependency
   order: Core (built-in) → DI → FX/Data → FX/AC → FX/CM. After load, assert the FX model resolves
   (e.g. `AutomationComponentType`, `FunctionalEntityType`, `AcDescriptorType` are present with the
   correct NodeClass). Provenance for the vendored nodesets is recorded (source repo + commit).
2. **AC1 publisher.** A `PubSubEngine` connection with a WriterGroup + DataSetWriter publishing one
   variable (a process value under AC1's FunctionalEntity) as a UADP NetworkMessage to a loopback UDP
   endpoint.
3. **AC2 subscriber.** Receive the UDP datagram and decode it with `decode_subscriber_uadp_message`,
   then extract the DataSetMessage field value. (We use the raw-decode path rather than a full
   `DataSetReader` abstraction — see Risks.)
4. **Verification.** Assert AC2's decoded value equals AC1's published value, within a bounded receive
   timeout so the test cannot hang.

## Data flow

AC1 FunctionalEntity variable → DataSetWriter → UADP NetworkMessage → UDP loopback → AC2 receive →
`decode_subscriber_uadp_message` → assert decoded value == published value.

## Error handling

- Nodeset load failures (missing dependency, parse error) fail the test with the specific nodeset and
  cause.
- The subscriber receive is bounded by a timeout; on timeout the test fails with "no C2C message
  received", never hangs.

## Testing

The spike *is* a verified integration test (it asserts the value flows). It also asserts the FX type
model is present after load. No separate test layer is needed.

## Risks / decisions

- **Dependency chain & vendoring.** The `ac` nodeset requires Core + DI + FX/Data; `cm` requires
  `ac`. We must vendor DI + the three FX nodesets (a few MB) and load them in order. If
  `nodeset_loader` does not auto-resolve ordering, the test sequences them explicitly.
- **Thin UADP subscriber.** async-opcua's PubSub subscriber path is JSON-bridge-leaning; the clean
  UADP entry point is `decode_subscriber_uadp_message`. The spike uses it directly on received bytes
  rather than a full `DataSetReader`. This is a spike-appropriate shortcut; surfacing exactly what a
  production FX subscriber/reader needs is itself a goal of the spike.
- **UDP in a test.** Loopback UDP is lossless, so a bounded poll-receive is deterministic. If sockets
  prove fiddly in CI, the fallback is to hand AC1's encoded bytes directly to AC2's decode — same
  proof, no socket, no timing.

## Success criteria

1. Both ACs load the full FX nodeset chain without error and expose the FX type model.
2. AC2 receives and decodes AC1's published process value, and it matches.
3. A written record of what the C2C path required and where the subscriber/reader gap is, to seed the
   real FX sub-projects (info model → C2C data exchange → online connection management → control
   groups/health).

## Findings (spike result)

1. **Does the FX info model load cleanly?** Yes — once a real library bug was fixed. Loading the
   chain (DI → FX/Data → FX/AC → FX/CM) via the runtime `NodeSetLoader` + `import_node_set` works,
   and `AutomationComponentType`/`FunctionalEntityType`/`AcDescriptorType` resolve as ObjectTypes in
   the FX/AC namespace. The spike's independent test caught a namespace-remapping bug in
   `NodeSet2Import::load` (it never installed the namespace index map on its decoding `Context`, so
   any nodeset listing its own namespace before its dependencies — as all the FX nodesets do — had
   its nodes placed under the wrong namespace index). Fixed by `ctx.set_index_map(namespaces.index_map())`
   (implementation by codex, validated by the Claude-authored test). This bug affected *all* runtime
   companion-nodeset loading, not just FX.
2. **What did the C2C publish path require?** Nothing new — it reused `UdpPublisher` + `PubSubBridge`
   + `PubSubConnectionConfig`/`WriterGroupConfig`/`DataSetWriterConfig` unchanged, publishing a plain
   Double variable from AC1's address space over loopback UDP. AC2 received the datagram and decoded
   it with `UadpNetworkMessage::decode` (the codec hardened in PR #123). It worked on the first run.
3. **Where is the subscriber/reader gap?** There is no production `DataSetReader`/ReaderGroup
   abstraction for UADP — the spike decodes raw bytes via `UadpNetworkMessage::decode`. Building a
   real subscriber (DataSetReader binding incoming fields into a target address space) is the first
   task of the follow-on "C2C data exchange" sub-project.

**Incidental notes for the real FX work:** `AddressSpace::add_namespace(uri, index)` takes an
explicit index and returns `()` (the FX chain occupies the low indices, so instance namespaces must
use a free index); the FX/AC namespace resolves to global index 3 in this setup.

**Decomposition confirmed for the real FX implementation (codex implements, Claude validates):**
info model (done by this spike) → C2C data exchange (production DataSetReader + AutomationComponent
instance objects) → online connection management (`EstablishConnections`/Connection) → ControlGroups
/ Health / capabilities / PubSub security.

## Probe 2 — FX ↔ PubSub mapping (deeper information pass)

The first spike proved the *substrate* (nodeset loads, generic UADP publish works) but was shallow on
the FX-specific data path. This probe inspected the FX `cm`/`data` nodesets + Part 81 §6.2.4 to answer
"how does an FX Connection actually drive data?", and it changes the C2C sub-project scope.

**Finding 1 — FX orchestrates standard Part 14 PubSub; it defines no new transport.** A Connection's
`CommunicationLinks` (`PubSubCommunicationLinkConfigurationDataType`) carry `DataSetWriterRef` /
`DataSetReaderRef` (`PubSubConfigurationRefDataType` — i.e. **references to PubSub configuration
objects by NodeId**) plus expected Published/Subscribed `ConfigurationVersionDataType`. `ReserveCommunicationIds`
hands out `DefaultPublisherId` / `WriterGroupIds` / `DataSetWriterIds`. So FX = a control layer that
points two ACs' DataSetWriter/DataSetReader objects at each other.

**Finding 2 — the real gap: async-opcua has NO Part 14 PubSub *information model*.** The PubSub engine
is driven entirely by Rust `PubSubConnectionConfig` structs; there are no `PublishSubscribeType` /
`PubSubConnectionType` / `WriterGroupType` / `DataSetWriterType` / `DataSetReaderType` /
`PublishedDataSetType` **objects in the address space**. FX cannot reference PubSub config that does
not exist as nodes. This — not "write a DataSetReader" — is the foundational C2C work.

**Finding 3 — AC instance-building is not the hard part.** The generic address space already supports
instantiating typed objects, so standing up an `AutomationComponent`/`FunctionalEntity` instance is
routine. The hard part is the PubSub model + engine binding above.

**Revised C2C "data exchange" decomposition (each: brainstorm → plan → codex implements / Claude validates):**
1. **PubSub information model** — expose the Part 14 PubSub object model in the address space and bind
   it bidirectionally to the existing `PubSubEngine` (address-space config drives the engine; runtime
   state surfaces back). Prereq for everything FX-PubSub.
2. **Production UADP `DataSetReader`** — a subscriber that binds incoming DataSetMessage fields into a
   `SubscribedDataSet`/target variables (today the spike only raw-decodes bytes).
3. **`ReserveCommunicationIds` + DataSet `ConfigurationVersion`** — ID reservation + version checks FX needs.
4. **Then** online connection management (`fx.cm` `ConnectionManagerType` / `EstablishConnections`,
   `NodeIdTranslation`) layers references on top of (1)–(3).
