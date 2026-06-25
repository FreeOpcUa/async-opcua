# FX (Field eXchange) Completion — Design

Date: 2026-06-25
Status: approved (scope "Full FX1–FX4" chosen by user)

## Purpose

Complete OPC UA FX (Parts 80/81/83) on top of the spike (#135) + the PubSub info-model reflection
(#151). Probe-2 finding: **FX is a control layer over standard Part-14 PubSub — it defines no new
transport.** An FX Connection points two AutomationComponents' DataSetWriter/DataSetReader objects at
each other (by NodeId) and orchestrates ids/versions/lifecycle. So the build order is: make the PubSub
data path real (reader runtime + reader info-model), then the FX orchestration on top.

Foundation already in place: PubSub publisher + UADP codec (#123), `decode_subscriber_uadp_message`
(decode only), the writer-side PubSub info-model reflection (#151), the FX nodeset chain loads
(#135 + the namespace-remap fix).

## Phases (each: codex implements, Claude validates; MCP-grounded; one PR each)

### FX1 — Production UADP DataSetReader (the headline gap)
Today the subscriber only decodes bytes to `UadpNetworkMessage`; nothing binds fields into the address
space. Add:
- Config: `ReaderGroupConfig` + `DataSetReaderConfig` mirroring the writer config — reader id, the
  PublisherId / WriterGroupId / DataSetWriterId filters that select which incoming DataSetMessages it
  consumes, and a `SubscribedDataSet` = the target variable NodeIds (the symmetric counterpart of the
  writer's `published_variables`).
- Runtime: given a decoded `UadpNetworkMessage`, match each `DataSetMessage` to a `DataSetReader`
  (by the filters), extract the DataSet fields in order, and write them to the reader's target
  address-space variables (TargetVariables binding). Reuse `PubSubBridge`/the address space.
- A receive path (UDP loopback) + a direct decode-and-apply entry point for deterministic tests.

### FX2 — Reader-side PubSub info-model objects
Extend `reflect_pubsub_config` (#151) to also materialize `ReaderGroup` (HasReaderGroup) →
`DataSetReader` (HasDataSetReader) instance objects with their identity properties + HasTypeDefinition,
so FX can reference a DataSetReader by NodeId.

### FX3 — ReserveCommunicationIds + DataSet ConfigurationVersion
- `ReserveCommunicationIds` (hands out DefaultPublisherId / WriterGroupIds / DataSetWriterIds).
- DataSet `ConfigurationVersionDataType` on published/subscribed datasets + the Published/Subscribed
  version checks FX uses to detect config drift.

### FX4 — Online connection management (the FX control layer)
- `fx.cm ConnectionManagerType` + `EstablishConnections` / connection lifecycle.
- `Connection` objects whose `CommunicationLinks` (`PubSubCommunicationLinkConfigurationDataType`)
  carry `DataSetWriterRef`/`DataSetReaderRef` (`PubSubConfigurationRefDataType` — NodeId refs to the
  PubSub objects from FX1/FX2) + expected ConfigurationVersions, plus `NodeIdTranslation`.

## Testing (Claude authors, independent; MCP-grounded)
- FX1: publish a value from one address space; the DataSetReader subscriber writes it into a second
  address space's target variable (end-to-end pub→sub C2C, loopback UDP or decode-and-apply).
- FX2: browse the ReaderGroup/DataSetReader objects + assert identity/type-definition + NodeId locator.
- FX3: ReserveCommunicationIds returns unique ids; a stale ConfigurationVersion is detected.
- FX4: EstablishConnections wires two ACs' writer/reader configs and data flows end-to-end.

## Provenance
FX spike (#135) `docs/.../2026-06-24-fx-spike-design.md` (Probe 2 decomposition); Part 14 §6.2
(DataSetReader/SubscribedDataSet), Part 81 §6.2.4 (Connection/CommunicationLinks), grounded via the
`opc-ua-reference` MCP. Builds on [[feature-fx-spike]] + [[feature-pubsub-uadp-interop]] +
the PubSub info-model (#151).
