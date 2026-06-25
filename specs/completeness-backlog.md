# Completeness backlog (un-defer the YAGNI deferrals)

**Principle:** async-opcua is a complete OPC UA *reference* implementation. Spec-defined behavior gets
built — "the spec defines it" is sufficient reason. (User direction 2026-06-25; see memory
`completeness-over-yagni`.) ponytail still governs HOW (shortest correct diff, no needless
abstraction), not WHETHER. One feature per PR: codex implements (MCP-grounded), Claude writes
independent tests.

## Done
- **FX (Parts 80/81/83) completion** — DONE (PRs #160-168): async-opcua-fx crate + FX/Data + FX/CM
  DataTypes; full 9-command EstablishConnections/CloseConnections w/ atomic abort + server Method adapter;
  VerifyAsset/VerifyFunctionalEntity (FxVerifier); ControlGroup locking; NodeIdTranslation; SetSecurityKeys
  (SKS). Follow-up: wire Get/SetSecurityKeys as callable address-space Method nodes. See
  `2026-06-25-fx-completion-design.md` + memory `feature-fx-completion`.

## To build (spec features, YAGNI-deferred)
- **A&C (Part 9):** condition history / HistoryRead on condition events; AddComment; DialogConditionType;
  automatic source monitoring (alarms self-trigger from a source var via sampling); GeneralModelChangeEvent.
- **Aggregates (Part 13):** AggregateFilter on MonitoredItems (aggregate subscriptions); HistoryUpdate of
  aggregates; annotation history (AnnotationCount); non-numeric/complex aggregates; status-bit edges
  (MultipleValues on dup min/max, Count before-start/after-end Bad_NoData, backward intervals, 2-prior slope).
- **PubSub:** writable PubSub configuration via address space — config Methods (AddConnection/
  AddWriterGroup/AddDataSetWriter/AddPublishedDataSet/removes) + Write/AddNodes handlers.
- **Node management (Part 4 §5.7):** full 9-node-class AddNodes (today Object+Variable); ModelChange
  events; server-assigned (null) NodeIds on the default manager.
- **Security/PKI/Audit:** ChannelThumbprint; multi-cert mixed server; full Audit*EventType hierarchy
  (certificate/write/node-management/method/success — security-critical ones already fire); better
  server security-check framework.

## Real constraints (need a new dep/infra — distinct from YAGNI; decide separately)
- FindServersOnNetwork — needs mDNS (new dep + LDS-ME multicast).
- OCSP revocation — needs OCSP responder/online infra (CRL chain validation done, PR #40).

## Not spec-conformance (judgment, not "deferred features")
- async-delivery actor phases 2 & 4 (migrate off LegacyCall, delete it) — internal refactor.
- Perf backlog Tier 2/3 (`complexity-cuts-backlog.md`) — is_subtype_of memoization, TBP index, etc.
- SDK tooling / example servers (`TODO.md`) — persistent-store example, "bad ideas" servers.
