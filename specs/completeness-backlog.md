# Completeness backlog (un-defer the YAGNI deferrals)

**Principle:** async-opcua is a complete OPC UA *reference* implementation. Spec-defined behavior gets
built — "the spec defines it" is sufficient reason. (User direction 2026-06-25; see memory
`completeness-over-yagni`.) ponytail still governs HOW (shortest correct diff, no needless
abstraction), not WHETHER. One feature per PR: codex implements (MCP-grounded), Claude writes
independent tests.

_Last refreshed 2026-06-27 (after RBAC #031 + HistoryUpdate #032)._

## Done
- **FX (Parts 80/81/83)** — async-opcua-fx crate; full EstablishConnections/CloseConnections + Verify*
  + ControlGroup + NodeIdTranslation + SetSecurityKeys (PRs #160–168; memory `feature-fx-completion`).
- **A&C (Part 9)** — AddComment (#169), DialogConditionType + Respond/Respond2 (#170), condition history /
  HistoryRead-events (#171), GeneralModelChangeEvent (#173), ConditionRefresh + Acknowledge/Confirm
  (#138), Discrete/OffNormal + Shelving/Suppression + branching + EURange limits (#152–#155), Exclusive/
  NonExclusive limit alarms w/ deadband (#139). Remaining: **automatic source monitoring** (below).
- **Aggregates (Part 13)** — full HistoryRead aggregate set (#142–#146); MultipleValues + status-bit edges
  (#175); AggregateFilter on MonitoredItems / aggregate subscriptions (#187/#188).
- **PubSub (Part 14)** — secured UADP NetworkMessage (#56); writable config Methods: connection/group
  (#178/#180) + PublishedDataSet (#181).
- **Node management (Part 4 §5.7)** — full 9-node-class AddNodes + NodeManagement (#172, #52).
- **Audit (Part 3/4 §A)** — full Audit*EventType hierarchy: write/method/node-mgmt (#174/#176/#177),
  session/channel/cert/cancel (#182–#186).
- **RBAC / Authorization (Part 3/18)** — feature 031, 106/106 (PRs #187–#196): node-level RolePermissions/
  AccessRestrictions, RoleSet, identity→role resolution, opt-in enforcement, secure preset.
- **Historical Access write (Part 11 HistoryUpdate)** — feature 032, 77/77 (PRs #198–#205): UpdateData/
  DeleteRawModified/DeleteAtTime/UpdateStructureData/UpdateEvent/DeleteEvent + modified-history read, on
  the sqlite backend AND a new in-memory store. Memory `feature-032-historyupdate-write`.

## To build (spec features, YAGNI-deferred)
- **A&C automatic source monitoring (Part 9 §5.8.2 / §4.4)** — **IN PROGRESS, feature 033.** Bind an
  alarm/condition to its `InputNode` (source variable), sample it, and auto-evaluate limit state
  transitions (Active/Inactive, Hi/HiHi/Lo/LoLo + deadband) instead of requiring the integrator to drive
  state manually. The last A&C gap — turns the limit-alarm types into a working closed loop.
- **Aggregates follow-ons (Part 13):** HistoryUpdate of aggregates; annotation history AnnotationCount;
  non-numeric / complex aggregates.
- **Security/PKI:** ChannelThumbprint binding; multi-cert mixed server (RSA+ECC per endpoint); better
  server security-check framework (`TODO.md`).

## Real constraints (need a new dep/infra — distinct from YAGNI; decide separately)
- FindServersOnNetwork — needs mDNS (new dep + LDS-ME multicast).
- OCSP revocation — needs OCSP responder/online infra (CRL chain validation done, PR #40).
- Nano/Micro/Embedded conformance-profile builds — feature alias + minimal example; the default node
  managers assume the core address space (memory `todo-embedded-profiles`).

## Not spec-conformance (judgment, not "deferred features")
- async-delivery actor phases 2 & 4 (migrate off LegacyCall, delete it) — internal refactor.
- Perf backlog Tier 2/3 (`complexity-cuts-backlog.md`) — is_subtype_of memoization, TBP index, etc.
- SDK tooling / example servers (`TODO.md`) — persistent-store example, "bad ideas" servers.
