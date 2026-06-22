---
description: "Task list for feature 022 — writable address space (NodeManagement)"
---

# Tasks: Writable Address Space (NodeManagement)

**Input**: design docs in `/specs/022-writable-address-space/`. Conformance Tier 3 facet #6.

**Verification division**: codex implements the mutators + config gate + demo (production/sample code, NO
git, NO tests); **Claude authors + runs ALL tests** independently, anchored to OPC UA Part 4 §5.7
NodeManagement status-code semantics + real address-space round-trips through the service (NOT codex
loopback). One commit per user story.

**Gate**: `cargo fmt --all --check && cargo clippy --all-targets --all-features --locked -- -D warnings`
+ json-off legs (`clippy -p async-opcua --no-default-features [--features json] -- -D warnings`) +
`cargo test -p async-opcua --test integration_tests node_management -- --test-threads=1` +
`cargo build -p async-opcua-demo-server`.

**Pinned facts (plan/research):** implement in the `InMemoryNodeManagerImpl` DEFAULT methods
(`memory/memory_mgr_impl.rs`, delegated to by `InMemoryNodeManager` `memory/mod.rs:1113+`), mutating the
`&RwLock<AddressSpace>` already passed in — additive, no `NodeMutator`/downstream change. `AddressSpace`
API: `node_exists`, `insert(node, Some((parent,ref,forward)))`, `insert_reference`, `delete_reference`,
`delete(id, delete_target_refs)->Option`. `AddNodeItem` getters (`parent_node_id`/`reference_type_id`/
`requested_new_node_id`(may be null→assign)/`browse_name`/`node_class`/`node_attributes`/
`type_definition_id`/`status`) + `set_result(id,status)`; construction pre-validates (honor a pre-set bad
status). Node build: `AddNodeAttributes` variant → `async-opcua-nodes` type. **GATE must be ADDED**:
`Limits.clients_can_modify_address_space: bool` (`#[serde(default)]`=false), read via
`context.info.config` limits; OFF→`BadServiceUnsupported` (today's behavior). Status map in research.md
D4. All status codes exist. No new dep; warning-free in ALL feature legs. Deferred: GeneralModelChange
events, persistence, non-in-memory managers.

## Phase 1: Setup
- [X] T001 Confirm impl point (`memory_mgr_impl.rs` defaults), the `AddressSpace` mutation API + node
  builders (`async-opcua-nodes`), `AddNodeItem`/`AddReferenceItem` getters/`set_result`, and the exact
  `context.info.config` → limits path for the gate. No code change.

## Phase 2: Foundational
- [X] T002 codex: add `pub clients_can_modify_address_space: bool` (`#[serde(default)]`=false) to `Limits`
  in `async-opcua-server/src/config/limits.rs` (+ `defaults`/`Default`); ensure the sample
  `samples/demo-server/sample.server.test.conf` + `samples/server.conf` still parse (the field already
  appears in YAML). Warning-free. (depends T001)

## Phase 3: US1 — AddNodes + DeleteNodes (P1) 🎯 MVP
- [X] T003 [US1] codex: implement `add_nodes` + `delete_nodes` in the in-memory impl defaults (helpers in
  a new `memory/node_management_impl.rs` if cleaner). Gate off → set every item `BadServiceUnsupported`.
  On: AddNodes — honor any pre-set bad status; else validate parent exists (`BadParentNodeIdInvalid`),
  requested id free or assign (`BadNodeIdExists`), build the node from `node_class`+`AddNodeAttributes`
  (at least Object + Variable; `BadNodeClassInvalid`/`BadTypeDefinitionInvalid`/`BadNodeAttributesInvalid`
  as applicable), `insert` with parent + type-def refs, `set_result(assigned_id, Good)`. DeleteNodes —
  `delete(id, delete_target_references)`; `None`→`BadNodeIdUnknown` else `Good`. No panic on any input.
  (depends T002)
- [X] T004 [P] [US1] Claude: e2e tests in `async-opcua/tests/integration/node_management.rs` (extend/add;
  register `mod node_management;` if new) driving the real service via the harness with the gate ENABLED:
  AddNodes→Browse/Read sees it; dup id→`BadNodeIdExists`; missing parent→`BadParentNodeIdInvalid`;
  DeleteNodes→Browse-absent; unknown→`BadNodeIdUnknown`; mixed valid/invalid batch→per-item status; gate
  OFF→every op `BadServiceUnsupported`; crafted/oversized batch→no panic. Anchored to Part 4 §5.7. (depends T003)
- [X] T005 [US1] Gate; **commit US1** (`feat(022 US1): writable address space — AddNodes/DeleteNodes (gated)`).

## Phase 4: US2 — AddReferences + DeleteReferences (P2)
- [X] T006 [US2] codex: implement `add_references` + `delete_references` in the in-memory impl defaults:
  gate off → unsupported; on: validate source/target/reference-type (`BadSourceNodeIdInvalid`/
  `BadTargetNodeIdInvalid`/`BadReferenceTypeIdInvalid`), `insert_reference`/`delete_reference` honoring
  direction + the source/target ownership rule documented on the trait, set status. (depends T003)
- [X] T007 [P] [US2] Claude: e2e tests — AddReferences→Browse shows it (right direction); bad
  source/target/type→respective status; DeleteReferences→Browse no longer shows it; gate OFF→unsupported;
  no panic. (depends T006)
- [X] T008 [US2] Gate; **commit US2** (`feat(022 US2): writable address space — AddReferences/DeleteReferences`).

## Phase 5: US3 — demo + gate/edge validation (P3)
- [X] T009 [US3] codex: demonstrate the writable address space in the demo-server (a node manager / config
  switch with `clients_can_modify_address_space` on, or documented), WITHOUT changing the default sample
  behavior. (depends T008)
- [X] T010 [US3] Claude: edge + gating pass — delete a node with children/references (consistency, no
  dangling refs, no panic), duplicate add, add under missing parent, batch at/over
  `max_nodes_per_node_management`; confirm gate-OFF refusal across all four ops; `cargo build -p
  async-opcua-demo-server` clean. Gate; **commit US3** (`feat(022 US3): demo writable address space + edge/gating tests`).

## Phase 6: Polish
- [X] T011 Update `specs/conformance-gap-backlog.md` (Tier 3 #6 → implemented, opt-in/gated; note
  model-change events still deferred). Doc-comment the gate + the deferred GeneralModelChangeEventType.
- [X] T012 Final gate: fmt + clippy --all-targets --all-features + json-off/no-default legs +
  `cargo test -p async-opcua --test integration_tests node_management -- --test-threads=1` +
  `cargo build -p async-opcua-demo-server` + existing-suite spot-check.

---

## Dependencies & Execution
- Setup (T001) → Foundational gate (T002) → US1 (T003–T005 MVP) → US2 (T006–T008) → US3 (T009–T010) →
  Polish. codex: T002, T003, T006, T009 (production/sample). Claude: all tests (T004, T007, T010) + docs.
  One commit per story. T004/T007 [P] = written alongside their codex sibling (different files).

## Notes
- Additive/opt-in: gate default OFF → existing read-only servers unchanged; `NodeMutator` trait +
  downstream overrides untouched.
- Deferred: `GeneralModelChangeEventType` emission; address-space persistence; AddNodes for complex typed
  instances beyond existing node/type support; writability for non-in-memory node managers.
- If full 9-node-class AddNodes is too large for US1, ship Object+Variable (the tested cases) and return
  `BadNodeClassInvalid`/`BadServiceUnsupported` for the rest, noting the partial coverage (no silent gap).
