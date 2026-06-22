# Implementation Plan: Writable Address Space (NodeManagement)

**Branch**: `022-writable-address-space` | **Date**: 2026-06-22 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/022-writable-address-space/spec.md`

## Summary

Implement AddNodes / DeleteNodes / AddReferences / DeleteReferences for the in-memory node manager,
gated by an (added) `clients_can_modify_address_space` config flag (default OFF → today's behavior). The
NodeManagement service, item types, batch limit, and the `NodeMutator` extension points are already
wired; this fills in the in-memory implementation by mutating the shared `AddressSpace` and returning the
Part 4 §5.7 per-operation status codes. (US1 AddNodes+DeleteNodes MVP; US2 references; US3 demo + gate +
edges.)

## Technical Context

**Language/Version**: Rust (workspace edition 2021).
**Primary Dependencies**: `async-opcua-server` (`InMemoryNodeManagerImpl`, `InMemoryNodeManager`,
`AddressSpace`, `AddNodeItem`/`AddNodeAttributes`/`DeleteNodeItem`/`AddReferenceItem`/
`DeleteReferenceItem`, `RequestContext`→`info.config`), `async-opcua-types`. **No new dependency.**
**Storage**: in-memory `AddressSpace` (no persistence; deferred).
**Testing**: Rust unit + integration tests (end-to-end through the NodeManagement service via the test
harness `TestNodeManager` / `SimpleNodeManager`), authored + run by Claude.
**Target Platform**: library + samples; all feature legs.
**Project Type**: library + samples.
**Performance Goals**: per-op O(1)–O(refs); batch bounded by `max_nodes_per_node_management`.
**Constraints**: opt-in/off-by-default; additive (no downstream impl forced to change); no panic on
crafted input; consistent address space (no dangling refs); clippy clean on all-features + json-off legs.
**Scale/Scope**: 1 config field + the 4 in-memory mutators (+ helpers) + demo wiring + tests.

### Key facts (verified in code)

- `InMemoryNodeManager<TImpl>` implements `NodeMutator` (`memory/mod.rs:1113+`) by delegating to
  `self.inner.<op>(context, &self.address_space, items)` — the `InMemoryNodeManagerImpl` trait methods in
  `memory/memory_mgr_impl.rs`, whose **defaults return `BadServiceUnsupported`**. → **Implement here**
  (the in-memory impl defaults, or a helper they call), operating on the `&RwLock<AddressSpace>` already
  passed in. Keeps the `NodeMutator` trait + downstream overrides untouched (additive).
- `AddressSpace` mutation API (`address_space/mod.rs`): `insert(node, parent+refs)`, `node_exists(id)`,
  `insert_reference(...)`, `delete_reference(...)`, `delete(id, delete_target_references) -> Option<...>`,
  `namespaces()`. These are the building blocks.
- `AddNodeItem` (`node_manager/node_management.rs`) already parses `AddNodeAttributes` via
  `from_extension_object` and runs `validate_attributes` + null parent/reference checks at construction,
  setting an initial status — so a lot of per-item validation already happens before the impl sees it.
  The impl must build a `NodeType` from `(node_class, browse_name, attributes)`, assign/validate the node
  id, insert with the parent + type-definition references, and set the result id + status.
- **GATE GAP**: `clients_can_modify_address_space` appears in the sample YAML under `limits:` but is **NOT
  a field on `Limits`** (`config/limits.rs`) — currently silently ignored. This feature **adds** it
  (`pub clients_can_modify_address_space: bool`, `#[serde(default)]` = false) so the flag becomes real,
  read via `context.info.config.limits.clients_can_modify_address_space`. Additive (new field, default
  false → existing configs unchanged; the sample YAML line becomes meaningful).

## Constitution Check

- **I. Correctness Over Completion**: every op validated, precise Part 4 §5.7 status per item, partial
  success in batches, address space kept consistent (delete removes references → no dangling refs). No
  faked success. ✅
- **IV. Security Is Paramount**: NodeManagement is remotely reachable + attacker-controlled → mutation is
  OFF by default, gated by explicit config; when on, all ops are bounds/validity-checked and **never
  panic** (no unwrap on client ids/attributes; batch capped by `max_nodes_per_node_management`). ✅
- **II/III. Do It Right Once / Discipline**: reuse the existing `AddressSpace` mutation API + the
  already-wired service/item layer rather than a parallel path; additive trait-default implementation so
  no downstream impl breaks; one commit per user story. ✅
- **V. Leave It Better**: turns a `BadServiceUnsupported` stub into a real, opt-in capability + wires a
  previously-dead config flag. ✅
- **Verification division**: codex implements the mutators + gate + demo; Claude authors/runs all tests
  (end-to-end through the service, gate-off refusal, crafted no-panic), anchored to Part 4 §5.7. ✅

**Gate: PASS** — no violations; no Complexity Tracking entries.

## Project Structure

### Documentation (this feature)

```
specs/022-writable-address-space/
├── spec.md  plan.md  research.md  data-model.md  quickstart.md
├── contracts/api-surface.md
└── checklists/requirements.md
```

### Source Code (repository root)

```
async-opcua-server/src/config/limits.rs        # (codex) ADD `clients_can_modify_address_space: bool`
                                                #   (#[serde(default)] = false) + defaults; additive.
async-opcua-server/src/node_manager/memory/
├── memory_mgr_impl.rs                          # (codex) implement add_nodes/delete_nodes/add_references/
│                                               #   delete_references defaults: gate-check, then mutate the
│                                               #   AddressSpace via insert/delete/insert_reference/
│                                               #   delete_reference; set per-item Part 4 §5.7 status.
│                                               #   (Factor the node-build/validation into helpers, e.g. a
│                                               #   new `memory/node_management_impl.rs`, if cleaner.)
└── mod.rs                                      # (only if a re-export/helper is needed)
samples/demo-server/...                         # US3 (codex): demonstrate a writable node manager / config
                                                #   switch; default sample behavior unchanged.
async-opcua/tests/integration/node_management.rs (extend/add)  # Claude: e2e add/delete/refs + gate-off +
                                                #   edge/no-panic tests through the NodeManagement service.
async-opcua-server/src/node_manager/memory/... #[cfg(test)]    # Claude: focused unit tests if useful.
```

**Structure decision**: implement in the in-memory impl defaults (delegated to by the wrapper) so the
standard/sample server and the test harness become gated-writable without changing the `NodeMutator`
trait or any downstream override. Add the config flag to `Limits`. No new crate/dep.

## Complexity Tracking

No constitution violations; no entries. (Node construction from `AddNodeAttributes` is the main
implementation effort but uses existing `AddressSpace`/attribute types — not added complexity.)
