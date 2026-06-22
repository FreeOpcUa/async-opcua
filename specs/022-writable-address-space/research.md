# Research: Writable Address Space (NodeManagement)

## Decision 1 — Implement in the in-memory impl defaults (delegated to by the wrapper)

**Finding**: `InMemoryNodeManager<TImpl>` implements `NodeMutator` (`memory/mod.rs:1113+`) by delegating
`add_nodes`/`add_references`/`delete_nodes`/`delete_references` to `self.inner.<op>(context,
&self.address_space, items)` — the `InMemoryNodeManagerImpl` trait methods (`memory/memory_mgr_impl.rs`),
whose defaults return `BadServiceUnsupported`.
**Decision**: implement the real mutation in those in-memory impl **defaults** (factoring the heavy
logic into helpers, e.g. a new `memory/node_management_impl.rs`), operating on the `&RwLock<AddressSpace>`
already passed in. **Rationale**: additive — the `NodeMutator` trait and any downstream override are
untouched; every in-memory-based manager (SimpleNodeManager, TestNodeManager, custom) gains the
gated capability for free. **Alternatives**: implement in the wrapper `memory/mod.rs` (bypasses impls'
ability to override → less flexible); change the `NodeMutator` trait defaults (would affect non-in-memory
managers — wrong scope).

## Decision 2 — The gate flag must be ADDED to `Limits`

**Finding**: `clients_can_modify_address_space` is present in the sample server YAML under `limits:` but is
**not** a field on `Limits` (`config/limits.rs`) — serde currently ignores it; it is dead.
**Decision**: add `pub clients_can_modify_address_space: bool` to `Limits` with `#[serde(default)]`
(= `false`) and a `defaults` entry; read it via `context.info.config.limits.clients_can_modify_address_space`
(confirm the exact path — `ServerInfo.config: Arc<ServerConfig>`). When `false` (default), every op returns
the same status as today (`BadServiceUnsupported`) → no behavior change; when `true`, mutation proceeds.
**Rationale**: makes the spec's "existing flag" real and the sample YAML meaningful; additive (new field,
default false). **Alternatives**: a per-node-manager builder flag (more plumbing; the config flag is the
operator-facing switch the sample already implies).

## Decision 3 — Node construction from `AddNodeAttributes`

**Finding**: `AddNodeItem` already parses `AddNodeAttributes` (enum: Object / Variable / Method /
ObjectType / VariableType / ReferenceType / DataType / View / Generic — `async-opcua-types/src/
add_node_attributes.rs`) and runs `validate_attributes` + null parent/reference/type-definition checks at
construction (setting an initial `status`). The concrete node types live in `async-opcua-nodes` (Variable,
Object, Method, …) with builders and a `specified_attributes` bitmask indicating which attributes the
client actually set.
**Decision**: per item, match `node_class` / `AddNodeAttributes` variant → construct the matching node
type with `(requested_or_assigned NodeId, browse_name, display_name)` and apply the supplied attributes
(respecting the `specified_attributes` mask, defaulting the rest), then `AddressSpace::insert(node,
Some(parent + reference_type + forward))` plus the type-definition reference where applicable.
**Rationale**: reuses the existing node types + attribute structs; the per-class mapping is mechanical.
This is the main implementation effort. **Alternatives**: support only Object/Variable first (MVP) and
return `BadNodeClassInvalid`/`BadNotSupported` for the rest — acceptable fallback if full coverage is too
large for one pass; US1 must at least cover Object + Variable (the common cases the tests use).

## Decision 4 — Status-code mapping (Part 4 §5.7)

**Decision** (per item; partial success in a batch; all status codes verified to exist):
- gate off → `BadServiceUnsupported`.
- AddNodes: requested id already present → `BadNodeIdExists`; parent missing → `BadParentNodeIdInvalid`;
  reference type null/unknown → `BadReferenceTypeIdInvalid`; node class invalid → `BadNodeClassInvalid`;
  type definition required-but-missing/invalid → `BadTypeDefinitionInvalid`; bad attributes →
  `BadNodeAttributesInvalid`; else insert + `Good` with the assigned NodeId. (Several of these are already
  pre-set by `AddNodeItem::new`; the impl must respect a pre-set bad status and skip.)
- DeleteNodes: `AddressSpace::delete(id, delete_target_references)` → `None` ⇒ `BadNodeIdUnknown`, else
  `Good`.
- AddReferences: source missing → `BadSourceNodeIdInvalid`; target missing → `BadTargetNodeIdInvalid`;
  ref type null/unknown → `BadReferenceTypeIdInvalid`; else `insert_reference` + `Good` (set source/target
  status per the trait's ownership rule).
- DeleteReferences: `delete_reference` (missing ref tolerated per spec) + `Good`/appropriate status.
**Rationale**: matches §5.7; never a generic error; no panic.

## Decision 5 — Consistency, no-panic, batch bound

**Decision**: all id/attribute access is fallible (no `unwrap` on client input); the batch is already
capped by `max_nodes_per_node_management`; deletes go through `AddressSpace::delete` /
`delete_node_references` so no dangling references remain; an added node is immediately browsable/readable
because the `AddressSpace` is the single source of truth for Read/Browse. **Model-change events
(`GeneralModelChangeEventType`) are OUT OF SCOPE** (Part 4 optional) — noted, deferred.

## Decision 6 — Verification anchoring

**Decision**: Claude's tests drive the **real NodeManagement service** end-to-end via the harness
(`SimpleNodeManager`/`TestNodeManager` with the gate enabled): AddNodes→Browse/Read sees it; dup→
`BadNodeIdExists`; missing parent→`BadParentNodeIdInvalid`; DeleteNodes→Browse-absent; unknown→
`BadNodeIdUnknown`; AddReferences→Browse-shows; DeleteReferences→Browse-absent; **gate off → every op
refused**; crafted/oversized batch → per-item status, **no panic**. Anchored to Part 4 §5.7, not codex
loopback. **Rationale**: verification division; the status-code + round-trip behavior is the contract.
