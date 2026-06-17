# Contract — `NodeManager` Capability-Trait Decomposition (FR-043 / R3)

The fat `NodeManager` trait (~30 methods spanning read, write, every history variant, browse, query,
call, add/delete nodes/references, and monitored-item lifecycle) is segregated into focused capability
traits so an implementer depends only on the operations it actually provides (Interface Segregation).
This is a **breaking change**, acceptable at 0.19, and must minimize churn for existing implementers via
default impls.

## Capability sub-traits (proposed)

| Sub-trait | Responsibility | Methods (from current `NodeManager`) |
|-----------|----------------|--------------------------------------|
| `NodeManagerCore` | identity & ownership | `owns_node`, namespace/registration, `init` |
| `AttributeProvider` | value/attribute read & write | read attributes, write attributes |
| `ViewProvider` | browsing & queries | browse, browse-next, translate-browse-paths, query |
| `MethodProvider` | method calls | call |
| `NodeMutator` | structural changes | add/delete nodes, add/delete references |
| `HistoryProvider` | history | history-read (raw/processed/at-time/events), history-update |
| `MonitoredItemProvider` | subscription wiring | create/modify/delete monitored items, set-monitoring-mode |

## Composition

- A composing supertrait (`NodeManager: NodeManagerCore + AttributeProvider + ViewProvider + …`) or a
  registration model where a node manager declares which capability traits it implements.
- **Default impls**: each capability method retains the current "return `BadServiceUnsupported`"
  default, so an implementer that only does, e.g., attributes + browse implements two sub-traits and
  inherits safe defaults for the rest — preserving today's ergonomics while making the dependency
  explicit.
- The built-in `InMemoryNodeManager` / `SimpleNodeManager` and the diagnostics/core-namespace managers
  are updated to the new trait set; their public construction surface is preserved where possible.

## Migration for existing implementers

| Today | After |
|-------|-------|
| `impl NodeManager for Foo { /* override the few methods you support */ }` | `impl NodeManagerCore for Foo { … }` + `impl AttributeProvider for Foo { … }` + the other sub-traits you actually use; unimplemented capabilities are covered by default impls |

## Constraints

- **No behavioral change** to request dispatch/fan-out (`owns_node` partitioning, concurrent
  `join_all`) — only the trait shape changes, not the runtime semantics.
- **No wire change** — service handling is identical; interop gate (FR-046) still applies.
- The segregation is a single, independently verifiable task in Track F (Constitution III), landing in
  the 0.19 break window with its migration note in the changelog (SC-011).

## Open decisions deferred to implementation

- Whether to use a marker-registration model vs. a supertrait bound — decided during the task by which
  yields the least implementer churn while keeping object-safety (`dyn NodeManager`) intact.
- Exact sub-trait boundaries may shift slightly once the real method set is enumerated against
  `node_manager/mod.rs`; the seven groups above are the target.
