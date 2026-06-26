# Implementation Plan: Role-Based Access Control / Authorization Model

**Branch**: `031-rbac-authorization` | **Date**: 2026-06-26 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `specs/031-rbac-authorization/spec.md`

## Summary

Build the full OPC UA node-level authorization model in `async-opcua-server`: resolve a Session's Roles
from its identity at activation, serve the RolePermissions/UserRolePermissions/AccessRestrictions node
attributes, and enforce `PermissionType` per node across Read/Write/Call/Browse/History/NodeManagement/event
delivery — with per-namespace defaults, the standard RoleSet info-model + management Methods, and a
configuration surface. Backwards compatible: with no role configuration, behaviour is unchanged
(permissive); enforcement is opt-in. The generated DataTypes (RolePermissionType, PermissionType,
AccessRestrictionType, IdentityMappingRuleType), the AttributeId enum entries, the well-known Role NodeIds,
and the RoleSet object in the core nodeset **already exist** — the work is the runtime model, attribute
serving, identity→role resolution, enforcement wiring, and config.

## Technical Context

**Language/Version**: Rust (workspace edition; async-opcua-server)
**Primary Dependencies**: async-opcua-types (generated DataTypes/NodeIds), async-opcua-nodes (Node/Base),
async-opcua-core-namespace (core nodeset incl. RoleSet), tokio; no new external deps expected.
**Storage**: In-memory address space (Base node attributes + per-namespace default tables + per-session
resolved role set). No persistence required.
**Testing**: `cargo test` — server unit tests + `async-opcua/tests/integration` (client↔server harness);
4-stack interop harness for the RoleSet browse interop (SC-002).
**Target Platform**: Linux server library; must build under `--no-default-features` and `--all-features`.
**Project Type**: Single Rust workspace (library crates), per existing structure.
**Performance Goals**: Role resolution is once-per-session-activate (cached); per-request enforcement is an
O(roles × permissions) membership check on already-loaded node attributes — negligible vs the existing
attribute read path. No new hot-path allocation per request beyond an `Arc` clone of the cached role set.
**Constraints**: Zero regression when unconfigured (SC-007); enforcement fail-closed only where configured
or under the secure preset; no panics on attacker-influenced input (Constitution IV).
**Scale/Scope**: ~150 tasks across 8 user stories; touches authenticator, RequestContext, address-space
attribute read/write, the per-service enforcement points, config, and the RoleSet method handlers.

### Key facts from the codebase survey (de-risks the plan)

- `AttributeId::RolePermissions=24`, `UserRolePermissions=25`, `AccessRestrictions=26` already exist in
  `async-opcua-types/src/attribute.rs` (NOT 16/17/18 — those are ArrayDimensions/AccessLevel/UserAccessLevel;
  the spec parenthetical is corrected in research.md).
- `RolePermissionType`, `PermissionType`, `AccessRestrictionType`, `IdentityMappingRuleType` are already
  generated in `async-opcua-types/src/generated/types/`.
- Well-known Role NodeIds (`WellKnownRole_*` with their Add/Remove Identity/Application/Endpoint methods) and
  the `RoleSet` object under `Server.ServerCapabilities` are already in `async-opcua-core-namespace` (nodeset_16).
- `Base` (`async-opcua-nodes/src/base.rs`) does NOT yet store role_permissions/access_restrictions — new
  optional fields + `get_attribute` cases (24/25/26) are needed.
- `RequestContext`/`RequestContextInner` (`node_manager/context.rs`) carries `token`, `session`,
  `authenticator`, `info` but NO resolved role set — the central place to add it.
- Enforcement centralizes in `address_space/utils.rs` (`is_readable`, `user_access_level`,
  `validate_write_access`, `read_node_value` UserAccessLevel/UserExecutable computation); Write already maps
  RolePermissions→`WriteMask::ROLE_PERMISSIONS`.
- `AuthManager::core_permissions` returns `CoreServerPermissions{ read_diagnostics }` — extend with the
  resolved role set; `DefaultAuthenticator`/`ServerUserToken`/`ServerConfig` are the config anchors.

## Constitution Check

| Principle | Gate | Status |
| --- | --- | --- |
| I. Correctness Over Completion (NON-NEGOTIABLE) | Each enforced permission decision is covered by an allow AND a deny test; no service silently skips its check. | PASS — every US has allow+deny acceptance scenarios; tasks include per-service deny tests. |
| II. Do It Right Once | Single central authorization decision point (no per-service ad-hoc logic divergence); reuse generated types, don't re-roll. | PASS — one `authorize(context, node, permission)` decision path; reuse generated DataTypes + nodeset. |
| III. Individual Task Discipline | Tasks one-per-line, executed/verified individually (one task per codex dispatch). | PASS — tasks.md will keep one task per line; implement runs one at a time. |
| IV. Security Is Paramount (fail-closed) | Authorization fails CLOSED where enforcement applies; no panic on attacker input; default must not silently weaken security. | PASS WITH JUSTIFICATION — see below. |
| V. Leave It Better | No debris; existing UserAccessLevel/UserExecutable path is unified with roles, not duplicated. | PASS — roles fold into the existing effective-access computation. |

**Principle IV justification (the permissive-when-unconfigured default).** The default posture is
*permissive when no RolePermissions/namespace-default is configured*, which preserves existing behaviour
(SC-007) and is the OPC UA model (a Node with no RolePermissions is governed only by AccessLevel/Executable,
as today). This is NOT a silent weakening: it is the documented, opt-in baseline, and where enforcement DOES
apply (a node/namespace has RolePermissions, or the secure preset / global enforce posture is selected) the
decision is strictly fail-closed — absence of the required PermissionType bit ⇒ `Bad_UserAccessDenied`.
A documented secure preset (FR-017) provides the fail-closed-by-default option. The enforcement code must
bound and never panic on attacker input (it operates on already-decoded, server-held node attributes and the
session's resolved roles — no new untrusted parse path is introduced).

**Result**: PASS. No unjustified violations; no Complexity Tracking entries required.

## Project Structure

### Documentation (this feature)

```
specs/031-rbac-authorization/
├── spec.md              # done (speckit-specify)
├── plan.md              # this file
├── research.md          # decisions (role storage, attribute ids, enforcement layering, defaults)
├── data-model.md        # entities → concrete Rust types / nodeset
├── contracts/
│   └── authorization.md # public surfaces: config builder, RoleResolver, authorize() decision, attribute serving
├── quickstart.md        # configure roles + verify enforcement
└── checklists/requirements.md   # done
```

### Source Code (repository root)

Single Rust workspace; the feature is additive within existing crates:

```
async-opcua-types/src/
├── attribute.rs                 # (already) RolePermissions/UserRolePermissions/AccessRestrictions ids 24/25/26
└── generated/types/             # (already) RolePermissionType, PermissionType, AccessRestrictionType, IdentityMappingRuleType

async-opcua-nodes/src/
└── base.rs                      # ADD optional role_permissions / access_restrictions fields + get_attribute cases

async-opcua-server/src/
├── authorization/               # NEW module: PermissionType helpers, RoleResolver, identity-mapping rules,
│                                #   the authorize() decision, namespace-default tables, secure preset
├── authenticator.rs             # extend CoreServerPermissions/AuthManager to surface the resolved role set
├── node_manager/context.rs      # carry the resolved session role set on RequestContext
├── address_space/utils.rs       # fold role checks into is_readable/user_access_level/validate_write_access/
│                                #   read_node_value (UserAccessLevel/UserExecutable/UserRolePermissions)
├── session/services/            # Browse/HistoryRead/HistoryUpdate/NodeManagement enforcement hooks
├── subscriptions/               # ReceiveEvents gating on event delivery
├── config/{server.rs,limits.rs} # role/identity-mapping/default-permission config + enforcement posture
└── (RoleSet method handlers wired on the core node manager, like the PubSub config methods pattern)

async-opcua/tests/integration/   # NEW rbac.rs: end-to-end allow/deny across services + RoleSet browse
```

**Structure Decision**: Single-project (Option 1). A new `authorization/` module in `async-opcua-server`
holds the role model, resolver, and the central `authorize()` decision; everything else is additive edits at
the existing enforcement points. No new crate (the generated types live in async-opcua-types already).

## Approach by user story (maps spec → hook points)

- **US1 (model + attributes)**: add `role_permissions`/`access_restrictions` to `Base` + `get_attribute`
  cases (24/25/26); compute `UserRolePermissions` in `read_node_value` from the session role set (parallel to
  the existing UserAccessLevel/UserExecutable special-casing).
- **US2 (identity→roles + RoleSet)**: `RoleResolver` + `IdentityMappingRule` evaluation at session activate;
  store the resolved role set on `RequestContext`/`Session`; verify the well-known roles + RoleSet already in
  the nodeset are correct and browsable.
- **US3 (Read/Write/Call enforce)**: central `authorize(context, node, PermissionType)`; fold into
  `is_readable`/`user_access_level`/`validate_write_access` and `is_user_executable`; permissive when no
  RolePermissions.
- **US4 (Browse + AccessRestrictions)**: filter Browse results by Browse permission; check AccessRestrictions
  (Signing/Encryption/Session) against the channel security mode → `Bad_SecurityModeInsufficient`;
  ApplyRestrictionsToBrowse.
- **US5 (history + node-mgmt + events)**: enforce ReadHistory/Insert/Modify/DeleteHistory, AddNode/DeleteNode/
  AddReference/RemoveReference, ReceiveEvents at their service handlers.
- **US6 (namespace defaults)**: per-namespace Default*Permissions tables consulted when a node lacks explicit
  values; expose via NamespaceMetadata; node-level overrides win.
- **US7 (runtime role methods)**: RoleSet AddRole/RemoveRole + RoleType Add/Remove Identity/Application/
  Endpoint method handlers (PubSub-config-methods pattern), gated to SecurityAdmin.
- **US8 (config + secure defaults)**: `ServerUserToken.roles`, `ServerConfig` identity-mapping/default tables,
  enforcement-posture flag in `Limits`, builder methods, and the documented secure preset.

## Complexity Tracking

No constitution violations requiring justification; table intentionally empty.

| Violation | Why Needed | Simpler Alternative Rejected Because |
| --- | --- | --- |
| (none) | — | — |
