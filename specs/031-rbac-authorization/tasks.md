# Tasks: Role-Based Access Control / Authorization Model

**Feature**: `031-rbac-authorization` | **Spec**: [spec.md](./spec.md) | **Plan**: [plan.md](./plan.md)

## Format: `[ID] [P?] [Story] Description (Spec: Part N §x.y)`

- **[P]** = parallelizable (different files, no incomplete dependency).
- Every task cites the OPC UA reference section(s) — codex MUST look them up via its OPC UA reference MCP
  (Part N = OPC-10000-N). See spec.md "Spec Traceability".
- One task per line; execute and verify one at a time (Constitution III; one task per codex dispatch).
- Tests are REQUIRED for enforcement (Constitution I/IV): each enforced permission needs an ALLOW and a DENY
  test. Claude authors tests independently of the codex implementation (see memory `codex-no-self-authored-tests`).
- Paths are repo-relative. `srv = async-opcua-server/src`, `types = async-opcua-types/src`,
  `nodes = async-opcua-nodes/src`, `it = async-opcua/tests/integration`.

---

## Phase 1: Setup (shared infrastructure)

- [ ] T001 Create the `authorization` module skeleton `srv/authorization/mod.rs` (+ `pub(crate) mod authorization;` in `srv/lib.rs`); empty submodules `resolver`, `rules`, `decision`, `defaults`, `preset` (Spec: Part 18 §4; Part 3 §4.8)
- [X] T002 [P] Add a `permission_for_service` mapping helper in `srv/authorization/decision.rs` mapping each service/operation to its required `PermissionType` bit per the usage table (Spec: Part 3 §4.8.2; Part 3 §8.55)
- [X] T003 [P] Add `PermissionType` convenience helpers (contains/union over `opcua_types::PermissionType`) in `srv/authorization/decision.rs` (Spec: Part 3 §8.55)
- [ ] T004 [P] Document the module's responsibility + the permissive-default contract at the top of `srv/authorization/mod.rs` (Spec: Part 3 §4.8; plan.md Constitution IV justification)

## Phase 2: Foundational (blocking prerequisites — BLOCKS all user stories)

- [X] T005 Add optional `role_permissions: Option<Vec<RolePermissionType>>` and `access_restrictions: Option<AccessRestrictionType>` fields to `nodes/base.rs::Base` with constructors/setters preserving existing construction (Spec: Part 3 §8.55, §8.56)
- [X] T006 Add `RolePermissions`(24)/`AccessRestrictions`(26) cases to `Base::get_attribute` in `nodes/base.rs` returning the stored values (null when unset); confirm `UserRolePermissions`(25) is handled in the read path, not here (Spec: Part 3 §5.2; Part 6 attribute table)
- [X] T007 [P] Add `VariableBuilder`/`ObjectBuilder`/generic node builder `.role_permissions(...)` and `.access_restrictions(...)` methods in `nodes/` builders (Spec: Part 3 §8.55, §8.56)
- [X] T008 Add a resolved-role-set carrier to `srv/node_manager/context.rs` — `RequestContextInner.user_roles: Arc<Vec<NodeId>>` + `RequestContext::user_roles(&self) -> &[NodeId]`, defaulting to empty (Spec: Part 18 §4.4.1; Part 3 §4.9)
- [ ] T009 Extend `srv/authenticator.rs::CoreServerPermissions` (or a new return) so the authenticator can surface the resolved role set for a `UserToken`; keep `read_diagnostics` behaviour (Spec: Part 18 §4; Part 3 §4.9)
- [X] T010 Implement the central `authorize(context, node_id, effective_role_permissions, required) -> bool` in `srv/authorization/decision.rs` with the permissive-when-unconfigured + fail-closed semantics from research.md D4/D5 (Spec: Part 3 §4.8.2; Part 4 §7.39 Bad_UserAccessDenied)
- [X] T011 [P] Unit-test `authorize`: union across roles, unconfigured⇒permit, list-excludes-my-roles⇒deny, required-bit present/absent — in `srv/authorization/decision.rs` tests (Spec: Part 3 §4.8.2)
- [X] T012 Add an `EffectiveNodePermissions` accessor that returns node-level RolePermissions else namespace default else "unconfigured" (namespace-default lookup stubbed until US6) in `srv/authorization/decision.rs` (Spec: Part 3 §4.8.2; Part 5 §6)

---

## Phase 3: User Story 1 — Permission model & readable permission attributes (P1) 🎯 MVP

**Goal**: clients can read RolePermissions(24)/UserRolePermissions(25)/AccessRestrictions(26); UserRolePermissions
is the per-session-role subset. **Independent test**: configure a node with two roles' permissions, read 24/25/26.

### Tests for US1

- [X] T013 [P] [US1] Integration test `it/rbac.rs::reads_role_permissions_attribute` — configured node returns full RolePermissions list (Spec: Part 3 §8.55; Part 4 §5.10 Read)
- [X] T014 [P] [US1] Integration test `it/rbac.rs::reads_access_restrictions_attribute` — configured AccessRestrictionType bitmask returned (Spec: Part 3 §8.56)
- [X] T015 [P] [US1] Integration test `it/rbac.rs::user_role_permissions_is_session_subset` — only the session's granted roles' entries returned (Spec: Part 3 §5.2; Part 18 §4)
- [X] T016 [P] [US1] Integration test `it/rbac.rs::unconfigured_permission_attrs_return_null` — node with no RolePermissions returns null/empty, no error (Spec: Part 3 §5.2)

### Implementation for US1

- [X] T017 [US1] Serve `RolePermissions`(24) and `AccessRestrictions`(26) through the address-space read path `srv/address_space/utils.rs::read_node_value` (Spec: Part 3 §5.2; Part 4 §5.10)
- [X] T018 [US1] Compute and serve `UserRolePermissions`(25) in `srv/address_space/utils.rs::read_node_value` from `context.user_roles()` ∩ node RolePermissions, merged across roles (Spec: Part 3 §5.2; Part 18 §4)
- [ ] T019 [US1] Gate reading the RolePermissions attribute itself by the `ReadRolePermissions` permission in the read path (permissive when unconfigured) (Spec: Part 3 §8.55 ReadRolePermissions)
- [ ] T020 [US1] Ensure `node.into()`/codegen-loaded nodes can carry RolePermissions/AccessRestrictions from the nodeset loader (preserve when present) `srv/node_manager/memory` (Spec: Part 3 §5.2)
- [X] T021 [US1] Verify the four US1 tests pass under default features; fix any read-path regressions (Spec: Part 4 §5.10)

**Checkpoint**: permission attributes are introspectable; UserRolePermissions is role-aware.

---

## Phase 4: User Story 2 — Identity→role resolution, RoleSet & well-known roles (P1)

**Goal**: each session gets a resolved role set from identity-mapping rules; RoleSet + 8 well-known roles are
browsable. **Independent test**: connect with mapped identities, check granted roles; browse RoleSet.

### Tests for US2

- [ ] T022 [P] [US2] Integration test `it/rbac.rs::username_maps_to_role` — username→Operator grants Operator (+AuthenticatedUser) (Spec: Part 18 §4.4.3; Part 3 §4.9.2)
- [X] T023 [P] [US2] Integration test `it/rbac.rs::anonymous_gets_anonymous_role_only` (Spec: Part 3 §4.9.2)
- [ ] T024 [P] [US2] Integration test `it/rbac.rs::cert_thumbprint_maps_to_role` — X509 thumbprint→SecurityAdmin (Spec: Part 18 §4.4.2 Thumbprint)
- [X] T025 [P] [US2] Integration test `it/rbac.rs::roleset_has_eight_well_known_roles` — browse `Server.ServerCapabilities.RoleSet` finds the 8 RoleType instances at standard NodeIds (Spec: Part 5 ServerCapabilities; Part 18 §4.4.1, §4.5)

### Implementation for US2

- [X] T026 [US2] Define the runtime `IdentityMappingRule` criteria enum (AnonymousIdentity/AuthenticatedUser/UserName/Thumbprint/Role/GroupId/Application) in `srv/authorization/rules.rs`, mapping to/from `IdentityMappingRuleType`/`IdentityCriteriaType` (Spec: Part 18 §4.4.2, §4.4.3)
- [X] T027 [US2] Define `ResolvedIdentity` (identity token kind + value, cert thumbprint, issued-token groups, application URI, endpoint) assembled at activate in `srv/authorization/resolver.rs` (Spec: Part 18 §4.4.1)
- [X] T028 [US2] Implement `RoleResolver` with the seeded 8 well-known roles + their default identity criteria (Anonymous⇒AnonymousIdentity, AuthenticatedUser⇒AuthenticatedUser) in `srv/authorization/resolver.rs` (Spec: Part 3 §4.9.2; Part 18 §4.4.1)
- [X] T029 [US2] Implement `RoleResolver::resolve(&ResolvedIdentity) -> Vec<NodeId>` evaluating all rules incl. Applications/Endpoints include/exclude filtering (Spec: Part 18 §4.4.1 Applications/Endpoints, §4.4.3)
- [X] T030 [US2] Resolve the role set at session activation and cache it (the resolved role set) on the Session; populate `RequestContextInner.user_roles` from it (Spec: Part 4 §5.6 ActivateSession; Part 18 §4)
- [X] T031 [US2] Assemble `ResolvedIdentity` from the activate path (identity token + channel cert thumbprint + app uri + endpoint) `srv/session/` (Spec: Part 4 §5.6.3; Part 18 §4.4.2)
- [X] T032 [P] [US2] Verify the well-known RoleType instances + RoleSet from the core nodeset (nodeset_16) load with correct BrowseNames/NodeIds; add any missing wiring `srv/node_manager/memory/core.rs` (Spec: Part 18 §4.4.1, §4.5; Part 5)
- [X] T033 [US2] Map well-known role NodeIds ↔ a `WellKnownRole` enum for ergonomic config `srv/authorization/mod.rs` (Spec: Part 3 §4.9.2; node_ids `WellKnownRole_*`)
- [X] T034 [US2] Verify the four US2 tests pass; confirm anonymous excludes AuthenticatedUser (Spec: Part 3 §4.9.2)

**Checkpoint**: sessions carry correct roles; RoleSet model is browsable.

---

## Phase 5: User Story 3 — Read / Write / Call enforcement (P1)

**Goal**: enforce Read/Write/Call per node by role; UserAccessLevel/UserExecutable reflect roles; permissive
when unconfigured. **Independent test**: Observer can read not write; Operator both; Engineer-only method.

### Tests for US3

- [X] T035 [P] [US3] Integration test `it/rbac.rs::write_denied_without_write_permission` (Bad_UserAccessDenied, value unchanged) (Spec: Part 4 §5.10 Write; Part 3 §8.55 Write)
- [X] T036 [P] [US3] Integration test `it/rbac.rs::write_allowed_with_write_permission` (Spec: Part 3 §8.55 Write)
- [X] T037 [P] [US3] Integration test `it/rbac.rs::read_denied_without_read_permission` (Spec: Part 3 §8.55 Read)
- [X] T038 [P] [US3] Integration test `it/rbac.rs::call_denied_without_call_permission` + allowed with it (Spec: Part 4 §5.11 Call; Part 3 §8.55 Call)
- [X] T039 [P] [US3] Integration test `it/rbac.rs::unconfigured_node_is_permissive` (backwards-compat) (Spec: Part 3 §4.8)
- [X] T040 [P] [US3] Integration test `it/rbac.rs::user_access_level_reflects_roles` (CurrentRead/CurrentWrite) (Spec: Part 3 §5.6.2 UserAccessLevel)
- [ ] T041 [P] [US3] Integration test `it/rbac.rs::multiple_roles_union_permissions` (Spec: Part 3 §4.8.2; FR-015)

### Implementation for US3

- [X] T042 [US3] Enforce the `Read` permission in `srv/address_space/utils.rs::is_readable`/`read_node_value` via `authorize(..., Read)`, permissive when unconfigured (Spec: Part 4 §5.10; Part 3 §8.55 Read)
- [X] T043 [US3] Fold role permissions into `srv/address_space/utils.rs::user_access_level` so UserAccessLevel CurrentRead/CurrentWrite reflect Read/Write permission (Spec: Part 3 §5.6.2)
- [X] T044 [US3] Enforce the `Write` permission on Value writes in `srv/address_space/utils.rs::validate_write_access`/writable check (Spec: Part 4 §5.10 Write; Part 3 §8.55 Write)
- [X] T045 [US3] Enforce `WriteAttribute`/`WriteRolePermissions` for non-Value attribute writes (RolePermissions attr write ⇒ WriteRolePermissions) `srv/address_space/utils.rs` (Spec: Part 3 §8.55 WriteAttribute/WriteRolePermissions)
- [X] T046 [US3] Enforce the `Call` permission via `authorize(..., Call)` in `srv/authenticator.rs::is_user_executable` + the method service path `srv/session/services/method.rs` (Spec: Part 4 §5.11; Part 3 §8.55 Call)
- [X] T047 [US3] Make `UserExecutable` reflect the Call permission for the session's roles `srv/address_space/utils.rs` (Spec: Part 3 §5.6.x UserExecutable)
- [X] T048 [US3] Return `Bad_UserAccessDenied` (not silent skip) on every denied per-node operation across Read/Write/Call (Spec: Part 4 §7.39 Bad_UserAccessDenied)
- [X] T049 [US3] Verify all seven US3 tests pass; run the full server crate + integration suite for zero regression when unconfigured (Spec: Part 4 §5.10–5.11; SC-007)

**Checkpoint**: core CRUD/Call enforcement is live and backwards-compatible — MVP+ security value delivered.

---

## Phase 6: User Story 4 — Browse permission & AccessRestrictions enforcement (P2)

**Goal**: Browse filtering by Browse permission; AccessRestrictions vs channel security mode. **Independent
test**: non-Operator can't see a Browse-restricted node; EncryptionRequired over Sign-only ⇒ insufficient.

### Tests for US4

- [X] T050 [P] [US4] Integration test `it/rbac.rs::browse_omits_nodes_without_browse_permission` (Spec: Part 4 §5.8 Browse; Part 3 §8.55 Browse)
- [X] T051 [P] [US4] Integration test `it/rbac.rs::encryption_required_rejects_unencrypted_access` (Bad_SecurityModeInsufficient) (Spec: Part 3 §8.56 EncryptionRequired)
- [X] T052 [P] [US4] Integration test `it/rbac.rs::session_required_rejects_sessionless` (Spec: Part 3 §8.56 SessionRequired; Part 4 §5.10)
- [X] T053 [P] [US4] Integration test `it/rbac.rs::apply_restrictions_to_browse_filters_node` (Spec: Part 3 §8.56 ApplyRestrictionsToBrowse)

### Implementation for US4

- [X] T054 [US4] Enforce the `Browse` permission by omitting denied nodes/references from Browse results in `srv/session/services/view.rs` / the browse node-manager path (Spec: Part 4 §5.8.2; Part 3 §8.55 Browse)
- [X] T055 [US4] Implement an `access_restrictions_ok(context, effective_restrictions) -> Result<(), StatusCode>` checking Signing/Encryption/Session vs the channel security mode + session presence in `srv/authorization/decision.rs` (Spec: Part 3 §8.56)
- [X] T056 [US4] AND `access_restrictions_ok` into the Read/Write/Call/History enforcement, returning `Bad_SecurityModeInsufficient` on failure (Spec: Part 3 §8.56; Part 4 §7.39)
- [X] T057 [US4] Implement `ApplyRestrictionsToBrowse`: apply AccessRestrictions to Browse filtering only when the bit is set `srv/session/services/view.rs` (Spec: Part 3 §8.56 ApplyRestrictionsToBrowse)
- [X] T058 [US4] Expose the channel `MessageSecurityMode` to the authorization decision via RequestContext/session `srv/node_manager/context.rs` (Spec: Part 4 §5.5 SecureChannel; Part 3 §8.56)
- [X] T059 [US4] Verify the four US4 tests pass (Spec: Part 3 §8.56; Part 4 §5.8)

**Checkpoint**: Browse + channel-security enforcement complete.

---

## Phase 7: User Story 5 — History & node-management enforcement (P2)

**Goal**: enforce history/node-mgmt/event permissions. **Independent test**: ReadHistory/DeleteHistory,
AddReference, ReceiveEvents allowed/denied by role.

### Tests for US5

- [X] T060 [P] [US5] Integration test `it/rbac.rs::history_read_denied_without_readhistory` (Spec: Part 11 §6 HistoryRead; Part 3 §8.55 ReadHistory)
- [X] T061 [P] [US5] Integration test `it/rbac.rs::history_delete_denied_without_deletehistory` (Spec: Part 11 §6 HistoryUpdate; Part 3 §8.55 DeleteHistory)
- [X] T062 [P] [US5] Integration test `it/rbac.rs::add_reference_denied_without_addreference` (Spec: Part 4 §5.7 AddReferences; Part 3 §8.55 AddReference)
- [X] T063 [P] [US5] Integration test `it/rbac.rs::receive_events_denied_filters_events` (Spec: Part 4 §5.12 MonitoredItems; Part 3 §8.55 ReceiveEvents)

### Implementation for US5

- [X] T064 [US5] Enforce `ReadHistory` on HistoryRead in `srv/services/history_read.rs` / `srv/session/services/attribute.rs` (Spec: Part 11 §6.3; Part 3 §8.55 ReadHistory)
- [X] T065 [US5] Enforce `InsertHistory`/`ModifyHistory`/`DeleteHistory` on HistoryUpdate per detail type in the history-update path `srv/node_manager/history.rs` consumers (Spec: Part 11 §6.8 HistoryUpdate; Part 3 §8.55)
- [X] T066 [US5] Enforce `AddNode`/`DeleteNode` on AddNodes/DeleteNodes in `srv/session/services/node_management.rs` (Spec: Part 4 §5.7.2/§5.7.4; Part 3 §8.55 AddNode/DeleteNode)
- [X] T067 [US5] Enforce `AddReference`/`RemoveReference` on AddReferences/DeleteReferences in `srv/session/services/node_management.rs` (Spec: Part 4 §5.7.3/§5.7.5; Part 3 §8.55)
- [X] T068 [US5] Enforce `ReceiveEvents` on event-notification delivery from event-source nodes in `srv/subscriptions/` event path (Spec: Part 4 §5.12.1.4; Part 3 §8.55 ReceiveEvents)
- [X] T069 [US5] Verify the four US5 tests pass (Spec: Part 11 §6; Part 4 §5.7)

**Checkpoint**: enforcement covers every permissioned service.

---

## Phase 8: User Story 6 — Per-namespace default permissions (P2)

**Goal**: namespace defaults govern nodes without explicit permissions; node-level overrides win.
**Independent test**: namespace default denies anonymous read; explicit node permission overrides.

### Tests for US6

- [X] T070 [P] [US6] Integration test `it/rbac.rs::namespace_default_governs_unconfigured_node` (Spec: Part 5 §6 NamespaceMetadata; Part 3 §4.8.2)
- [X] T071 [P] [US6] Integration test `it/rbac.rs::node_permission_overrides_namespace_default` (Spec: Part 3 §4.8.2)
- [X] T072 [P] [US6] Integration test `it/rbac.rs::default_role_permissions_readable_via_namespacemetadata` (Spec: Part 5 §6.2.x)

### Implementation for US6

- [X] T073 [US6] Add per-namespace default tables (DefaultRolePermissions/DefaultUserRolePermissions/DefaultAccessRestrictions) in `srv/authorization/defaults.rs`, keyed by namespace index (Spec: Part 5 §6 NamespacesType/NamespaceMetadataType)
- [X] T074 [US6] Wire `EffectiveNodePermissions` (T012) to fall back to the namespace default when a node has no explicit value; node-level wins (Spec: Part 3 §4.8.2)
- [X] T075 [US6] Expose Default* values on the NamespaceMetadata nodes for each namespace `srv/node_manager/memory/core.rs` (Spec: Part 5 §6.2 NamespaceMetadataType)
- [X] T076 [US6] Apply the same default fallback to AccessRestrictions resolution (Spec: Part 3 §8.56; Part 5 §6)
- [X] T077 [US6] Verify the three US6 tests pass (Spec: Part 5 §6)

**Checkpoint**: defaults reduce per-node config; precedence correct.

---

## Phase 9: User Story 7 — Runtime role management methods (P3)

**Goal**: SecurityAdmin can AddRole/AddIdentity etc. at runtime; non-admins denied. **Independent test**:
AddRole+AddIdentity grants a new session a role; non-admin rejected.

### Tests for US7

- [X] T078 [P] [US7] Integration test `it/rbac.rs::add_role_creates_roletype_instance` (Spec: Part 18 §4.6 AddRole)
- [X] T079 [P] [US7] Integration test `it/rbac.rs::add_identity_grants_new_session_role` (Spec: Part 18 §4.4.1 AddIdentity)
- [X] T080 [P] [US7] Integration test `it/rbac.rs::role_management_denied_to_non_security_admin` (Bad_UserAccessDenied) (Spec: Part 18 §4.6/§4.8; Part 3 §8.55 Call)
- [X] T081 [P] [US7] Integration test `it/rbac.rs::remove_identity_revokes_mapping` (Spec: Part 18 §4.4.1 RemoveIdentity)

### Implementation for US7

- [X] T082 [US7] Register `RoleSet.AddRole`/`RemoveRole` method callbacks on the core node manager (PubSub-config-methods pattern), reflecting new RoleType instances under RoleSet (Spec: Part 18 §4.6 RoleSetType Methods)
- [X] T083 [US7] Register `RoleType.AddIdentity`/`RemoveIdentity` callbacks updating the resolver's mapping rules (Spec: Part 18 §4.4.1 / §4.8)
- [X] T084 [US7] Register `RoleType.AddApplication`/`RemoveApplication` callbacks updating the role's application filter (Spec: Part 18 §4.4.1 Applications)
- [X] T085 [US7] Register `RoleType.AddEndpoint`/`RemoveEndpoint` callbacks updating the role's endpoint filter (Spec: Part 18 §4.4.1 Endpoints)
- [X] T086 [US7] Gate ALL role-management methods to SecurityAdmin (Call permission + role check), returning Bad_UserAccessDenied otherwise (Spec: Part 18 §4.8 security; Part 3 §4.9.2 SecurityAdmin)
- [X] T087 [US7] Ensure runtime mapping changes affect NEW sessions only (resolution at activate) and are reflected in the RoleSet model (Spec: Part 18 §4.4.1)
- [X] T088 [US7] Verify the four US7 tests pass (Spec: Part 18 §4.4.1, §4.6)

**Checkpoint**: runtime role administration works and is privilege-gated.

---

## Phase 10: User Story 8 — Configuration API & secure defaults (P3)

**Goal**: declare roles/mappings/defaults via the builder; opt-in enforcement; secure preset. **Independent
test**: no-config server unchanged; configured server enforces; secure preset restricts anonymous.

### Tests for US8

- [ ] T089 [P] [US8] Integration test `it/rbac.rs::no_role_config_is_unchanged_behaviour` (existing semantics) (Spec: Part 3 §4.8; SC-007)
- [ ] T090 [P] [US8] Integration test `it/rbac.rs::configured_server_enforces_roles` (Spec: Part 18 §4)
- [ ] T091 [P] [US8] Integration test `it/rbac.rs::secure_preset_restricts_anonymous` (Spec: Part 3 §4.9.2 suggested permissions)

### Implementation for US8

- [X] T092 [US8] Add `roles: Vec<NodeId>` to `srv/config/server.rs::ServerUserToken` + `with_roles(...)` (Spec: Part 18 §4.4.1; Part 3 §4.9)
- [ ] T093 [US8] Add identity-mapping-rule + per-namespace default config to `srv/config/server.rs::ServerConfig` (Spec: Part 18 §4.4.3; Part 5 §6)
- [ ] T094 [US8] Add `enforce_role_based_access: bool` (global posture) to `srv/config/limits.rs` (default false) (Spec: Part 3 §4.8; plan.md D5)
- [ ] T095 [US8] Add `ServerBuilder` methods: `identity_mapping_rule`, `default_role_permissions`, `default_access_restrictions`, `enforce_role_based_access`, `with_secure_role_preset` `srv/builder.rs` (Spec: Part 18 §4; Part 5 §6)
- [ ] T096 [US8] Wire `DefaultAuthenticator` to grant each `ServerUserToken`'s configured roles via the resolver `srv/authenticator.rs` (Spec: Part 18 §4.4.1)
- [ ] T097 [US8] Implement `with_secure_role_preset` in `srv/authorization/preset.rs` applying the Part 3 §4.9.2 well-known-role suggested permissions (Spec: Part 3 §4.9.2)
- [ ] T098 [US8] Verify the three US8 tests pass; confirm no-config path is byte-for-byte the old behaviour (Spec: SC-007)

**Checkpoint**: configurable, opt-in, with a secure preset.

---

## Phase 11: Polish & cross-cutting concerns

- [ ] T099 [P] Run the FULL `cargo test -p async-opcua-server` (all binaries) — zero regressions (Spec: SC-007)
- [ ] T100 [P] Build + test under `--no-default-features` and `--all-features`; fix any feature-gating gaps (Spec: FR-016)
- [ ] T101 [P] `cargo clippy --workspace --all-targets` + `cargo fmt --all --check` clean (Spec: Constitution V)
- [ ] T102 [P] Interop: browse RoleSet from a reference client (node-opcua / .NET / open62541) without error (Spec: SC-002; Part 18 §4.5)
- [ ] T103 [P] Add an example/doc snippet for RBAC config in the demo-server or docs (quickstart.md mirror) (Spec: FR-012)
- [ ] T104 [P] Security review of the enforcement path: fail-closed where enforced, no panic on attacker input, no secret leakage (Spec: Constitution IV)
- [ ] T105 [P] Confirm `Bad_UserAccessDenied`/`Bad_SecurityModeInsufficient` are returned per-operation (not whole-request) where the spec requires operation-level results (Spec: Part 4 §7.39; per-service result tables)
- [ ] T106 Update `specs/SESSION-HANDOFF.md` + memory with the RBAC feature outcome (Spec: project process)

---

## Dependencies & Execution Order

- **Setup (Phase 1)** → no deps.
- **Foundational (Phase 2)** → after Setup; **BLOCKS all user stories** (Base fields, RequestContext role set,
  `authorize`, EffectiveNodePermissions).
- **US1 (Phase 3)** → after Foundational. MVP.
- **US2 (Phase 4)** → after Foundational (role resolution); US1 independent of US2 but US3 needs both.
- **US3 (Phase 5)** → after US1 + US2 (needs attributes + resolved roles + `authorize`).
- **US4 (Phase 6)** → after US3 (extends enforcement; adds AccessRestrictions + Browse).
- **US5 (Phase 7)** → after US3 (extends to history/node-mgmt/events).
- **US6 (Phase 8)** → after US3 (default fallback in EffectiveNodePermissions).
- **US7 (Phase 9)** → after US2 (RoleSet) + US3 (gating).
- **US8 (Phase 10)** → after all (config to drive everything).
- **Polish (Phase 11)** → last.

### Parallel opportunities

- Within each story, all `[P]` test tasks can be authored in parallel before/with implementation.
- T002/T003/T004 (Setup) are parallel. T007 (builders) parallel to T005/T006. US1 and US2 implementation can
  proceed largely in parallel after Foundational (different files), converging at US3.

## Implementation strategy

- **MVP** = Phase 1 + Phase 2 + **US1** (introspectable permission attributes). Then **US2 + US3** deliver the
  core enforcement (the real security value). US4–US6 broaden enforcement; US7–US8 add runtime mgmt + config.
- Ship per user story (one PR per story, commit per story — see memory `commit-at-end-of-user-story`), each a
  complete, independently-testable increment behind the permissive-default (no regressions until configured).
- Codex implements one task at a time WITH its cited spec section looked up via the OPC UA reference MCP;
  Claude authors the independent tests (memory `codex-no-self-authored-tests`, `one-task-per-codex-dispatch`).

## Total

106 tasks (Setup 4, Foundational 8, US1 9, US2 13, US3 15, US4 10, US5 10, US6 8, US7 11, US8 10, Polish 8).
