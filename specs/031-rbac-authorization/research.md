# Research: RBAC / Authorization Model

Phase 0 decisions. All resolved (no open NEEDS CLARIFICATION).

## D1 — Node attribute ids are 24/25/26 (spec correction)

- **Decision**: Use AttributeId RolePermissions=**24**, UserRolePermissions=**25**, AccessRestrictions=**26**.
- **Rationale**: These are the real OPC UA attribute ids (Part 6 attribute table; Part 3 §5.2). The spec.md
  parenthetical "(16)/(17)/(18)" is WRONG — 16/17/18 are ArrayDimensions/AccessLevel/UserAccessLevel. The
  `AttributeId` enum in `async-opcua-types/src/attribute.rs` already defines 24/25/26 and parses them.
- **Alternatives**: none — the ids are fixed by the spec.

## D2 — Reuse the already-generated DataTypes

- **Decision**: Reuse `RolePermissionType`, `PermissionType` (bitmask), `AccessRestrictionType` (bitmask),
  `IdentityMappingRuleType`, `IdentityCriteriaType` from `async-opcua-types/src/generated/types/`.
- **Rationale**: They are already generated (encode/decode complete). No codegen change needed for the data
  model; do not hand-roll parallel types (Constitution II).
- **Alternatives**: hand-written model types — rejected (duplication, drift).

## D3 — Where the resolved session role set lives

- **Decision**: Resolve the role set ONCE at session activation and cache it (Arc<Vec<NodeId>> of role
  NodeIds) on the Session, surfaced to every service via `RequestContext` (a getter/field on
  `RequestContextInner`).
- **Rationale**: Role resolution depends on identity + application URI + endpoint, all known at activate.
  Caching avoids re-evaluating mapping rules per request; `RequestContext` is already the universal handle
  every node manager/service receives. Keeps enforcement O(roles) per check with no per-request resolution.
- **Alternatives**: (a) recompute per request — rejected (cost + the identity is fixed for the session);
  (b) store only in the authenticator and look up by token each call — rejected (extra indirection; the
  resolved set is session state). The authenticator REMAINS the source of mapping rules; the *resolved* set
  is session state.

## D4 — Central authorization decision point

- **Decision**: One function `authorize(context, node, required: PermissionType) -> bool` in a new
  `async-opcua-server/src/authorization/` module, consulted by every enforcement site. It: (1) collects the
  node's effective RolePermissions (node-level, else per-namespace default, else "unconfigured"); (2) if
  unconfigured and the global enforce posture is off → permit (backwards-compat); (3) else union the
  permissions of the session's roles and test the required bit.
- **Rationale**: Constitution II (one decision path, no per-service divergence). Folds into the existing
  `is_readable`/`user_access_level`/`validate_write_access`/`is_user_executable` computations rather than
  duplicating.
- **Alternatives**: per-service inline checks — rejected (drift, inconsistent deny semantics).

## D5 — Backwards-compatible default (permissive when unconfigured)

- **Decision**: A node with no RolePermissions AND no applicable namespace default is NOT role-restricted
  (governed only by AccessLevel/Executable as today). Enforcement applies only where RolePermissions/namespace
  defaults exist, OR a global `enforce_role_based_access` posture is selected. Where enforcement applies, it is
  fail-closed (missing bit ⇒ Bad_UserAccessDenied).
- **Rationale**: SC-007 (zero regression unconfigured) + matches the OPC UA model. Distinct from "node HAS a
  RolePermissions list that excludes my roles" → that DENIES. The distinction is "no list at all" vs "a list
  without my roles".
- **Alternatives**: deny-by-default globally — rejected as a *default* (breaks every existing deployment);
  offered instead as the opt-in secure preset (FR-017).

## D6 — Identity → role resolution rules

- **Decision**: Evaluate `IdentityMappingRule`s (criteria: AnonymousIdentity, AuthenticatedUser, UserName,
  Thumbprint, Role, GroupId, Application) against the activated session's identity token, certificate
  thumbprint, issued-token groups, application URI, and endpoint. A session is granted every role whose
  Identities (subject to Applications/Endpoints include/exclude) match. Anonymous sessions get Anonymous only
  (not AuthenticatedUser); any successful non-anonymous authentication implies AuthenticatedUser.
- **Rationale**: Part 18 §4.4 (RoleType Identities/Applications/Endpoints) + Part 3 §4.9.2 semantics. Config
  order used where Part 18 leaves ordering server-defined.
- **Alternatives**: username-only mapping — rejected (incomplete vs spec criteria set).

## D7 — RoleSet model already in the nodeset; management methods via the core node manager

- **Decision**: The `RoleSet` object + the 8 well-known RoleType instances are already loaded from
  `async-opcua-core-namespace` (nodeset_16). Wire the RoleSet/RoleType management Methods (AddRole/RemoveRole/
  Add/Remove Identity/Application/Endpoint) as callbacks on the core node manager — the SAME pattern as the
  writable PubSub config methods (register against the type/instance Method node ids, resolve the target from
  object_id), gated to SecurityAdmin.
- **Rationale**: Reuse the proven method-registration pattern; don't re-instantiate the nodeset. Custom roles
  added at runtime are reflected as new RoleType instances under RoleSet.
- **Alternatives**: a separate node manager for RoleSet — rejected (the nodes are ns0, owned by the core NM).

## D8 — AccessRestrictions enforcement against the channel

- **Decision**: AccessRestrictions (SigningRequired/EncryptionRequired/SessionRequired) are checked against
  the SecureChannel security mode (None/Sign/SignAndEncrypt) and session presence; failure ⇒
  `Bad_SecurityModeInsufficient` (or node omitted from Browse when ApplyRestrictionsToBrowse). These are
  independent of (and ANDed with) the RolePermission check.
- **Rationale**: Part 3 §8.56. The channel security mode is already on the RequestContext/session path.
- **Alternatives**: ignore AccessRestrictions — rejected (spec requirement FR-008).

## D9 — Build matrix / no new deps

- **Decision**: No new external dependency. The module builds under `--no-default-features` and
  `--all-features`. Enforcement gates are feature-independent (operate on generated types always present).
- **Rationale**: Constitution + the project's build-matrix CI legs (json-off / no-default).
- **Alternatives**: n/a.
