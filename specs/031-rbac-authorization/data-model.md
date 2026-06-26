# Data Model: RBAC / Authorization

Entities mapped to concrete async-opcua types. Generated types are reused as-is; new types are introduced in
`async-opcua-server/src/authorization/`.

## Permission (PermissionType) — generated, reuse

- `opcua_types::PermissionType` bitmask (Part 3 §8.55). 17 bits: Browse, ReadRolePermissions, WriteAttribute,
  WriteRolePermissions, WriteHistorizing, Read, Write, ReadHistory, InsertHistory, ModifyHistory,
  DeleteHistory, ReceiveEvents, Call, AddReference, RemoveReference, DeleteNode, AddNode.
- Helper: a service→required-bit mapping (Part 3 §4.8.2 usage table). E.g. Read service → `Read`; Write Value
  → `Write`; Write RolePermissions attr → `WriteRolePermissions`; Call → `Call`; Browse → `Browse`;
  HistoryRead → `ReadHistory`; HistoryUpdate insert/replace → `InsertHistory`, update → `ModifyHistory`,
  delete → `DeleteHistory`; AddNodes → `AddNode`; DeleteNodes → `DeleteNode`; AddReferences → `AddReference`;
  DeleteReferences → `RemoveReference`; monitored-event delivery → `ReceiveEvents`.

## RolePermission (RolePermissionType) — generated, reuse

- `opcua_types::RolePermissionType { role_id: NodeId, permissions: PermissionType }`.
- A node's RolePermissions = `Vec<RolePermissionType>` (the per-role permission grants for that node).

## NodePermissions (NEW — on Base)

- New optional fields on `async-opcua-nodes::Base`:
  - `role_permissions: Option<Vec<RolePermissionType>>` (attribute 24)
  - `access_restrictions: Option<AccessRestrictionType>` (attribute 26)
- UserRolePermissions (attribute 25) is COMPUTED, not stored: the subset of `role_permissions` whose `role_id`
  is in the session's resolved role set (entries merged/unioned across the session roles).
- `get_attribute` (Base) returns these for 24/25/26; 25 requires the request context's role set, so it is
  computed in the address-space read path (like UserAccessLevel/UserExecutable today), not in Base alone.

## AccessRestriction (AccessRestrictionType) — generated, reuse

- `opcua_types::AccessRestrictionType` bitmask: SigningRequired(1), EncryptionRequired(2), SessionRequired(4),
  ApplyRestrictionsToBrowse(8) (Part 3 §8.56). Stored per-node (attr 26) and per-namespace default.

## Role (runtime) (NEW)

- `RoleId = NodeId` — well-known roles use the standard ns0 NodeIds (`WellKnownRole_*`), custom roles get
  server-assigned NodeIds in a server namespace.
- Runtime `Role { id: NodeId, identities: Vec<IdentityMappingRule>, applications: ApplicationFilter,
  endpoints: EndpointFilter }` — mirrors RoleType (Part 18 §4.4.1). The 8 well-known roles are seeded;
  Applications/Endpoints are include/exclude lists (RoleType ApplicationsExclude/EndpointsExclude flags).

## IdentityMappingRule (IdentityMappingRuleType) — generated type + runtime criteria (NEW)

- `opcua_types::IdentityMappingRuleType { criteria_type: IdentityCriteriaType, criteria: ExtensionObject/String }`.
- Runtime criteria enum (Part 18 §4.4.2/§4.4.3): AnonymousIdentity, AuthenticatedUser, UserName(name),
  Thumbprint(certThumbprint), Role(roleId), GroupId(issuedTokenGroup), Application(appUri). Evaluated against
  the activated session at resolve time.

## SessionRoleSet (NEW — session state)

- `Arc<Vec<NodeId>>` of granted role NodeIds, resolved once at activation, cached on the Session and exposed
  via `RequestContext`. The union basis for every authorization decision.

## NamespaceDefaults (NEW)

- Per-namespace `{ default_role_permissions: Option<Vec<RolePermissionType>>,
  default_user_role_permissions: ..., default_access_restrictions: Option<AccessRestrictionType> }`, consulted
  when a node lacks an explicit value; exposed via the namespace's NamespaceMetadata (Part 5 §6). Node-level
  values override.

## AuthorizationConfig (NEW — config surface)

- `ServerUserToken.roles: Vec<NodeId>` (assign roles to a configured user/cert/issued-token).
- `ServerConfig`/builder: identity-mapping rules, per-namespace defaults, and an `enforce_role_based_access`
  posture flag (in `Limits` alongside `clients_can_modify_address_space`), plus a secure-preset constructor.

## Relationships

```
Session --(resolved at activate)--> SessionRoleSet (Vec<RoleId>)
Role <--(granted via)-- IdentityMappingRule (criteria match)  [Applications/Endpoints filter]
Node --(has)--> RolePermissions (Vec<RolePermissionType>)  --falls back to--> NamespaceDefaults
Node --(has)--> AccessRestrictions (AccessRestrictionType)  --falls back to--> NamespaceDefaults
authorize(SessionRoleSet, Node.effectiveRolePermissions, requiredPermission) -> allow|deny
AccessRestrictions x ChannelSecurityMode -> ok | Bad_SecurityModeInsufficient
```

## Validation / invariants

- UserRolePermissions ⊆ RolePermissions for the session's roles (computed, never stored).
- Multiple roles → union of permissions (FR-015).
- "No RolePermissions configured anywhere" ⇒ permissive (D5); "RolePermissions present but excludes my roles"
  ⇒ deny.
- Node-level value strictly overrides namespace default.
- Reading/writing RolePermissions attr governed by ReadRolePermissions/WriteRolePermissions (FR-014).
