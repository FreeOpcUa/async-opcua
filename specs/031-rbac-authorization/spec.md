# Feature Specification: Role-Based Access Control / Authorization Model

**Feature Branch**: `031-rbac-authorization`
**Created**: 2026-06-26
**Status**: Draft
**Input**: Full node-level OPC UA authorization subsystem — OPC UA Part 3 §4.8–4.9 + §8.55 (PermissionType),
Part 5 (RoleSet/RoleType/IdentityMappingRuleType), Part 18 (Role-Based Security). Build the complete
role-based access control surface for `async-opcua-server`, superseding the coarse server-wide
`CoreServerPermissions` model with the standard node-level RolePermissions model. Backwards compatible:
servers with no role configuration keep their current behaviour (permissive, opt-in enforcement).

## Context & Scope

OPC UA defines a node-level authorization model: every Node may carry `RolePermissions` (the permissions
each Role has on the Node) and `AccessRestrictions` (security-mode/session requirements); a Session is
granted a set of Roles by mapping its identity (anonymous / username / certificate / issued token, plus
application URI and endpoint) through configured `IdentityMappingRule`s; and Services enforce the relevant
`PermissionType` bit before acting on a Node. The server exposes the role configuration as a browsable
`RoleSet` information model with the eight standard well-known Roles and management Methods.

Today async-opcua has only a coarse, server-wide permission check (`CoreServerPermissions`) and exposes
`UserAccessLevel`/`UserExecutable` from the authenticator. This feature builds the standard model and
wires enforcement into the service path, while preserving backwards compatibility: when no roles /
RolePermissions are configured, access is unchanged (permissive), and enforcement is opt-in.

This is a complete reference implementation: build the full spec surface; do not YAGNI-defer.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Permission model & readable permission attributes (Priority: P1)

An operator configures permissions on nodes, and a client can read the `RolePermissions`,
`UserRolePermissions`, and `AccessRestrictions` attributes of any node. The server returns the configured
`RolePermissions`/`AccessRestrictions`, and computes `UserRolePermissions` as the subset of permissions
that apply to the roles granted to the calling Session.

**Why this priority**: It is the data foundation every other story builds on — the `PermissionType`
bitmask, `RolePermissionType`, and the three node attributes (24/25/26) — and is independently valuable
(clients can introspect permissions) and independently testable.

**Independent Test**: Configure a node with RolePermissions for two roles; read attributes 24/25/26 over a
session; verify RolePermissions returns the full set, AccessRestrictions returns the configured value, and
UserRolePermissions returns only the entries for the session's granted roles.

**Acceptance Scenarios**:

1. **Given** a node with configured RolePermissions, **When** a client reads the RolePermissions attribute,
   **Then** it receives the full list of (roleId, permissions) entries.
2. **Given** a session granted role R, **When** the client reads UserRolePermissions of a node whose
   RolePermissions list includes R and other roles, **Then** only the entry for R (merged across the
   session's roles) is returned.
3. **Given** a node with no configured RolePermissions, **When** the attributes are read, **Then** the
   server returns the applicable per-namespace default (or a null/empty value when none is configured),
   without error.
4. **Given** a node with AccessRestrictions configured, **When** the AccessRestrictions attribute is read,
   **Then** the configured bitmask (SigningRequired/EncryptionRequired/SessionRequired/
   ApplyRestrictionsToBrowse) is returned.

### User Story 2 - Identity-to-role resolution, RoleSet & well-known roles (Priority: P1)

The server grants each activated Session a set of Roles by evaluating configured identity-mapping rules
against the session's identity (anonymous / username / certificate thumbprint / issued-token group),
application URI, and endpoint. The eight well-known Roles and the `RoleSet` object are present and
browsable under `Server.ServerCapabilities.RoleSet`.

**Why this priority**: Without role resolution there is nothing to enforce against, and the RoleSet model
is mandated by the spec. Independently valuable (clients can browse roles and the server attributes the
correct roles) and testable via the resolved role set on a session.

**Independent Test**: Configure identity-mapping rules (e.g. username "alice" → Operator, anonymous →
Anonymous); connect with each identity; verify the granted role set; browse `Server.ServerCapabilities.
RoleSet` and confirm the eight well-known RoleType instances with their Identities/Applications/Endpoints
components.

**Acceptance Scenarios**:

1. **Given** an identity-mapping rule mapping username "alice" to Operator, **When** alice activates a
   session, **Then** the session is granted the Operator role (plus AuthenticatedUser).
2. **Given** an anonymous session, **When** it is activated, **Then** it is granted exactly the Anonymous
   role (and not AuthenticatedUser).
3. **Given** a session authenticated with a certificate whose thumbprint matches a Thumbprint mapping rule
   for SecurityAdmin, **When** activated, **Then** it is granted SecurityAdmin.
4. **Given** the default server, **When** a client browses `Server.ServerCapabilities.RoleSet`, **Then** it
   finds the eight well-known RoleType instances (Anonymous, AuthenticatedUser, Observer, Operator,
   Engineer, Supervisor, ConfigureAdmin, SecurityAdmin) with the standard NodeIds and components.

### User Story 3 - Read / Write / Call enforcement (Priority: P1)

The server enforces the Read, Write, and Call permissions per node against the calling session's roles.
A session lacking the required permission on a node is denied with `Bad_UserAccessDenied`. The
`UserAccessLevel` and `UserExecutable` attributes reflect the resolved roles. When a node has no configured
RolePermissions (and no applicable default), behaviour is unchanged (permissive) — enforcement is opt-in.

**Why this priority**: This is the core security value — actually restricting Read/Write/Call by role —
and the most-used services. Independently testable end-to-end via Read/Write/Call against permissioned
nodes.

**Independent Test**: Configure a variable granting Read to Observer and Write to Operator; connect as
Observer and as Operator; verify Observer can read but not write (Bad_UserAccessDenied) and Operator can
both; verify a method granting Call only to Engineer rejects others.

**Acceptance Scenarios**:

1. **Given** a variable whose RolePermissions grant Write only to Operator, **When** an Observer session
   writes the Value, **Then** the write is rejected with Bad_UserAccessDenied and the value is unchanged.
2. **Given** the same variable, **When** an Operator session writes the Value, **Then** the write succeeds.
3. **Given** a variable granting Read only to Operator, **When** an Observer reads the Value, **Then** Read
   is denied (Bad_UserAccessDenied) per the Read permission.
4. **Given** a method whose RolePermissions grant Call only to Engineer, **When** a non-Engineer calls it,
   **Then** the call is rejected with Bad_UserAccessDenied; **When** an Engineer calls it, it succeeds.
5. **Given** a node with no RolePermissions configured anywhere (no default), **When** any session accesses
   it, **Then** access is permitted (backwards-compatible permissive behaviour).
6. **Given** a permissioned variable, **When** UserAccessLevel is read by a session, **Then** the
   CurrentRead/CurrentWrite bits reflect the session's effective Read/Write permission.

### User Story 4 - Browse permission & AccessRestrictions enforcement (Priority: P2)

The server enforces the Browse permission (nodes/references the session may not Browse are omitted from
Browse results) and AccessRestrictions: SessionRequired, SigningRequired, and EncryptionRequired are
checked against the channel's security mode and the session, returning `Bad_SecurityModeInsufficient`
(or omitting/denying) as appropriate, including the ApplyRestrictionsToBrowse behaviour.

**Why this priority**: Browse-result filtering and channel-security requirements are important but secondary
to the core CRUD enforcement, and depend on US1–US3.

**Independent Test**: Configure a node with Browse granted only to Operator and AccessRestrictions
EncryptionRequired; Browse as a non-Operator and confirm the node is filtered out; access a node requiring
EncryptionRequired over a Sign-only channel and confirm Bad_SecurityModeInsufficient.

**Acceptance Scenarios**:

1. **Given** a node whose RolePermissions deny Browse to the session's roles, **When** the session browses
   its parent, **Then** that node/reference is omitted from the Browse result.
2. **Given** a node with AccessRestrictions EncryptionRequired, **When** it is accessed over a channel that
   is not encrypted, **Then** the access is rejected with Bad_SecurityModeInsufficient.
3. **Given** a node with AccessRestrictions SessionRequired, **When** it is accessed without an active
   session (session-less service), **Then** the access is denied.
4. **Given** AccessRestrictions with ApplyRestrictionsToBrowse set, **When** the security requirements are
   unmet, **Then** the restriction is also applied to Browse (node filtered), not only to Read/Write.

### User Story 5 - History & node-management enforcement (Priority: P2)

The server enforces ReadHistory / InsertHistory / ModifyHistory / DeleteHistory on the HistoryRead and
HistoryUpdate services, AddNode / DeleteNode / AddReference / RemoveReference on the NodeManagement
services, and ReceiveEvents on event/notification delivery, each against the session's roles.

**Why this priority**: Extends enforcement to the remaining permissioned services; depends on US1–US3 and
the existing history/node-management/subscription paths.

**Independent Test**: Configure ReadHistory for Observer and DeleteHistory for Engineer on a historizing
variable; verify HistoryRead allowed/denied accordingly and HistoryUpdate delete allowed/denied; configure
AddReference denied and verify AddReferences is rejected; configure ReceiveEvents denied on an event source
and verify the session receives no events from it.

**Acceptance Scenarios**:

1. **Given** a variable granting ReadHistory only to Observer, **When** a non-Observer issues HistoryRead,
   **Then** it is denied with Bad_UserAccessDenied.
2. **Given** a node granting DeleteHistory only to Engineer, **When** a non-Engineer issues a
   HistoryUpdate delete, **Then** it is denied; an Engineer succeeds.
3. **Given** a target node whose RolePermissions deny AddReference to the session, **When** AddReferences is
   called, **Then** it is rejected with Bad_UserAccessDenied.
4. **Given** an event-source node whose RolePermissions deny ReceiveEvents to the session's roles, **When**
   the session monitors the source for events, **Then** events from that source are not delivered to it.

### User Story 6 - Per-namespace default permissions (Priority: P2)

When a Node has no explicit RolePermissions / AccessRestrictions, the server applies the per-namespace
`DefaultRolePermissions` / `DefaultUserRolePermissions` / `DefaultAccessRestrictions`, exposed on the
NamespaceMetadata for each namespace. Node-level values always take precedence over namespace defaults.

**Why this priority**: Reduces configuration burden and matches the spec's namespace-default mechanism;
depends on US1 (model) and US3 (enforcement) being in place.

**Independent Test**: Set DefaultRolePermissions for a namespace granting Read to AuthenticatedUser only;
verify a node in that namespace with no explicit RolePermissions is governed by the default (anonymous
denied Read); add explicit RolePermissions to one node and verify the override wins.

**Acceptance Scenarios**:

1. **Given** a namespace with DefaultRolePermissions granting Read only to AuthenticatedUser, **When** an
   anonymous session reads a node in that namespace with no explicit RolePermissions, **Then** Read is
   denied.
2. **Given** the same namespace, **When** a node carries explicit RolePermissions that grant Read to
   Anonymous, **Then** the node-level permission overrides the namespace default (anonymous read allowed).
3. **Given** a namespace's DefaultRolePermissions readable via NamespaceMetadata, **When** a client reads
   it, **Then** the configured defaults are returned.

### User Story 7 - Runtime role management methods (Priority: P3)

A suitably privileged client (SecurityAdmin) can manage roles at runtime via the standard Methods:
`AddRole`/`RemoveRole` on the RoleSet, and `AddIdentity`/`RemoveIdentity`/`AddApplication`/
`RemoveApplication`/`AddEndpoint`/`RemoveEndpoint` on a RoleType instance. Changes take effect for new
sessions and are reflected in the RoleSet information model.

**Why this priority**: Runtime mutability is valuable but optional relative to static configuration; depends
on US2 (RoleSet model) + US3 (enforcement, to gate the Methods).

**Independent Test**: As SecurityAdmin, call AddRole to create a custom role, AddIdentity to map a username
to it, and verify a session with that username is granted the new role; as a non-SecurityAdmin, verify the
management Methods are rejected.

**Acceptance Scenarios**:

1. **Given** a SecurityAdmin session, **When** it calls RoleSet.AddRole with a name and namespace, **Then** a
   new RoleType instance appears under RoleSet and AddRole returns its NodeId.
2. **Given** a new role and a SecurityAdmin session, **When** it calls AddIdentity with a UserName rule,
   **Then** a subsequent session with that username is granted the new role.
3. **Given** a non-SecurityAdmin session, **When** it calls any RoleSet/RoleType management Method, **Then**
   the call is rejected with Bad_UserAccessDenied.
4. **Given** a custom role with an identity mapping, **When** RemoveIdentity (or RemoveRole) is called,
   **Then** new sessions are no longer granted via that mapping (or the role is gone).

### User Story 8 - Configuration API & secure defaults (Priority: P3)

A server author can declare roles, identity-mapping rules, and default permissions through the server
configuration/builder surface, and choose an enforcement posture. Defaults are backwards-compatible: with
no role configuration, the server behaves exactly as before (permissive); enforcement is opt-in, and a
documented secure preset is available.

**Why this priority**: Ergonomics and safe rollout; depends on all prior stories being in place to
configure.

**Independent Test**: Build a server with no role config and verify all existing behaviour/tests are
unchanged; build a server declaring roles + mappings + a default-deny preset and verify enforcement is
active.

**Acceptance Scenarios**:

1. **Given** a server built with no role configuration, **When** clients access nodes, **Then** behaviour is
   identical to the pre-feature server (permissive; existing tests pass unchanged).
2. **Given** a server configured with roles, identity mappings, and namespace defaults, **When** it starts,
   **Then** the RoleSet model and the configured permissions are active and enforced.
3. **Given** the documented secure preset, **When** applied, **Then** anonymous access is restricted per the
   well-known-role suggested permissions (Part 3 §4.9.2) without further per-node configuration.

### Edge Cases

- A session granted multiple roles receives the **union** of their permissions (a permission allowed by any
  granted role is allowed).
- A node's RolePermissions list that does not mention a session's roles at all → that session has **no**
  permissions on the node (deny), once enforcement applies to that node.
- Reading/writing the RolePermissions attribute itself is governed by the ReadRolePermissions /
  WriteRolePermissions permissions (not the ordinary Read/Write).
- Distinction between "node has no RolePermissions configured anywhere" (permissive, backwards-compatible)
  and "node has a RolePermissions list that excludes my roles" (deny).
- AccessRestrictions interaction with session-less services and with Browse (ApplyRestrictionsToBrowse).
- Well-known Role NodeIds and the RoleSet object must use the standard namespace-0 identifiers so external
  clients interoperate.
- Backwards compatibility under both `--no-default-features` and `--all-features` builds.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST model the `PermissionType` bitmask with all 17 bits (Browse,
  ReadRolePermissions, WriteAttribute, WriteRolePermissions, WriteHistorizing, Read, Write, ReadHistory,
  InsertHistory, ModifyHistory, DeleteHistory, ReceiveEvents, Call, AddReference, RemoveReference,
  DeleteNode, AddNode) and the `RolePermissionType` (roleId + permissions).
- **FR-002**: The system MUST expose the `RolePermissions` (24), `UserRolePermissions` (25), and
  `AccessRestrictions` (26) node attributes for read, returning configured values and computing
  UserRolePermissions as the per-session-role subset.
- **FR-003**: The system MUST grant each activated Session a set of Roles by evaluating configured
  identity-mapping rules against the session identity (anonymous / username / certificate thumbprint /
  issued-token group), application URI, and endpoint, per IdentityMappingRuleType criteria types.
- **FR-004**: The system MUST provide the `RoleSet` object under `Server.ServerCapabilities.RoleSet` and the
  eight well-known RoleType instances with the standard NodeIds and their Identities/Applications/Endpoints
  components.
- **FR-005**: The system MUST enforce Read, Write, and Call permissions per node against the session's roles
  on the Read, Write, and Call services, denying with Bad_UserAccessDenied when the required permission is
  absent.
- **FR-006**: The system MUST reflect the session's effective permissions in the UserAccessLevel and
  UserExecutable attributes.
- **FR-007**: The system MUST enforce the Browse permission by omitting nodes/references the session may not
  Browse from Browse results.
- **FR-008**: The system MUST enforce AccessRestrictions (SigningRequired, EncryptionRequired,
  SessionRequired, ApplyRestrictionsToBrowse) against the channel security mode and session, denying with
  Bad_SecurityModeInsufficient where the channel is insufficient.
- **FR-009**: The system MUST enforce ReadHistory/InsertHistory/ModifyHistory/DeleteHistory on
  HistoryRead/HistoryUpdate, AddNode/DeleteNode/AddReference/RemoveReference on the NodeManagement services,
  and ReceiveEvents on event delivery.
- **FR-010**: The system MUST apply per-namespace DefaultRolePermissions/DefaultUserRolePermissions/
  DefaultAccessRestrictions when a node has no explicit value, with node-level values taking precedence, and
  expose these defaults via NamespaceMetadata.
- **FR-011**: The system MUST provide the runtime role-management Methods (RoleSet AddRole/RemoveRole;
  RoleType AddIdentity/RemoveIdentity/AddApplication/RemoveApplication/AddEndpoint/RemoveEndpoint), gated so
  that only SecurityAdmin (or equivalently privileged) sessions may invoke them.
- **FR-012**: The system MUST provide a server-configuration/builder API to declare roles, identity-mapping
  rules, and default permissions, and to select the enforcement posture.
- **FR-013**: The system MUST remain backwards compatible: with no role configuration, access behaviour is
  unchanged (permissive) and enforcement is opt-in; a node with no RolePermissions configured anywhere is
  not restricted.
- **FR-014**: Governing the RolePermissions attribute itself MUST use the ReadRolePermissions /
  WriteRolePermissions permissions rather than ordinary Read/Write.
- **FR-015**: A session with multiple roles MUST receive the union of their permissions.
- **FR-016**: The system MUST build and pass tests under both `--no-default-features` and `--all-features`,
  and MUST NOT regress existing service behaviour or tests when no roles are configured.
- **FR-017**: The system SHOULD provide a documented secure preset implementing the Part 3 §4.9.2
  well-known-role suggested permissions out of the box.

### Key Entities

- **Permission (PermissionType)**: the 17-bit set of operations a role may perform on a node.
- **RolePermission (RolePermissionType)**: an association of a roleId (NodeId) with a PermissionType set.
- **Role (RoleType instance)**: a named principal grouping with Identities (mapping rules), Applications,
  and Endpoints; the eight well-known roles plus any custom roles.
- **IdentityMappingRule**: a criterion (AnonymousIdentity / AuthenticatedUser / UserName / Thumbprint /
  Role / GroupId / Application) plus its value, used to grant a role to matching sessions.
- **AccessRestriction (AccessRestrictionType)**: per-node security requirements
  (SigningRequired/EncryptionRequired/SessionRequired/ApplyRestrictionsToBrowse).
- **NamespaceMetadata defaults**: DefaultRolePermissions/DefaultUserRolePermissions/DefaultAccessRestrictions
  for a namespace.
- **Session role set**: the resolved set of Roles granted to an activated session, used for all enforcement.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A client can read the RolePermissions, UserRolePermissions, and AccessRestrictions attributes
  of any node and receives correct, role-aware values (UserRolePermissions reflects only the session's
  granted roles).
- **SC-002**: All eight well-known roles and the RoleSet object are browsable at their standard NodeIds and
  interoperate with an external reference client (node-opcua / .NET / open62541) without error.
- **SC-003**: With permissions configured, Read/Write/Call/Browse/HistoryRead/HistoryUpdate/NodeManagement/
  event delivery are correctly allowed or denied (Bad_UserAccessDenied / Bad_SecurityModeInsufficient) for
  100% of the acceptance scenarios across all enforced services.
- **SC-004**: A session granted multiple roles receives the union of their permissions in every enforced
  service.
- **SC-005**: Per-namespace defaults govern nodes without explicit permissions, and node-level permissions
  always override namespace defaults.
- **SC-006**: A SecurityAdmin can create a role, map an identity to it, and observe a new session being
  granted that role; non-SecurityAdmin sessions cannot invoke the management Methods.
- **SC-007**: With no role configuration, the full existing server test suite passes unchanged (zero
  regressions) under both `--no-default-features` and `--all-features`; enforcement is strictly opt-in.

## Spec Traceability (OPC UA reference sections)

Every task derived from this spec MUST cite the relevant section(s) below so the implementer can look
them up via the OPC UA reference MCP. Sections are from the OPC 10000 series (Part N = OPC-10000-N).

| Area | Reference section(s) |
| --- | --- |
| Role-based security model; identity → roles | Part 18 §4 (RoleManagement); Part 3 §4.8 (Security model), §4.9 (Roles) |
| Well-known Roles (8) + suggested permissions | Part 3 §4.9.2 (Well-Known Roles) |
| `PermissionType` bitmask (17 bits) + `RolePermissionType` | Part 3 §8.55 (PermissionType); Part 5 (RolePermissionType DataType) |
| `AccessRestrictionType` (Signing/Encryption/Session/ApplyToBrowse) | Part 3 §8.56 (AccessRestrictionType) |
| RolePermissions (24) / UserRolePermissions (25) / AccessRestrictions (26) attributes | Part 3 §5.2 (Base NodeClass attributes); Part 4 §6 (Attribute ids); Part 3 §5.9.x |
| Per-namespace defaults (Default*Permissions / NamespaceMetadata) | Part 5 §6 (NamespaceMetadataType / NamespacesType) |
| `RoleSetType`, `RoleType` (i=15620), components | Part 18 §4.4.1 (RoleType), §4.5 (RoleSetType); Part 5 (ServerCapabilities.RoleSet) |
| `IdentityMappingRuleType` (i=15634) + criteria types | Part 18 §4.4.3 (IdentityMappingRuleType); Part 18 §4.4.2 (IdentityCriteriaType) |
| RoleType Methods (AddIdentity/RemoveIdentity/AddApplication/RemoveApplication/AddEndpoint/RemoveEndpoint) | Part 18 §4.4.1 / §4.8 (Role Methods) |
| RoleSet Methods (AddRole/RemoveRole) | Part 18 §4.6 (RoleSetType Methods) |
| Service permission enforcement (which PermissionType per service) | Part 3 §4.8.2 (PermissionType usage table); Part 4 §5 (per-service: Read/Write/Call/Browse/HistoryRead/HistoryUpdate/AddNodes/AddReferences/DeleteNodes/DeleteReferences) |
| AccessRestrictions enforcement vs SecureChannel / SessionlessInvoke | Part 3 §8.56; Part 4 §5.4 (SecureChannel), §5.10 (sessionless) |
| Status codes (Bad_UserAccessDenied / Bad_SecurityModeInsufficient) | Part 4 §7.39 (StatusCodes); Part 3 §4.8 |

## Assumptions

- The standard well-known Role NodeIds, RoleSetType/RoleType/IdentityMappingRuleType definitions, the three
  node attributes (24/25/26), the PermissionType/AccessRestrictionType bit definitions, and the management
  Method NodeIds are available in the generated namespace-0 type set (Part 3/5/18); where a generated type
  or attribute id is missing it will be added as part of the build.
- "Permissive when unconfigured" means: a node with no RolePermissions (and no applicable namespace default)
  is not access-restricted — preserving today's behaviour. Enforcement applies only where RolePermissions or
  a namespace default exist, or where a global enforce-by-default posture is selected.
- The existing authenticator (`UserToken`, `is_user_executable`, `CoreServerPermissions`) is the integration
  point for identity and is superseded for node-level decisions by the resolved session role set; the coarse
  server-wide checks may be re-expressed in terms of roles but their external behaviour is preserved by
  default.
- Identity-mapping evaluation order and precedence follow Part 18; where the spec leaves ordering to the
  server, configuration order is used.
- Enforcement integrates at the node-manager / service boundary already used for UserAccessLevel /
  UserExecutable and the existing permission checks.

## Out of Scope

- A Global Discovery Server (GDS)-based central authorization service or the full Part-12 push of role
  configuration (the local RoleSet model + management Methods are in scope; GDS distribution is not).
- External authorization servers / OAuth scopes mapping beyond the existing issued-token identity (issued
  tokens are mapped to roles via GroupId rules, but no new token-service infrastructure is built).
- Encryption/transport changes — AccessRestrictions are enforced against the existing channel security mode;
  no new security policies or transports are added.
