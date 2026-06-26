# Contracts: RBAC / Authorization public surfaces

The interfaces this feature exposes. Signatures are indicative (final names settled in implementation), but
the contracts (inputs/outputs/semantics) are binding.

## 1. Central authorization decision

```rust
// async-opcua-server/src/authorization/mod.rs
/// True iff the session (via `context`) holds `required` on `node`, OR the node is unconfigured and the
/// global enforce posture is off (backwards-compatible permissive). Fail-closed where enforcement applies.
pub(crate) fn authorize(
    context: &RequestContext,
    node: &NodeType,           // or node_id + effective RolePermissions accessor
    required: PermissionType,
) -> bool;
```

- **Semantics**: effective RolePermissions = node-level `role_permissions`, else per-namespace default, else
  `unconfigured`. If `unconfigured` and `!enforce_role_based_access` → `true`. Otherwise → the union of the
  permissions for the session's roles contains `required`.
- A denied decision causes the caller to return `Bad_UserAccessDenied` for that operation/node.

## 2. Session role resolution

```rust
// async-opcua-server/src/authorization/resolver.rs
pub struct RoleResolver { /* mapping rules, well-known roles */ }
impl RoleResolver {
    /// Resolve the granted roles for an activated session identity.
    pub fn resolve(
        &self,
        identity: &ResolvedIdentity,  // anonymous|username|x509-thumbprint|issued-token-groups + app uri + endpoint
    ) -> Vec<NodeId>;                 // role NodeIds (well-known + custom)
}
```

- Exposed on `RequestContext`: `fn user_roles(&self) -> &[NodeId]` (the cached resolved set).

## 3. Node permission attributes (read)

- Reading attribute **24** (RolePermissions) returns `Vec<RolePermissionType>` (or null when unconfigured and
  no default) — governed by the **ReadRolePermissions** permission.
- Reading attribute **25** (UserRolePermissions) returns the per-session-role subset.
- Reading attribute **26** (AccessRestrictions) returns the effective `AccessRestrictionType`.
- `UserAccessLevel`/`UserExecutable` reflect the role-effective Read/Write/Call result.

## 4. Configuration / builder surface

```rust
// ServerUserToken — assign roles to a configured identity
pub struct ServerUserToken { /* ... */ pub roles: Vec<NodeId> }

// ServerBuilder / ServerConfig
impl ServerBuilder {
    pub fn identity_mapping_rule(self, role: NodeId, rule: IdentityMappingRule) -> Self;
    pub fn default_role_permissions(self, namespace: u16, perms: Vec<RolePermissionType>) -> Self;
    pub fn default_access_restrictions(self, namespace: u16, r: AccessRestrictionType) -> Self;
    pub fn enforce_role_based_access(self, enabled: bool) -> Self;     // global posture (default: false)
    pub fn with_secure_role_preset(self) -> Self;                      // Part 3 §4.9.2 suggested permissions
}
```

- **Backwards compatibility**: a server built with none of these behaves exactly as before (permissive).

## 5. RoleSet / RoleType management Methods (server-side handlers)

Wired as method callbacks on the core node manager (PubSub-config-methods pattern), gated to SecurityAdmin:

- `RoleSet.AddRole(roleName, namespaceUri) -> roleNodeId`; `RoleSet.RemoveRole(roleNodeId)`.
- `RoleType.AddIdentity(rule)`, `RemoveIdentity(rule)`, `AddApplication(uri)`, `RemoveApplication(uri)`,
  `AddEndpoint(endpoint)`, `RemoveEndpoint(endpoint)`.
- Non-SecurityAdmin callers → `Bad_UserAccessDenied`.

## 6. Enforcement integration points (where contracts are consumed)

| Service | Required permission | Hook |
| --- | --- | --- |
| Read (Value) | Read | `address_space/utils.rs::is_readable` / `user_access_level` |
| Read (RolePermissions attr) | ReadRolePermissions | attribute read path |
| Write (Value) | Write | `validate_write_access` / writable check |
| Write (RolePermissions attr) | WriteRolePermissions | `validate_write_access` (WriteMask already maps it) |
| Call | Call | `is_user_executable` / method service |
| Browse | Browse (+ AccessRestrictions) | view/browse service result filtering |
| HistoryRead | ReadHistory | history_read service |
| HistoryUpdate | Insert/Modify/DeleteHistory | history_update service |
| AddNodes/DeleteNodes | AddNode/DeleteNode | node_management service |
| AddReferences/DeleteReferences | AddReference/RemoveReference | node_management service |
| Event delivery | ReceiveEvents | subscriptions event path |
| Any | AccessRestrictions vs channel | central, ANDed: Bad_SecurityModeInsufficient |
