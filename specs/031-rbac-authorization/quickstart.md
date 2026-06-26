# Quickstart: RBAC / Authorization

How to configure and verify role-based access control once this feature lands.

## 1. Default (no config) — unchanged behaviour

A server built without any role configuration behaves exactly as before: nodes are governed only by
AccessLevel/UserAccessLevel/Executable; no role enforcement. Existing code and tests are unaffected.

## 2. Assign roles to users

```rust
let (server, handle) = ServerBuilder::new()
    .add_user_token("alice", ServerUserToken::user_pass("alice", "pw").with_roles([WellKnownRole::Operator]))
    .add_user_token("eng",   ServerUserToken::user_pass("eng", "pw").with_roles([WellKnownRole::Engineer]))
    // map an X509 cert thumbprint to SecurityAdmin
    .identity_mapping_rule(WellKnownRole::SecurityAdmin, IdentityMappingRule::thumbprint("AB12…"))
    .build()?;
```

- Anonymous sessions get the Anonymous role; any authenticated session implies AuthenticatedUser.

## 3. Permission a node

```rust
VariableBuilder::new(&id, "Setpoint", "Setpoint")
    .data_type(DataTypeId::Double)
    .role_permissions([
        RolePermissionType { role_id: WellKnownRole::Observer.into(), permissions: PermissionType::Read },
        RolePermissionType { role_id: WellKnownRole::Operator.into(),
            permissions: PermissionType::Read | PermissionType::Write },
    ])
    .build();
```

- Observer can read but not write; Operator can read+write; anyone else is denied (the list excludes them).
- A node with NO `role_permissions` (and no namespace default) is permissive (governed only by AccessLevel).

## 4. Namespace defaults & enforce posture

```rust
ServerBuilder::new()
    .default_role_permissions(2, [RolePermissionType {
        role_id: WellKnownRole::AuthenticatedUser.into(), permissions: PermissionType::Read }])
    .enforce_role_based_access(true)        // optional: deny when nothing grants access
    .with_secure_role_preset()              // optional: Part 3 §4.9.2 suggested permissions
```

## 5. Verify

```rust
// Observer session: read OK, write denied
assert_eq!(observer.read_value(&id).await?.status(), StatusCode::Good);
assert_eq!(observer.write_value(&id, 1.0).await.unwrap_err().status(), StatusCode::BadUserAccessDenied);

// Operator session: write OK
assert_eq!(operator.write_value(&id, 1.0).await?, StatusCode::Good);

// UserRolePermissions attribute reflects the session's roles
let urp = session.read_attribute(&id, AttributeId::UserRolePermissions).await?;

// Browse the standard RoleSet
let roles = session.browse(ObjectId::Server_ServerCapabilities_RoleSet).await?;  // 8 well-known roles
```

## 6. Runtime role management (SecurityAdmin only)

```rust
let role = security_admin.call(RoleSet::AddRole, ("Maintainer", "urn:my:ns")).await?;  // -> new RoleType NodeId
security_admin.call(role, RoleType::AddIdentity, username_rule("maint")).await?;
// a session authenticating as "maint" is now granted the new role
```

Non-SecurityAdmin callers of any management Method receive `Bad_UserAccessDenied`.
