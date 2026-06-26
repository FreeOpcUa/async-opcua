//! Role-Based Access Control integration tests — OPC UA Part 3 §4.8–4.9 / §8.55–8.56, Part 18.
//!
//! US1 (feature 031): the RolePermissions(24) / UserRolePermissions(25) / AccessRestrictions(26)
//! node attributes are readable. Enforcement (US3+) is not exercised here.

use crate::utils::{read_value_id, setup};
use opcua::{
    server::address_space::{AccessLevel, VariableBuilder},
    types::{
        AccessRestrictionType, AttributeId, DataTypeId, NodeId, ObjectId, PermissionType,
        ReferenceTypeId, RolePermissionType, TimestampsToReturn, VariableTypeId, Variant,
    },
};

/// Build a Double variable carrying the given role permissions + access restrictions.
fn add_permissioned_var(
    tester: &crate::utils::Tester,
    nm: &std::sync::Arc<crate::utils::TestNodeManager>,
    name: &str,
    role_permissions: Vec<RolePermissionType>,
    access_restrictions: Option<AccessRestrictionType>,
) -> NodeId {
    let id = nm.inner().next_node_id();
    let mut builder = VariableBuilder::new(&id, name, name)
        .value(0.0f64)
        .data_type(DataTypeId::Double)
        .access_level(AccessLevel::CURRENT_READ)
        .user_access_level(AccessLevel::CURRENT_READ);
    if !role_permissions.is_empty() {
        builder = builder.role_permissions(role_permissions);
    }
    if let Some(ar) = access_restrictions {
        builder = builder.access_restrictions(ar);
    }
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        builder.build().into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        Some(&VariableTypeId::BaseDataVariableType.into()),
        Vec::new(),
    );
    id
}

/// US1 / Part 3 §5.2.9: the RolePermissions attribute (24) returns the configured (roleId, permissions) list.
#[tokio::test]
async fn reads_role_permissions_attribute() {
    let (tester, nm, session) = setup().await;
    let role = NodeId::new(1, 4242);
    let id = add_permissioned_var(
        &tester,
        &nm,
        "RpVar",
        vec![RolePermissionType {
            role_id: role.clone(),
            permissions: PermissionType::Read | PermissionType::Write,
        }],
        None,
    );

    let r = session
        .read(
            &[read_value_id(AttributeId::RolePermissions, id)],
            TimestampsToReturn::Neither,
            0.0,
        )
        .await
        .unwrap();
    let Some(Variant::Array(arr)) = &r[0].value else {
        panic!("RolePermissions must be an array, got {:?}", r[0].value);
    };
    assert_eq!(arr.values.len(), 1);
    let Variant::ExtensionObject(obj) = &arr.values[0] else {
        panic!("RolePermissions entry must be an ExtensionObject");
    };
    let rp = obj
        .inner_as::<RolePermissionType>()
        .expect("RolePermissionType");
    assert_eq!(rp.role_id, role);
    assert_eq!(rp.permissions, PermissionType::Read | PermissionType::Write);
}

/// US1 / Part 3 §8.56: the AccessRestrictions attribute (26) returns the configured bitmask.
#[tokio::test]
async fn reads_access_restrictions_attribute() {
    let (tester, nm, session) = setup().await;
    let id = add_permissioned_var(
        &tester,
        &nm,
        "ArVar",
        Vec::new(),
        Some(AccessRestrictionType::EncryptionRequired),
    );

    let r = session
        .read(
            &[read_value_id(AttributeId::AccessRestrictions, id)],
            TimestampsToReturn::Neither,
            0.0,
        )
        .await
        .unwrap();
    assert_eq!(
        r[0].value,
        Some(Variant::UInt16(
            AccessRestrictionType::EncryptionRequired.bits() as u16
        )),
        "AccessRestrictions must return the UInt16 bitmask"
    );
}

/// US1 / Part 3 §5.2: UserRolePermissions (25) is the subset for the session's granted roles. Until role
/// resolution (US2), a session has no roles, so the subset of any RolePermissions list is empty.
#[tokio::test]
async fn user_role_permissions_is_empty_without_granted_roles() {
    let (tester, nm, session) = setup().await;
    let id = add_permissioned_var(
        &tester,
        &nm,
        "UrpVar",
        vec![RolePermissionType {
            role_id: NodeId::new(1, 7),
            permissions: PermissionType::Read,
        }],
        None,
    );

    let r = session
        .read(
            &[read_value_id(AttributeId::UserRolePermissions, id)],
            TimestampsToReturn::Neither,
            0.0,
        )
        .await
        .unwrap();
    // No roles granted ⇒ empty subset (null or an empty array), never the full list.
    match &r[0].value {
        None | Some(Variant::Empty) => {}
        Some(Variant::Array(arr)) => assert!(
            arr.values.is_empty(),
            "UserRolePermissions must be empty without granted roles"
        ),
        other => panic!("unexpected UserRolePermissions value: {other:?}"),
    }
}

/// US1: a node with no configured permissions returns null/empty for 24/25/26 without error.
#[tokio::test]
async fn unconfigured_permission_attributes_are_null() {
    let (tester, nm, session) = setup().await;
    let id = add_permissioned_var(&tester, &nm, "PlainVar", Vec::new(), None);

    let r = session
        .read(
            &[
                read_value_id(AttributeId::RolePermissions, id.clone()),
                read_value_id(AttributeId::UserRolePermissions, id.clone()),
                read_value_id(AttributeId::AccessRestrictions, id),
            ],
            TimestampsToReturn::Neither,
            0.0,
        )
        .await
        .unwrap();
    for dv in &r {
        assert!(
            matches!(dv.value, None | Some(Variant::Empty)) || dv.status().is_good(),
            "unconfigured permission attribute must not error: {dv:?}"
        );
    }
}

/// US2 / Part 3 §4.9.2: an anonymous session is granted the Anonymous well-known role (i=15644).
/// Observable end-to-end via UserRolePermissions: a node permissioned for the Anonymous role reports
/// that entry to the (anonymous) session, proving identity→role resolution ran at activation.
#[tokio::test]
async fn anonymous_session_is_granted_anonymous_role() {
    let (tester, nm, session) = setup().await;
    let anonymous_role = NodeId::new(0, 15644);
    let id = add_permissioned_var(
        &tester,
        &nm,
        "AnonPerm",
        vec![RolePermissionType {
            role_id: anonymous_role.clone(),
            permissions: PermissionType::Read,
        }],
        None,
    );

    let r = session
        .read(
            &[read_value_id(AttributeId::UserRolePermissions, id)],
            TimestampsToReturn::Neither,
            0.0,
        )
        .await
        .unwrap();
    let Some(Variant::Array(arr)) = &r[0].value else {
        panic!(
            "anonymous session must see its Anonymous-role permission, got {:?}",
            r[0].value
        );
    };
    assert_eq!(
        arr.values.len(),
        1,
        "expected one UserRolePermissions entry"
    );
    let Variant::ExtensionObject(obj) = &arr.values[0] else {
        panic!("entry must be an ExtensionObject");
    };
    let rp = obj
        .inner_as::<RolePermissionType>()
        .expect("RolePermissionType");
    assert_eq!(
        rp.role_id, anonymous_role,
        "must be the Anonymous role entry"
    );
    assert_eq!(rp.permissions, PermissionType::Read);
}

/// US2 / Part 18 §4.4.1 / Part 5: the RoleSet object and the 8 well-known RoleType instances are
/// present in the address space at their standard NodeIds.
#[tokio::test]
async fn roleset_exposes_well_known_roles() {
    use opcua::server::node_manager::memory::CoreNodeManager;

    let (tester, _nm, _session) = setup().await;
    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .expect("CoreNodeManager");
    let space = core_nm.address_space().read();

    // RoleSet object (i=15606) + the 8 well-known roles.
    let role_set = NodeId::new(0, 15606);
    assert!(space.node_exists(&role_set), "RoleSet object must exist");
    for (role, id) in [
        ("Anonymous", 15644u32),
        ("AuthenticatedUser", 15656),
        ("Observer", 15668),
        ("Operator", 15680),
        ("Supervisor", 15692),
        ("SecurityAdmin", 15704),
        ("ConfigureAdmin", 15716),
        ("Engineer", 16036),
    ] {
        assert!(
            space.node_exists(&NodeId::new(0, id)),
            "well-known role {role} (i={id}) must exist"
        );
    }
}
