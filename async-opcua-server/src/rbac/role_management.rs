use std::sync::Arc;

use opcua_core::sync::RwLock;
use opcua_nodes::DefaultTypeTree;
use opcua_types::{
    BrowseDirection, EndpointType, IdentityMappingRuleType, MethodId, NodeId, ObjectId,
    ObjectTypeId, QualifiedName, ReferenceTypeId, StatusCode, Variant,
};

use crate::{
    address_space::{AddressSpace, ObjectBuilder},
    node_manager::{memory::CoreNodeManager, RequestContext},
    rbac::{resolver::RoleResolver, rules::IdentityMappingRule, WellKnownRole},
};

type Handler = fn(
    &RequestContext,
    &Arc<RwLock<AddressSpace>>,
    &Arc<RwLock<RoleResolver>>,
    &NodeId,
    &[Variant],
) -> Result<Vec<Variant>, StatusCode>;

pub(crate) fn is_security_admin(context: &RequestContext) -> bool {
    context
        .user_roles()
        .contains(&WellKnownRole::SecurityAdmin.node_id())
}

pub(crate) fn register_role_management_methods(
    core_node_manager: &CoreNodeManager,
    role_resolver: Arc<RwLock<RoleResolver>>,
    address_space: Arc<RwLock<AddressSpace>>,
) {
    let methods: &[(MethodId, Handler)] = &[
        (MethodId::RoleType_AddIdentity, add_identity),
        (MethodId::RoleType_RemoveIdentity, remove_identity),
        (MethodId::RoleType_AddApplication, add_application),
        (MethodId::RoleType_RemoveApplication, remove_application),
        (MethodId::RoleType_AddEndpoint, add_endpoint),
        (MethodId::RoleType_RemoveEndpoint, remove_endpoint),
        (MethodId::RoleSetType_AddRole, add_role),
        (MethodId::RoleSetType_RemoveRole, remove_role),
        (
            MethodId::Server_ServerCapabilities_RoleSet_AddRole,
            add_role,
        ),
        (
            MethodId::Server_ServerCapabilities_RoleSet_RemoveRole,
            remove_role,
        ),
        (MethodId::WellKnownRole_Anonymous_AddIdentity, add_identity),
        (
            MethodId::WellKnownRole_Anonymous_RemoveIdentity,
            remove_identity,
        ),
        (
            MethodId::WellKnownRole_Anonymous_AddApplication,
            add_application,
        ),
        (
            MethodId::WellKnownRole_Anonymous_RemoveApplication,
            remove_application,
        ),
        (MethodId::WellKnownRole_Anonymous_AddEndpoint, add_endpoint),
        (
            MethodId::WellKnownRole_Anonymous_RemoveEndpoint,
            remove_endpoint,
        ),
        (
            MethodId::WellKnownRole_AuthenticatedUser_AddIdentity,
            add_identity,
        ),
        (
            MethodId::WellKnownRole_AuthenticatedUser_RemoveIdentity,
            remove_identity,
        ),
        (
            MethodId::WellKnownRole_AuthenticatedUser_AddApplication,
            add_application,
        ),
        (
            MethodId::WellKnownRole_AuthenticatedUser_RemoveApplication,
            remove_application,
        ),
        (
            MethodId::WellKnownRole_AuthenticatedUser_AddEndpoint,
            add_endpoint,
        ),
        (
            MethodId::WellKnownRole_AuthenticatedUser_RemoveEndpoint,
            remove_endpoint,
        ),
        (MethodId::WellKnownRole_Observer_AddIdentity, add_identity),
        (
            MethodId::WellKnownRole_Observer_RemoveIdentity,
            remove_identity,
        ),
        (
            MethodId::WellKnownRole_Observer_AddApplication,
            add_application,
        ),
        (
            MethodId::WellKnownRole_Observer_RemoveApplication,
            remove_application,
        ),
        (MethodId::WellKnownRole_Observer_AddEndpoint, add_endpoint),
        (
            MethodId::WellKnownRole_Observer_RemoveEndpoint,
            remove_endpoint,
        ),
        (MethodId::WellKnownRole_Operator_AddIdentity, add_identity),
        (
            MethodId::WellKnownRole_Operator_RemoveIdentity,
            remove_identity,
        ),
        (
            MethodId::WellKnownRole_Operator_AddApplication,
            add_application,
        ),
        (
            MethodId::WellKnownRole_Operator_RemoveApplication,
            remove_application,
        ),
        (MethodId::WellKnownRole_Operator_AddEndpoint, add_endpoint),
        (
            MethodId::WellKnownRole_Operator_RemoveEndpoint,
            remove_endpoint,
        ),
        (MethodId::WellKnownRole_Engineer_AddIdentity, add_identity),
        (
            MethodId::WellKnownRole_Engineer_RemoveIdentity,
            remove_identity,
        ),
        (
            MethodId::WellKnownRole_Engineer_AddApplication,
            add_application,
        ),
        (
            MethodId::WellKnownRole_Engineer_RemoveApplication,
            remove_application,
        ),
        (MethodId::WellKnownRole_Engineer_AddEndpoint, add_endpoint),
        (
            MethodId::WellKnownRole_Engineer_RemoveEndpoint,
            remove_endpoint,
        ),
        (MethodId::WellKnownRole_Supervisor_AddIdentity, add_identity),
        (
            MethodId::WellKnownRole_Supervisor_RemoveIdentity,
            remove_identity,
        ),
        (
            MethodId::WellKnownRole_Supervisor_AddApplication,
            add_application,
        ),
        (
            MethodId::WellKnownRole_Supervisor_RemoveApplication,
            remove_application,
        ),
        (MethodId::WellKnownRole_Supervisor_AddEndpoint, add_endpoint),
        (
            MethodId::WellKnownRole_Supervisor_RemoveEndpoint,
            remove_endpoint,
        ),
        (
            MethodId::WellKnownRole_ConfigureAdmin_AddIdentity,
            add_identity,
        ),
        (
            MethodId::WellKnownRole_ConfigureAdmin_RemoveIdentity,
            remove_identity,
        ),
        (
            MethodId::WellKnownRole_ConfigureAdmin_AddApplication,
            add_application,
        ),
        (
            MethodId::WellKnownRole_ConfigureAdmin_RemoveApplication,
            remove_application,
        ),
        (
            MethodId::WellKnownRole_ConfigureAdmin_AddEndpoint,
            add_endpoint,
        ),
        (
            MethodId::WellKnownRole_ConfigureAdmin_RemoveEndpoint,
            remove_endpoint,
        ),
        (
            MethodId::WellKnownRole_SecurityAdmin_AddIdentity,
            add_identity,
        ),
        (
            MethodId::WellKnownRole_SecurityAdmin_RemoveIdentity,
            remove_identity,
        ),
        (
            MethodId::WellKnownRole_SecurityAdmin_AddApplication,
            add_application,
        ),
        (
            MethodId::WellKnownRole_SecurityAdmin_RemoveApplication,
            remove_application,
        ),
        (
            MethodId::WellKnownRole_SecurityAdmin_AddEndpoint,
            add_endpoint,
        ),
        (
            MethodId::WellKnownRole_SecurityAdmin_RemoveEndpoint,
            remove_endpoint,
        ),
    ];

    for &(method_id, handler) in methods {
        let address_space = Arc::clone(&address_space);
        let role_resolver = Arc::clone(&role_resolver);
        core_node_manager.inner().add_method_callback_with_context(
            method_id.into(),
            move |context, object_id, args| {
                handler(context, &address_space, &role_resolver, object_id, args)
            },
        );
    }
}

fn add_application(
    context: &RequestContext,
    _address_space: &Arc<RwLock<AddressSpace>>,
    role_resolver: &Arc<RwLock<RoleResolver>>,
    object_id: &NodeId,
    args: &[Variant],
) -> Result<Vec<Variant>, StatusCode> {
    if !is_security_admin(context) {
        return Err(StatusCode::BadUserAccessDenied);
    }

    let application_uri = decode_application_uri_argument(args)?;
    let mut resolver = role_resolver.write();
    if !resolver.contains_role(object_id) {
        return Err(StatusCode::BadNodeIdUnknown);
    }

    if resolver.add_application(object_id, application_uri) {
        Ok(Vec::new())
    } else {
        Err(StatusCode::BadAlreadyExists)
    }
}

fn remove_application(
    context: &RequestContext,
    _address_space: &Arc<RwLock<AddressSpace>>,
    role_resolver: &Arc<RwLock<RoleResolver>>,
    object_id: &NodeId,
    args: &[Variant],
) -> Result<Vec<Variant>, StatusCode> {
    if !is_security_admin(context) {
        return Err(StatusCode::BadUserAccessDenied);
    }

    let application_uri = decode_application_uri_argument(args)?;
    let mut resolver = role_resolver.write();
    if !resolver.contains_role(object_id) {
        return Err(StatusCode::BadNodeIdUnknown);
    }

    if resolver.remove_application(object_id, &application_uri) {
        Ok(Vec::new())
    } else {
        Err(StatusCode::BadNotFound)
    }
}

fn add_endpoint(
    context: &RequestContext,
    _address_space: &Arc<RwLock<AddressSpace>>,
    role_resolver: &Arc<RwLock<RoleResolver>>,
    object_id: &NodeId,
    args: &[Variant],
) -> Result<Vec<Variant>, StatusCode> {
    if !is_security_admin(context) {
        return Err(StatusCode::BadUserAccessDenied);
    }

    let endpoint_url = decode_endpoint_url_argument(args)?;
    let mut resolver = role_resolver.write();
    if !resolver.contains_role(object_id) {
        return Err(StatusCode::BadNodeIdUnknown);
    }

    if resolver.add_endpoint(object_id, endpoint_url) {
        Ok(Vec::new())
    } else {
        Err(StatusCode::BadAlreadyExists)
    }
}

fn remove_endpoint(
    context: &RequestContext,
    _address_space: &Arc<RwLock<AddressSpace>>,
    role_resolver: &Arc<RwLock<RoleResolver>>,
    object_id: &NodeId,
    args: &[Variant],
) -> Result<Vec<Variant>, StatusCode> {
    if !is_security_admin(context) {
        return Err(StatusCode::BadUserAccessDenied);
    }

    let endpoint_url = decode_endpoint_url_argument(args)?;
    let mut resolver = role_resolver.write();
    if !resolver.contains_role(object_id) {
        return Err(StatusCode::BadNodeIdUnknown);
    }

    if resolver.remove_endpoint(object_id, &endpoint_url) {
        Ok(Vec::new())
    } else {
        Err(StatusCode::BadNotFound)
    }
}

fn add_identity(
    context: &RequestContext,
    _address_space: &Arc<RwLock<AddressSpace>>,
    role_resolver: &Arc<RwLock<RoleResolver>>,
    object_id: &NodeId,
    args: &[Variant],
) -> Result<Vec<Variant>, StatusCode> {
    if !is_security_admin(context) {
        return Err(StatusCode::BadUserAccessDenied);
    }

    let rule = decode_identity_mapping_rule_argument(args)?;
    let mut resolver = role_resolver.write();
    if !resolver.contains_role(object_id) {
        return Err(StatusCode::BadNodeIdUnknown);
    }

    resolver.add_mapping(object_id.clone(), rule);
    Ok(Vec::new())
}

fn remove_identity(
    context: &RequestContext,
    _address_space: &Arc<RwLock<AddressSpace>>,
    role_resolver: &Arc<RwLock<RoleResolver>>,
    object_id: &NodeId,
    args: &[Variant],
) -> Result<Vec<Variant>, StatusCode> {
    if !is_security_admin(context) {
        return Err(StatusCode::BadUserAccessDenied);
    }

    let rule = decode_identity_mapping_rule_argument(args)?;
    let mut resolver = role_resolver.write();
    if !resolver.contains_role(object_id) {
        return Err(StatusCode::BadNodeIdUnknown);
    }

    if resolver.remove_mapping(object_id, &rule) {
        Ok(Vec::new())
    } else {
        Err(StatusCode::BadNotFound)
    }
}

fn add_role(
    context: &RequestContext,
    address_space: &Arc<RwLock<AddressSpace>>,
    role_resolver: &Arc<RwLock<RoleResolver>>,
    object_id: &NodeId,
    args: &[Variant],
) -> Result<Vec<Variant>, StatusCode> {
    if !is_security_admin(context) {
        return Err(StatusCode::BadUserAccessDenied);
    }
    ensure_role_set_object(object_id)?;

    let role_name = decode_string_argument(args, 0)?;
    if role_name.is_empty() {
        return Err(StatusCode::BadBrowseNameInvalid);
    }
    let namespace_uri = decode_string_argument(args, 1)?;

    let role_node_id = {
        let mut space = address_space.write();
        let role_set = role_set_node_id();
        let namespace_index = namespace_index_for_role(&mut space, &namespace_uri);
        let browse_name = QualifiedName::new(namespace_index, role_name.as_str());

        let duplicate = {
            let type_tree = DefaultTypeTree::new();
            space
                .find_node_by_browse_name(
                    &role_set,
                    Some((ReferenceTypeId::HasComponent, false)),
                    &type_tree,
                    BrowseDirection::Forward,
                    browse_name.clone(),
                )
                .is_some()
        };
        if duplicate {
            return Err(StatusCode::BadBrowseNameDuplicated);
        }

        let role_node_id = unique_role_node_id(&space, &namespace_uri, &role_name);
        let inserted = ObjectBuilder::new(&role_node_id, browse_name, role_name.as_str())
            .has_type_definition(ObjectTypeId::RoleType)
            .component_of(role_set)
            .insert(&mut *space);
        if !inserted {
            return Err(StatusCode::BadNodeIdExists);
        }
        role_node_id
    };

    role_resolver.write().register_role(role_node_id.clone());
    Ok(vec![Variant::from(role_node_id)])
}

fn remove_role(
    context: &RequestContext,
    address_space: &Arc<RwLock<AddressSpace>>,
    role_resolver: &Arc<RwLock<RoleResolver>>,
    object_id: &NodeId,
    args: &[Variant],
) -> Result<Vec<Variant>, StatusCode> {
    if !is_security_admin(context) {
        return Err(StatusCode::BadUserAccessDenied);
    }
    ensure_role_set_object(object_id)?;

    let role_node_id = decode_node_id_argument(args)?.clone();
    {
        let resolver = role_resolver.read();
        if !resolver.is_runtime_role(&role_node_id) {
            return if resolver.contains_role(&role_node_id) {
                Err(StatusCode::BadRequestNotAllowed)
            } else {
                Err(StatusCode::BadNodeIdUnknown)
            };
        }
    }

    let role_set = role_set_node_id();
    let mut space = address_space.write();
    if !space.node_exists(&role_node_id)
        || !space.has_reference(&role_set, &role_node_id, ReferenceTypeId::HasComponent)
    {
        return Err(StatusCode::BadNodeIdUnknown);
    }
    space.delete(&role_node_id, true);
    drop(space);

    if role_resolver.write().remove_role(&role_node_id) {
        Ok(Vec::new())
    } else {
        Err(StatusCode::BadNodeIdUnknown)
    }
}

fn ensure_role_set_object(object_id: &NodeId) -> Result<(), StatusCode> {
    if object_id == &role_set_node_id() {
        Ok(())
    } else {
        Err(StatusCode::BadNodeIdInvalid)
    }
}

fn role_set_node_id() -> NodeId {
    ObjectId::Server_ServerCapabilities_RoleSet.into()
}

fn namespace_index_for_role(space: &mut AddressSpace, namespace_uri: &str) -> u16 {
    if namespace_uri.is_empty() {
        return 0;
    }
    if let Some(index) = space.namespace_index(namespace_uri) {
        return index;
    }

    let index = space
        .namespaces()
        .keys()
        .copied()
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    space.add_namespace(namespace_uri, index);
    index
}

fn unique_role_node_id(space: &AddressSpace, namespace_uri: &str, role_name: &str) -> NodeId {
    let base = format!("Role:{namespace_uri}:{role_name}");
    let mut candidate = NodeId::new(0, base.clone());
    let mut suffix = 1usize;

    while space.node_exists(&candidate) {
        candidate = NodeId::new(0, format!("{base}:{suffix}"));
        suffix = suffix.saturating_add(1);
    }

    candidate
}

fn decode_string_argument(args: &[Variant], index: usize) -> Result<String, StatusCode> {
    let Variant::String(value) = args.get(index).ok_or(StatusCode::BadArgumentsMissing)? else {
        return Err(StatusCode::BadInvalidArgument);
    };
    if value.is_null() {
        return Err(StatusCode::BadInvalidArgument);
    }
    Ok(value.to_string())
}

fn decode_application_uri_argument(args: &[Variant]) -> Result<String, StatusCode> {
    let application_uri = decode_string_argument(args, 0)?;
    if application_uri.is_empty() {
        return Err(StatusCode::BadInvalidArgument);
    }

    Ok(application_uri)
}

fn decode_endpoint_url_argument(args: &[Variant]) -> Result<String, StatusCode> {
    let argument = args.first().ok_or(StatusCode::BadArgumentsMissing)?.clone();
    let endpoint = argument
        .try_cast_to::<EndpointType>()
        .map_err(|_| StatusCode::BadInvalidArgument)?;

    // Role grant matching is by endpoint URL, so the resolver stores only this field
    // instead of retaining the full EndpointType structure.
    if endpoint.endpoint_url.is_null() {
        return Err(StatusCode::BadInvalidArgument);
    }
    let endpoint_url = endpoint.endpoint_url.to_string();
    if endpoint_url.is_empty() {
        return Err(StatusCode::BadInvalidArgument);
    }

    Ok(endpoint_url)
}

fn decode_node_id_argument(args: &[Variant]) -> Result<&NodeId, StatusCode> {
    let argument = args.first().ok_or(StatusCode::BadArgumentsMissing)?;
    let Variant::NodeId(node_id) = argument else {
        return Err(StatusCode::BadInvalidArgument);
    };

    Ok(node_id)
}

fn decode_identity_mapping_rule_argument(
    args: &[Variant],
) -> Result<IdentityMappingRule, StatusCode> {
    let argument = args.first().ok_or(StatusCode::BadArgumentsMissing)?.clone();
    let generated = argument
        .try_cast_to::<IdentityMappingRuleType>()
        .map_err(|_| StatusCode::BadInvalidArgument)?;

    IdentityMappingRule::try_from(generated).map_err(|_| StatusCode::BadInvalidArgument)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        add_application, add_endpoint, add_identity, add_role, remove_application, remove_endpoint,
        remove_identity, remove_role,
    };

    use opcua_core::sync::RwLock;
    use opcua_nodes::DefaultTypeTree;
    use opcua_nodes::NamespaceMap;
    use opcua_types::{
        AnonymousIdentityToken, ApplicationDescription, BrowseDirection, ByteString, EndpointType,
        ExtensionObject, IdentityCriteriaType, IdentityMappingRuleType, MessageSecurityMode,
        MethodId, NodeId, ObjectId, QualifiedName, ReferenceTypeId, StatusCode, UAString, Variant,
    };

    use crate::{
        address_space::{AddressSpace, CoreNamespace},
        authenticator::UserToken,
        identity_token::{IdentityToken, POLICY_ID_ANONYMOUS},
        node_manager::memory::InMemoryNodeManagerImpl,
        node_manager::{DefaultTypeTreeGetter, RequestContext, RequestContextInner},
        rbac::{
            resolver::{ResolvedIdentity, RoleResolver},
            WellKnownRole,
        },
        session::instance::Session,
        ServerBuilder,
    };

    #[tokio::test]
    async fn add_role_requires_security_admin_role() {
        let context = request_context_with_roles(Vec::new());
        let address_space = Arc::new(RwLock::new(core_address_space()));
        let resolver = Arc::new(RwLock::new(RoleResolver::default()));
        let role_set = NodeId::from(ObjectId::Server_ServerCapabilities_RoleSet);

        let result = add_role(
            &context,
            &address_space,
            &resolver,
            &role_set,
            &[
                Variant::String(UAString::from("RuntimeRole")),
                Variant::String(UAString::from("urn:runtime")),
            ],
        );

        assert_eq!(result, Err(StatusCode::BadUserAccessDenied));
    }

    #[tokio::test]
    async fn security_admin_can_add_and_remove_runtime_role() {
        let context = request_context_with_roles(vec![WellKnownRole::SecurityAdmin.node_id()]);
        let address_space = Arc::new(RwLock::new(core_address_space()));
        let resolver = Arc::new(RwLock::new(RoleResolver::default()));
        let role_set = NodeId::from(ObjectId::Server_ServerCapabilities_RoleSet);

        let outputs = add_role(
            &context,
            &address_space,
            &resolver,
            &role_set,
            &[
                Variant::String(UAString::from("RuntimeRole")),
                Variant::String(UAString::from("urn:runtime")),
            ],
        )
        .expect("SecurityAdmin should be allowed to add roles");
        let role_node_id = match outputs.as_slice() {
            [Variant::NodeId(node_id)] => node_id.clone(),
            other => panic!("unexpected AddRole outputs: {other:?}"),
        };

        {
            let space = address_space.read();
            assert!(space.node_exists(&role_node_id));
            let type_tree = DefaultTypeTree::new();
            let runtime_namespace = space
                .namespace_index("urn:runtime")
                .expect("runtime namespace should be registered");
            assert!(space
                .find_node_by_browse_name(
                    &role_set,
                    Some((ReferenceTypeId::HasComponent, false)),
                    &type_tree,
                    BrowseDirection::Forward,
                    QualifiedName::new(runtime_namespace, "RuntimeRole"),
                )
                .is_some());
        }
        assert!(resolver.read().is_runtime_role(&role_node_id));

        remove_role(
            &context,
            &address_space,
            &resolver,
            &role_set,
            &[Variant::NodeId(role_node_id.clone())],
        )
        .expect("SecurityAdmin should be allowed to remove runtime roles");

        assert!(!address_space.read().node_exists(&role_node_id));
        assert!(!resolver.read().is_runtime_role(&role_node_id));
    }

    #[tokio::test]
    async fn security_admin_can_add_and_remove_role_identity_mapping() {
        let context = request_context_with_roles(vec![WellKnownRole::SecurityAdmin.node_id()]);
        let address_space = Arc::new(RwLock::new(core_address_space()));
        let resolver = Arc::new(RwLock::new(RoleResolver::default()));
        let role_node_id = WellKnownRole::Operator.node_id();
        let rule = IdentityMappingRuleType {
            criteria_type: IdentityCriteriaType::UserName,
            criteria: UAString::from("operator"),
        };
        let identity = ResolvedIdentity::username(
            "operator",
            Some("urn:client"),
            Some("opc.tcp://localhost:4840"),
        );

        add_identity(
            &context,
            &address_space,
            &resolver,
            &role_node_id,
            &[Variant::from(rule.clone())],
        )
        .expect("SecurityAdmin should be allowed to add role identity mappings");

        assert!(resolver.read().resolve(&identity).contains(&role_node_id));

        remove_identity(
            &context,
            &address_space,
            &resolver,
            &role_node_id,
            &[Variant::from(rule)],
        )
        .expect("SecurityAdmin should be allowed to remove role identity mappings");

        assert!(!resolver.read().resolve(&identity).contains(&role_node_id));
    }

    #[tokio::test]
    async fn add_identity_requires_security_admin_role() {
        let context = request_context_with_roles(Vec::new());
        let address_space = Arc::new(RwLock::new(core_address_space()));
        let resolver = Arc::new(RwLock::new(RoleResolver::default()));
        let role_node_id = WellKnownRole::Operator.node_id();
        let rule = IdentityMappingRuleType {
            criteria_type: IdentityCriteriaType::UserName,
            criteria: UAString::from("operator"),
        };

        let result = add_identity(
            &context,
            &address_space,
            &resolver,
            &role_node_id,
            &[Variant::from(rule)],
        );

        assert_eq!(result, Err(StatusCode::BadUserAccessDenied));
    }

    #[tokio::test]
    async fn security_admin_can_add_and_remove_role_application_filter() {
        let context = request_context_with_roles(vec![WellKnownRole::SecurityAdmin.node_id()]);
        let address_space = Arc::new(RwLock::new(core_address_space()));
        let resolver = Arc::new(RwLock::new(RoleResolver::default()));
        let role_node_id = WellKnownRole::Operator.node_id();
        let rule = IdentityMappingRuleType {
            criteria_type: IdentityCriteriaType::UserName,
            criteria: UAString::from("operator"),
        };
        let blocked_identity = ResolvedIdentity::username(
            "operator",
            Some("urn:blocked-client"),
            Some("opc.tcp://localhost:4840"),
        );
        let other_identity = ResolvedIdentity::username(
            "operator",
            Some("urn:other-client"),
            Some("opc.tcp://localhost:4840"),
        );

        add_identity(
            &context,
            &address_space,
            &resolver,
            &role_node_id,
            &[Variant::from(rule)],
        )
        .expect("SecurityAdmin should be allowed to add role identity mappings");
        assert!(resolver
            .read()
            .resolve(&blocked_identity)
            .contains(&role_node_id));

        add_application(
            &context,
            &address_space,
            &resolver,
            &role_node_id,
            &[Variant::String(UAString::from("urn:blocked-client"))],
        )
        .expect("SecurityAdmin should be allowed to add role application filters");

        assert!(!resolver
            .read()
            .resolve(&blocked_identity)
            .contains(&role_node_id));
        assert!(resolver
            .read()
            .resolve(&other_identity)
            .contains(&role_node_id));

        remove_application(
            &context,
            &address_space,
            &resolver,
            &role_node_id,
            &[Variant::String(UAString::from("urn:blocked-client"))],
        )
        .expect("SecurityAdmin should be allowed to remove role application filters");

        assert!(resolver
            .read()
            .resolve(&blocked_identity)
            .contains(&role_node_id));
    }

    #[tokio::test]
    async fn add_application_requires_security_admin_role() {
        let context = request_context_with_roles(Vec::new());
        let address_space = Arc::new(RwLock::new(core_address_space()));
        let resolver = Arc::new(RwLock::new(RoleResolver::default()));
        let role_node_id = WellKnownRole::Operator.node_id();

        let result = add_application(
            &context,
            &address_space,
            &resolver,
            &role_node_id,
            &[Variant::String(UAString::from("urn:blocked-client"))],
        );

        assert_eq!(result, Err(StatusCode::BadUserAccessDenied));
    }

    #[tokio::test]
    async fn security_admin_can_add_and_remove_role_endpoint_filter() {
        let context = request_context_with_roles(vec![WellKnownRole::SecurityAdmin.node_id()]);
        let address_space = Arc::new(RwLock::new(core_address_space()));
        let resolver = Arc::new(RwLock::new(RoleResolver::default()));
        let role_node_id = WellKnownRole::Operator.node_id();
        let rule = IdentityMappingRuleType {
            criteria_type: IdentityCriteriaType::UserName,
            criteria: UAString::from("operator"),
        };
        let blocked_identity = ResolvedIdentity::username(
            "operator",
            Some("urn:client"),
            Some("opc.tcp://blocked.example:4840"),
        );
        let other_identity = ResolvedIdentity::username(
            "operator",
            Some("urn:client"),
            Some("opc.tcp://allowed.example:4840"),
        );

        add_identity(
            &context,
            &address_space,
            &resolver,
            &role_node_id,
            &[Variant::from(rule)],
        )
        .expect("SecurityAdmin should be allowed to add role identity mappings");
        assert!(resolver
            .read()
            .resolve(&blocked_identity)
            .contains(&role_node_id));

        add_endpoint(
            &context,
            &address_space,
            &resolver,
            &role_node_id,
            &[endpoint_argument("opc.tcp://blocked.example:4840")],
        )
        .expect("SecurityAdmin should be allowed to add role endpoint filters");

        assert!(!resolver
            .read()
            .resolve(&blocked_identity)
            .contains(&role_node_id));
        assert!(resolver
            .read()
            .resolve(&other_identity)
            .contains(&role_node_id));

        remove_endpoint(
            &context,
            &address_space,
            &resolver,
            &role_node_id,
            &[endpoint_argument("opc.tcp://blocked.example:4840")],
        )
        .expect("SecurityAdmin should be allowed to remove role endpoint filters");

        assert!(resolver
            .read()
            .resolve(&blocked_identity)
            .contains(&role_node_id));
    }

    #[tokio::test]
    async fn add_endpoint_requires_security_admin_role() {
        let context = request_context_with_roles(Vec::new());
        let address_space = Arc::new(RwLock::new(core_address_space()));
        let resolver = Arc::new(RwLock::new(RoleResolver::default()));
        let role_node_id = WellKnownRole::Operator.node_id();

        let result = add_endpoint(
            &context,
            &address_space,
            &resolver,
            &role_node_id,
            &[endpoint_argument("opc.tcp://blocked.example:4840")],
        );

        assert_eq!(result, Err(StatusCode::BadUserAccessDenied));
    }

    #[tokio::test]
    async fn server_startup_registers_role_set_method_callbacks() {
        let (_server, handle) = ServerBuilder::new_anonymous("role method registration test")
            .build()
            .expect("test server should build");
        let core_node_manager = handle
            .node_managers()
            .get_of_type::<crate::node_manager::memory::CoreNodeManager>()
            .expect("default server should include core node manager");

        for method_id in [
            MethodId::RoleType_AddIdentity,
            MethodId::RoleType_RemoveIdentity,
            MethodId::RoleType_AddApplication,
            MethodId::RoleType_RemoveApplication,
            MethodId::RoleType_AddEndpoint,
            MethodId::RoleType_RemoveEndpoint,
            MethodId::RoleSetType_AddRole,
            MethodId::RoleSetType_RemoveRole,
            MethodId::Server_ServerCapabilities_RoleSet_AddRole,
            MethodId::Server_ServerCapabilities_RoleSet_RemoveRole,
            MethodId::WellKnownRole_Anonymous_AddIdentity,
            MethodId::WellKnownRole_Anonymous_RemoveIdentity,
            MethodId::WellKnownRole_Anonymous_AddApplication,
            MethodId::WellKnownRole_Anonymous_RemoveApplication,
            MethodId::WellKnownRole_Anonymous_AddEndpoint,
            MethodId::WellKnownRole_Anonymous_RemoveEndpoint,
            MethodId::WellKnownRole_AuthenticatedUser_AddIdentity,
            MethodId::WellKnownRole_AuthenticatedUser_RemoveIdentity,
            MethodId::WellKnownRole_AuthenticatedUser_AddApplication,
            MethodId::WellKnownRole_AuthenticatedUser_RemoveApplication,
            MethodId::WellKnownRole_AuthenticatedUser_AddEndpoint,
            MethodId::WellKnownRole_AuthenticatedUser_RemoveEndpoint,
            MethodId::WellKnownRole_Observer_AddIdentity,
            MethodId::WellKnownRole_Observer_RemoveIdentity,
            MethodId::WellKnownRole_Observer_AddApplication,
            MethodId::WellKnownRole_Observer_RemoveApplication,
            MethodId::WellKnownRole_Observer_AddEndpoint,
            MethodId::WellKnownRole_Observer_RemoveEndpoint,
            MethodId::WellKnownRole_Operator_AddIdentity,
            MethodId::WellKnownRole_Operator_RemoveIdentity,
            MethodId::WellKnownRole_Operator_AddApplication,
            MethodId::WellKnownRole_Operator_RemoveApplication,
            MethodId::WellKnownRole_Operator_AddEndpoint,
            MethodId::WellKnownRole_Operator_RemoveEndpoint,
            MethodId::WellKnownRole_Engineer_AddIdentity,
            MethodId::WellKnownRole_Engineer_RemoveIdentity,
            MethodId::WellKnownRole_Engineer_AddApplication,
            MethodId::WellKnownRole_Engineer_RemoveApplication,
            MethodId::WellKnownRole_Engineer_AddEndpoint,
            MethodId::WellKnownRole_Engineer_RemoveEndpoint,
            MethodId::WellKnownRole_Supervisor_AddIdentity,
            MethodId::WellKnownRole_Supervisor_RemoveIdentity,
            MethodId::WellKnownRole_Supervisor_AddApplication,
            MethodId::WellKnownRole_Supervisor_RemoveApplication,
            MethodId::WellKnownRole_Supervisor_AddEndpoint,
            MethodId::WellKnownRole_Supervisor_RemoveEndpoint,
            MethodId::WellKnownRole_ConfigureAdmin_AddIdentity,
            MethodId::WellKnownRole_ConfigureAdmin_RemoveIdentity,
            MethodId::WellKnownRole_ConfigureAdmin_AddApplication,
            MethodId::WellKnownRole_ConfigureAdmin_RemoveApplication,
            MethodId::WellKnownRole_ConfigureAdmin_AddEndpoint,
            MethodId::WellKnownRole_ConfigureAdmin_RemoveEndpoint,
            MethodId::WellKnownRole_SecurityAdmin_AddIdentity,
            MethodId::WellKnownRole_SecurityAdmin_RemoveIdentity,
            MethodId::WellKnownRole_SecurityAdmin_AddApplication,
            MethodId::WellKnownRole_SecurityAdmin_RemoveApplication,
            MethodId::WellKnownRole_SecurityAdmin_AddEndpoint,
            MethodId::WellKnownRole_SecurityAdmin_RemoveEndpoint,
        ] {
            assert!(
                core_node_manager
                    .inner()
                    .accepts_method_without_object_component(&method_id.into()),
                "{method_id:?} should be registered"
            );
        }
    }

    fn endpoint_argument(endpoint_url: &str) -> Variant {
        Variant::ExtensionObject(ExtensionObject::from_message(EndpointType {
            endpoint_url: UAString::from(endpoint_url),
            security_mode: MessageSecurityMode::SignAndEncrypt,
            security_policy_uri: UAString::from("http://opcfoundation.org/UA/SecurityPolicy#None"),
            transport_profile_uri: UAString::from(
                "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary",
            ),
        }))
    }

    fn core_address_space() -> AddressSpace {
        let mut address_space = AddressSpace::new();
        address_space.add_namespace("http://opcfoundation.org/UA/", 0);
        let mut namespaces = NamespaceMap::default();
        address_space.import_node_set(&CoreNamespace, &mut namespaces);
        address_space
    }

    fn request_context_with_roles(user_roles: Vec<NodeId>) -> RequestContext {
        let (_server, handle) = ServerBuilder::new_anonymous("role management test")
            .without_node_managers()
            .build()
            .expect("test server should build");
        let info = handle.info().clone();
        let session = Session::create(
            &info,
            NodeId::new(0, 1),
            1,
            60_000,
            0,
            0,
            UAString::from("opc.tcp://localhost"),
            opcua_crypto::SecurityPolicy::None.to_str().to_string(),
            IdentityToken::Anonymous(AnonymousIdentityToken {
                policy_id: UAString::from(POLICY_ID_ANONYMOUS),
            }),
            None,
            ByteString::null(),
            UAString::from("test"),
            ApplicationDescription::default(),
            MessageSecurityMode::None,
        );

        RequestContext {
            current_node_manager_index: 0,
            inner: Arc::new(RequestContextInner {
                session: Arc::new(RwLock::new(session)),
                session_id: 1,
                authenticator: info.authenticator.clone(),
                token: UserToken("anonymous".to_string()),
                user_roles: Arc::new(user_roles),
                type_tree: info.type_tree.clone(),
                type_tree_getter: Arc::new(DefaultTypeTreeGetter),
                subscriptions: handle.subscriptions().clone(),
                info,
            }),
        }
    }
}
