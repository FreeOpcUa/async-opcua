use std::sync::Arc;

use crate::{
    authenticator::{AuthManager, UserToken},
    info::ServerInfo,
    session::instance::Session,
    SubscriptionCache,
};
use opcua_core::{sync::RwLock, trace_read_lock};
use opcua_nodes::TypeTree;
use opcua_types::{BrowseDescriptionResultMask, NodeId};
use parking_lot::lock_api::{RawRwLock, RwLockReadGuard};
use tracing::debug_span;
use tracing_futures::Instrument;

use super::{
    view::{ExternalReferenceRequest, NodeMetadata},
    DefaultTypeTree, NodeManagers,
};

/// Trait for providing a dynamic type tree for a user.
/// This is a bit complex, it doesn't return a type tree directly,
/// instead it returns something that wraps a type tree, for example
/// a `RwLockReadGuard<'_, RawRwLock, dyn TypeTree>`
pub trait TypeTreeForUser: Send + Sync {
    /// Get the type tree for the user associated with the given `ctx`.
    /// This can be the server global type tree, or a custom type tree for each individual user.
    ///
    /// It is sync, so you should do any setup in your [`AuthManager`] implementation.
    fn get_type_tree_for_user<'a>(
        &'a self,
        ctx: &'a RequestContext,
    ) -> Box<dyn TypeTreeReadContext + 'a>;
}

pub(crate) struct DefaultTypeTreeGetter;

impl TypeTreeForUser for DefaultTypeTreeGetter {
    fn get_type_tree_for_user<'a>(
        &'a self,
        ctx: &'a RequestContext,
    ) -> Box<dyn TypeTreeReadContext + 'a> {
        Box::new(trace_read_lock!(ctx.type_tree))
    }
}

/// Type returned from [`TypeTreeForUser`], a trait for something that dereferences
/// to a `dyn TypeTree`.
pub trait TypeTreeReadContext {
    /// Dereference to a dynamic [TypeTree].
    fn get(&self) -> &dyn TypeTree;
}

impl<R: RawRwLock, T: TypeTree> TypeTreeReadContext for RwLockReadGuard<'_, R, T> {
    fn get(&self) -> &dyn TypeTree {
        &**self
    }
}

#[derive(Clone)]
/// Context object passed during writes, contains useful context the node
/// managers can use to execute service calls.
pub struct RequestContext {
    /// The full session object for the session responsible for this service call.
    pub session: Arc<RwLock<Session>>,
    /// The session ID for the session responsible for this service call.
    pub session_id: u32,
    /// The global `AuthManager` object.
    pub authenticator: Arc<dyn AuthManager>,
    /// The current user token.
    pub token: UserToken,
    /// Index of the current node manager.
    pub current_node_manager_index: usize,
    /// Global type tree object.
    pub type_tree: Arc<RwLock<DefaultTypeTree>>,
    /// Wrapper to get a type tree
    pub type_tree_getter: Arc<dyn TypeTreeForUser>,
    /// Subscription cache, containing all subscriptions on the server.
    pub subscriptions: Arc<SubscriptionCache>,
    /// Server info object, containing configuration and other shared server
    /// state.
    pub info: Arc<ServerInfo>,
}

impl RequestContext {
    /// Get the type tree for the current user.
    pub fn get_type_tree_for_user<'a>(&'a self) -> Box<dyn TypeTreeReadContext + 'a> {
        self.type_tree_getter.get_type_tree_for_user(self)
    }
}

/// Resolve a list of references.
pub(crate) async fn resolve_external_references(
    context: &RequestContext,
    node_managers: &NodeManagers,
    references: &[(&NodeId, BrowseDescriptionResultMask)],
) -> Vec<Option<NodeMetadata>> {
    let mut res: Vec<_> = references
        .iter()
        .map(|(n, mask)| ExternalReferenceRequest::new(n, *mask))
        .collect();

    for nm in node_managers.iter() {
        let mut items: Vec<_> = res
            .iter_mut()
            .filter(|r| nm.owns_node(r.node_id()))
            .collect();

        nm.resolve_external_references(context, &mut items)
            .instrument(debug_span!("resolve external references", node_manager = %nm.name()))
            .await;
    }

    res.into_iter().map(|r| r.into_inner()).collect()
}
