use std::sync::Arc;

use super::{DynNodeManager, NodeManager, ServerContext};

/// Trait for node manager builders. Node managers are built at the same time as the server,
/// after it has been configured, so each custom node manager needs to defined a builder type
/// that implements this trait.
///
/// Build is infallible, if you need anything to fail, you need to either panic or
/// propagate that failure to the user when creating the builder.
pub trait NodeManagerBuilder {
    /// Build the node manager, you can store data from `context`, but you should not
    /// hold any locks when this method has finished.
    fn build(self: Box<Self>, context: ServerContext) -> Arc<DynNodeManager>;
}

impl<T, R: NodeManager + Send + Sync + 'static> NodeManagerBuilder for T
where
    T: FnOnce(ServerContext) -> R,
{
    fn build(self: Box<Self>, context: ServerContext) -> Arc<DynNodeManager> {
        Arc::new(self(context))
    }
}
