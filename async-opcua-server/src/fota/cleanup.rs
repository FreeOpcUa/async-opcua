//! Cleanup registry for session-bound temporary FOTA files.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, OnceLock, Weak},
};

use opcua_core::sync::RwLock;
use opcua_types::NodeId;
use parking_lot::RwLock as ParkingRwLock;
use tracing::warn;

use crate::{address_space::AddressSpace, fota::file_node::TemporaryFileNode};

type AddressSpaceRef = Weak<RwLock<AddressSpace>>;

#[derive(Debug, Clone)]
struct CleanupResource {
    address_space: Option<AddressSpaceRef>,
    node_ids: Vec<NodeId>,
    file_path: Option<PathBuf>,
}

/// Summary of resources removed by a cleanup operation.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CleanupReport {
    /// Number of registered resources drained.
    pub resources: usize,
    /// Number of address-space nodes deleted.
    pub nodes: usize,
    /// Number of filesystem files deleted.
    pub files: usize,
    /// Number of cleanup errors encountered.
    pub errors: usize,
}

static CLEANUP_REGISTRY: OnceLock<ParkingRwLock<HashMap<NodeId, Vec<CleanupResource>>>> =
    OnceLock::new();

fn registry() -> &'static ParkingRwLock<HashMap<NodeId, Vec<CleanupResource>>> {
    CLEANUP_REGISTRY.get_or_init(|| ParkingRwLock::new(HashMap::new()))
}

/// Register temporary file nodes and optional backing file for session cleanup.
pub fn register_session_file(
    session_id: NodeId,
    address_space: &Arc<RwLock<AddressSpace>>,
    file_node: &TemporaryFileNode,
    file_path: Option<PathBuf>,
) {
    let resource = CleanupResource {
        address_space: Some(Arc::downgrade(address_space)),
        node_ids: file_node.node_ids(),
        file_path,
    };
    registry()
        .write()
        .entry(session_id)
        .or_default()
        .push(resource);
}

/// Register a filesystem path for session cleanup.
pub fn register_session_file_path(session_id: NodeId, file_path: PathBuf) {
    let resource = CleanupResource {
        address_space: None,
        node_ids: Vec::new(),
        file_path: Some(file_path),
    };
    registry()
        .write()
        .entry(session_id)
        .or_default()
        .push(resource);
}

/// Cleanup all FOTA resources registered for a session.
pub fn cleanup_session(session_id: &NodeId) -> CleanupReport {
    let resources = registry().write().remove(session_id).unwrap_or_default();
    cleanup_resources(resources)
}

fn cleanup_resources(resources: Vec<CleanupResource>) -> CleanupReport {
    let mut report = CleanupReport {
        resources: resources.len(),
        ..CleanupReport::default()
    };

    for resource in resources {
        if let Some(address_space) = resource.address_space.and_then(|weak| weak.upgrade()) {
            let mut address_space = opcua_core::trace_write_lock!(address_space);
            for node_id in &resource.node_ids {
                if address_space.delete(node_id, true).is_some() {
                    report.nodes += 1;
                }
            }
        } else if !resource.node_ids.is_empty() {
            report.errors += 1;
            warn!("FOTA cleanup skipped address-space nodes because the address space was dropped");
        }

        if let Some(file_path) = resource.file_path {
            match std::fs::remove_file(&file_path) {
                Ok(()) => report.files += 1,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    report.errors += 1;
                    warn!(
                        "FOTA cleanup failed to delete {}: {err}",
                        file_path.display()
                    );
                }
            }
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fota::file_node::TemporaryFileNodeConfig;

    #[test]
    fn cleanup_session_removes_registered_address_space_nodes() {
        let address_space = Arc::new(RwLock::new(AddressSpace::new()));
        let session_id = NodeId::new(0, "cleanup-session-1");
        let file_node = {
            let mut address_space = address_space.write();
            TemporaryFileNode::create(
                &mut address_space,
                TemporaryFileNodeConfig::new(2, session_id.clone(), "firmware.bin"),
            )
            .expect("temporary file node should be created")
        };

        register_session_file(session_id.clone(), &address_space, &file_node, None);
        let report = cleanup_session(&session_id);

        assert_eq!(report.resources, 1);
        assert_eq!(report.nodes, file_node.node_ids().len());
        let address_space = address_space.read();
        for node_id in file_node.node_ids() {
            assert!(
                address_space.find(&node_id).is_none(),
                "expected cleanup to delete owned node {node_id}"
            );
        }
    }

    #[test]
    fn cleanup_session_removes_registered_file_path() {
        let session_id = NodeId::new(0, "cleanup-session-2");
        let path = std::env::temp_dir().join(format!(
            "async_opcua_fota_cleanup_{}_{}.bin",
            std::process::id(),
            "cleanup-session-2"
        ));
        std::fs::write(&path, b"firmware").expect("temporary file should be written");

        register_session_file_path(session_id.clone(), path.clone());
        let report = cleanup_session(&session_id);

        assert_eq!(report.resources, 1);
        assert_eq!(report.files, 1);
        assert!(!path.exists());
    }
}
