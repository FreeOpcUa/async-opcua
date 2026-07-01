//! Cleanup registry for session-bound temporary FOTA files.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Weak},
};

use opcua_core::sync::RwLock;
use opcua_types::NodeId;
use parking_lot::RwLock as ParkingRwLock;
use tracing::warn;

use crate::{address_space::AddressSpace, fota::file_node::TemporaryFileNode, info::ServerInfo};

type AddressSpaceRef = Weak<RwLock<AddressSpace>>;

#[derive(Debug, Clone)]
pub(crate) struct CleanupResource {
    address_space: Option<AddressSpaceRef>,
    node_ids: Vec<NodeId>,
    file_path: Option<PathBuf>,
}

/// Per-`Server` registry of session-bound temporary FOTA file cleanup resources.
/// Owned by `ServerInfo` so independent servers in one process do not collide on
/// session `NodeId`s (which are not globally unique).
#[derive(Default)]
pub(crate) struct FotaCleanupRegistry {
    resources: ParkingRwLock<HashMap<NodeId, Vec<CleanupResource>>>,
}

impl FotaCleanupRegistry {
    fn register(&self, session_id: NodeId, resource: CleanupResource) {
        self.resources
            .write()
            .entry(session_id)
            .or_default()
            .push(resource);
    }

    fn take(&self, session_id: &NodeId) -> Vec<CleanupResource> {
        self.resources
            .write()
            .remove(session_id)
            .unwrap_or_default()
    }
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

/// Register temporary file nodes and optional backing file for session cleanup.
///
/// Takes the owning `ServerInfo` so cleanup state is per-server (feature 049).
pub fn register_session_file(
    info: &ServerInfo,
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
    info.fota_cleanup.register(session_id, resource);
}

/// Register a filesystem path for session cleanup.
pub fn register_session_file_path(info: &ServerInfo, session_id: NodeId, file_path: PathBuf) {
    let resource = CleanupResource {
        address_space: None,
        node_ids: Vec::new(),
        file_path: Some(file_path),
    };
    info.fota_cleanup.register(session_id, resource);
}

/// Cleanup all FOTA resources registered for a session.
pub fn cleanup_session(info: &ServerInfo, session_id: &NodeId) -> CleanupReport {
    cleanup_resources(info.fota_cleanup.take(session_id))
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
    use crate::ServerBuilder;

    fn test_info() -> Arc<ServerInfo> {
        let (_server, handle) = ServerBuilder::new_anonymous("fota-cleanup-test")
            .build()
            .expect("test server should build");
        handle.info().clone()
    }

    #[tokio::test]
    async fn cleanup_session_removes_registered_address_space_nodes() {
        let info = test_info();
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

        register_session_file(&info, session_id.clone(), &address_space, &file_node, None);
        let report = cleanup_session(&info, &session_id);

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

    #[tokio::test]
    async fn cleanup_session_removes_registered_file_path() {
        let info = test_info();
        let session_id = NodeId::new(0, "cleanup-session-2");
        let path = std::env::temp_dir().join(format!(
            "async_opcua_fota_cleanup_{}_{}.bin",
            std::process::id(),
            "cleanup-session-2"
        ));
        std::fs::write(&path, b"firmware").expect("temporary file should be written");

        register_session_file_path(&info, session_id.clone(), path.clone());
        let report = cleanup_session(&info, &session_id);

        assert_eq!(report.resources, 1);
        assert_eq!(report.files, 1);
        assert!(!path.exists());
    }

    // Feature 049: two servers sharing a session NodeId must have isolated cleanup state.
    #[tokio::test]
    async fn fota_cleanup_is_isolated_per_server_instance() {
        let info_a = test_info();
        let info_b = test_info();
        let session_id = NodeId::new(0, "shared-session");
        let path =
            std::env::temp_dir().join(format!("async_opcua_fota_iso_{}.bin", std::process::id()));
        std::fs::write(&path, b"fw").expect("temporary file should be written");

        register_session_file_path(&info_a, session_id.clone(), path.clone());

        // B sees nothing for the same session id and does not touch A's file.
        let report_b = cleanup_session(&info_b, &session_id);
        assert_eq!(report_b.resources, 0);
        assert!(path.exists());

        // A still has its own resource.
        let report_a = cleanup_session(&info_a, &session_id);
        assert_eq!(report_a.resources, 1);

        let _ = std::fs::remove_file(&path);
    }
}
