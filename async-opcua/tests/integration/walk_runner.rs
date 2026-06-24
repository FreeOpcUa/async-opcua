//! Address-space walk conformance runner (Part 4 §5.8 Browse / §5.8.3 BrowseNext).
//!
//! This ports the spirit of the OPC Foundation reference stack's `CommonTestWorkers
//! .BrowseFullAddressSpaceWorkerAsync`: walk the entire hierarchical address space from the Root
//! folder, deliberately using a small `maxReferencesPerNode` so the server is forced to use
//! continuation points across many nodes. It asserts the View-service invariants a conformant server
//! must uphold while a generic client crawls it:
//!
//!   * no Browse/BrowseNext result ever returns more references than the client requested,
//!   * continuation points round-trip (BrowseNext retrieves the remainder),
//!   * the crawl terminates (cycle-safe) and reaches the whole standard address space.

use std::collections::{HashSet, VecDeque};

use opcua::types::{
    BrowseDescription, BrowseDirection, BrowseResultMask, NodeClassMask, NodeId, ObjectId,
    ReferenceTypeId, StatusCode,
};

use super::utils::setup;

/// Small on purpose: forces the server to emit continuation points on any node with more than this
/// many forward hierarchical references, exercising the BrowseNext path heavily.
const MAX_REFS_PER_NODE: u32 = 3;
/// Safety bound so a server bug can never hang the test.
const MAX_BROWSE_OPS: usize = 200_000;

fn hierarchical_desc(node_id: NodeId) -> BrowseDescription {
    BrowseDescription {
        node_id,
        browse_direction: BrowseDirection::Forward,
        reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
        include_subtypes: true,
        node_class_mask: NodeClassMask::all().bits(),
        result_mask: BrowseResultMask::All as u32,
    }
}

#[tokio::test]
async fn full_address_space_walk_honors_operation_limits() {
    let (_tester, _nm, session) = setup().await;

    let mut visited: HashSet<NodeId> = HashSet::new();
    let mut queue: VecDeque<NodeId> = VecDeque::new();
    let root: NodeId = ObjectId::RootFolder.into();
    visited.insert(root.clone());
    queue.push_back(root);

    let mut browse_ops = 0usize;
    let mut continuation_points_used = 0usize;
    let mut max_refs_seen = 0usize;

    // Collect the forward references of one node, following continuation points, asserting the
    // per-result cap is honored, and enqueue any not-yet-visited local target nodes.
    while let Some(node) = queue.pop_front() {
        assert!(
            browse_ops < MAX_BROWSE_OPS,
            "address-space walk exceeded {MAX_BROWSE_OPS} browse ops — possible cycle or runaway"
        );

        let r = session
            .browse(&[hierarchical_desc(node.clone())], MAX_REFS_PER_NODE, None)
            .await
            .unwrap();
        browse_ops += 1;
        let mut result = r.into_iter().next().expect("one browse result");
        assert_eq!(
            StatusCode::Good,
            result.status_code,
            "browse of {node} returned {}",
            result.status_code
        );

        loop {
            let refs = result.references.clone().unwrap_or_default();
            max_refs_seen = max_refs_seen.max(refs.len());
            assert!(
                refs.len() <= MAX_REFS_PER_NODE as usize,
                "server returned {} references for a maxReferencesPerNode={} request (node {node})",
                refs.len(),
                MAX_REFS_PER_NODE
            );
            for reference in refs {
                // Only follow targets that live on this server (local, namespace-resolved).
                let target = reference.node_id;
                if target.server_index == 0 && target.namespace_uri.is_null() {
                    let id = target.node_id;
                    if visited.insert(id.clone()) {
                        queue.push_back(id);
                    }
                }
            }

            if result.continuation_point.is_null() {
                break;
            }
            continuation_points_used += 1;
            assert!(
                browse_ops < MAX_BROWSE_OPS,
                "address-space walk exceeded {MAX_BROWSE_OPS} browse ops during BrowseNext"
            );
            let next = session
                .browse_next(false, &[result.continuation_point.clone()])
                .await
                .unwrap();
            browse_ops += 1;
            result = next.into_iter().next().expect("one browse_next result");
            assert_eq!(
                StatusCode::Good,
                result.status_code,
                "browse_next of {node}"
            );
        }
    }

    println!(
        "[walk] nodes_visited={} browse_ops={} continuation_points_used={} max_refs_per_result={}",
        visited.len(),
        browse_ops,
        continuation_points_used,
        max_refs_seen
    );

    // The standard address space is large; reaching only a handful of nodes means the crawl broke.
    assert!(
        visited.len() > 1500,
        "walk only reached {} nodes; expected the full standard address space (>1500)",
        visited.len()
    );
    // With maxReferencesPerNode=3 over a real address space, continuation points must have been
    // exercised — otherwise the server is silently ignoring the cap.
    assert!(
        continuation_points_used > 0,
        "no continuation points were used despite maxReferencesPerNode={MAX_REFS_PER_NODE}"
    );
}
