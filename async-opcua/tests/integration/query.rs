//! Feature 023 — end-to-end Query (QueryFirst/QueryNext) via the new client API, against the
//! already-implemented server handler. Anchored to OPC UA Part 4 §5.9 + real round-trips.

use super::utils::setup;
use opcua::types::{
    AttributeId, ContentFilter, ExpandedNodeId, NodeId, NodeTypeDescription, NumericRange,
    ObjectTypeId, QueryDataDescription, RelativePath, StatusCode, ViewDescription,
};

fn browse_name_of_type(type_def: ObjectTypeId, include_sub_types: bool) -> NodeTypeDescription {
    NodeTypeDescription {
        type_definition_node: type_def.into(),
        include_sub_types,
        data_to_return: Some(vec![QueryDataDescription {
            relative_path: RelativePath::default(), // the matched node itself
            attribute_id: AttributeId::BrowseName as u32,
            index_range: NumericRange::default(),
        }]),
    }
}

#[tokio::test]
async fn query_first_returns_typed_nodes() {
    let (_tester, _nm, session) = setup().await;

    // FolderType has several instances in the standard address space (Objects/Types/Views/...).
    let resp = session
        .query_first(
            ViewDescription::default(),
            vec![browse_name_of_type(ObjectTypeId::FolderType, true)],
            ContentFilter::default(),
            1000,
            0,
        )
        .await
        .unwrap();

    println!(
        "query_first status={:?} data_sets={} cp_null={}",
        resp.response_header.service_result,
        resp.query_data_sets.as_ref().map(|v| v.len()).unwrap_or(0),
        resp.continuation_point.is_null()
    );
    assert_eq!(resp.response_header.service_result, StatusCode::Good);
    let sets = resp.query_data_sets.unwrap_or_default();
    assert!(!sets.is_empty(), "expected at least one FolderType node");
    // Each data set carries the matched node + the requested BrowseName value.
    for ds in &sets {
        assert!(!ds.node_id.is_null());
    }
}

/// QueryNext paginates a multi-batch result via the continuation point — no loss/duplication.
#[tokio::test]
async fn query_next_paginates_all_data_sets() {
    let (_tester, _nm, session) = setup().await;

    // Ground truth: total FolderType nodes in one big batch.
    let total: usize = session
        .query_first(
            ViewDescription::default(),
            vec![browse_name_of_type(ObjectTypeId::FolderType, true)],
            ContentFilter::default(),
            1000,
            0,
        )
        .await
        .unwrap()
        .query_data_sets
        .map(|v| v.len())
        .unwrap_or(0);
    assert!(total > 5, "need a multi-batch-worth of nodes, got {total}");

    // Page in small batches and collect all node ids.
    let first = session
        .query_first(
            ViewDescription::default(),
            vec![browse_name_of_type(ObjectTypeId::FolderType, true)],
            ContentFilter::default(),
            5,
            0,
        )
        .await
        .unwrap();
    assert_eq!(first.response_header.service_result, StatusCode::Good);

    let mut ids: Vec<ExpandedNodeId> = first
        .query_data_sets
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.node_id)
        .collect();
    let mut cp = first.continuation_point.clone();
    assert!(!cp.is_null(), "a result larger than the batch must page");

    let mut guard = 0;
    while !cp.is_null() {
        guard += 1;
        assert!(guard < 100, "pagination did not terminate");
        let next = session.query_next(false, cp.clone()).await.unwrap();
        ids.extend(
            next.query_data_sets
                .unwrap_or_default()
                .into_iter()
                .map(|d| d.node_id),
        );
        cp = next.revised_continuation_point.clone();
    }

    assert_eq!(
        ids.len(),
        total,
        "pagination must return every data set exactly once"
    );
    let mut seen = std::collections::HashSet::new();
    for id in &ids {
        assert!(
            seen.insert(id.clone()),
            "duplicate node id across pages: {id:?}"
        );
    }
}

/// QueryNext with the release flag frees the continuation point; reusing it fails.
#[tokio::test]
async fn query_next_release_frees_continuation_point() {
    let (_tester, _nm, session) = setup().await;
    let first = session
        .query_first(
            ViewDescription::default(),
            vec![browse_name_of_type(ObjectTypeId::FolderType, true)],
            ContentFilter::default(),
            5,
            0,
        )
        .await
        .unwrap();
    let cp = first.continuation_point.clone();
    assert!(!cp.is_null());

    // Release the (fresh, valid) continuation point -> Good, no data (Part 4 §5.9.4).
    let released = session.query_next(true, cp.clone()).await.unwrap();
    assert_eq!(released.response_header.service_result, StatusCode::Good);
    assert!(released
        .query_data_sets
        .map(|v| v.is_empty())
        .unwrap_or(true));

    // Reusing the released continuation point must fail cleanly.
    let reused = session.query_next(false, cp).await;
    let status = reused
        .map(|r| r.response_header.service_result)
        .unwrap_or_else(|e| e.status());
    assert_eq!(status, StatusCode::BadContinuationPointInvalid);
}

/// A query that matches nothing is handled cleanly (no panic) — record the actual status.
#[tokio::test]
async fn query_invalid_type_definition_is_rejected() {
    // P4-QUERY-01 — OPC UA Part 4 Annex B Table B.6: a typeDefinitionNode that is not a valid
    // TypeDefinitionNode must be reported (Bad_NotTypeDefinition in parsingResults, surfaced as a
    // Bad_InvalidArgument service result) rather than silently treated as a no-match. Spec-anchored.
    let (_tester, _nm, session) = setup().await;
    // NodeId 0:999_999 is not a type definition node.
    let bogus = NodeTypeDescription {
        type_definition_node: NodeId::new(0, 999_999u32).into(),
        include_sub_types: false,
        data_to_return: Some(vec![QueryDataDescription {
            relative_path: RelativePath::default(),
            attribute_id: AttributeId::BrowseName as u32,
            index_range: NumericRange::default(),
        }]),
    };
    let e = session
        .query_first(
            ViewDescription::default(),
            vec![bogus],
            ContentFilter::default(),
            1000,
            0,
        )
        .await
        .unwrap_err();
    assert_eq!(e.status(), opcua::types::StatusCode::BadInvalidArgument);
}

/// A non-default / unknown view — record the actual handler behavior (the backlog's BadViewIdUnknown
/// claim is verified here, not assumed).
#[tokio::test]
async fn query_non_default_view_behavior() {
    let (_tester, _nm, session) = setup().await;
    let view = ViewDescription {
        view_id: NodeId::new(0, 999_999u32),
        timestamp: Default::default(),
        view_version: 0,
    };
    // Observed: the server rejects an unknown view with BadViewIdUnknown (surfaced as a service fault
    // → the client maps it to an Err). No panic/hang.
    let result = session
        .query_first(
            view,
            vec![browse_name_of_type(ObjectTypeId::FolderType, true)],
            ContentFilter::default(),
            1000,
            0,
        )
        .await;
    let status = result
        .map(|r| r.response_header.service_result)
        .unwrap_or_else(|e| e.status());
    assert_eq!(status, StatusCode::BadViewIdUnknown);
}
