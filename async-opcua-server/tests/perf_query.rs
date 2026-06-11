//! Performance tests for SC-004 query latency over a 100k-node address space.

use std::time::{Duration, Instant};

use opcua_nodes::{DefaultTypeTree, ParsedContentFilter};
use opcua_server::{
    address_space::{AddressSpace, ObjectBuilder, ObjectTypeBuilder},
    services::query::traversal::QueryGraphTraversal,
};
use opcua_types::{
    BrowseDirection, ContentFilter, ContentFilterElement, FilterOperator, NodeId, ObjectId,
    ObjectTypeId, Operand, QualifiedName, ReferenceTypeId, StatusCode,
};

const PERF_QUERY_NAMESPACE_URI: &str = "urn:async-opcua:perf-query:nodes";
const PERF_QUERY_NAMESPACE_INDEX: u16 = 1;
const QUERY_NODE_COUNT: usize = 100_000;
const QUERY_LATENCY_BUDGET: Duration = Duration::from_millis(100);
const QUERY_LOAD_REQUESTS: usize = 20;

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "SC-004 query latency budget is measured in release mode"
)]
fn related_to_query_scan_over_100k_nodes_median_stays_under_100ms() {
    let fixture = PerfQueryFixture::new();
    let filter = fixture.related_to_filter();

    assert!(
        scan_related_to_query(&fixture, &filter).is_none(),
        "warmup no-match query should scan all nodes without returning a result"
    );

    let mut samples = Vec::with_capacity(QUERY_LOAD_REQUESTS);
    for _ in 0..QUERY_LOAD_REQUESTS {
        let started = Instant::now();
        let result = scan_related_to_query(&fixture, &filter);
        let elapsed = started.elapsed();
        assert!(result.is_none(), "no-match query should return no result");
        samples.push(elapsed);
    }
    samples.sort_unstable();

    let p95_index = (samples.len() * 95).div_ceil(100).saturating_sub(1);
    let median = samples[samples.len() / 2];
    let p95 = samples[p95_index];
    let max = samples[samples.len() - 1];

    assert!(
        median < QUERY_LATENCY_BUDGET,
        "SC-004 RelatedTo traversal median latency over {QUERY_NODE_COUNT} nodes exceeded {QUERY_LATENCY_BUDGET:?}; median={median:?}, p95={p95:?}, max={max:?}, samples={samples:?}"
    );
}

struct PerfQueryFixture {
    address_space: AddressSpace,
    type_tree: DefaultTypeTree,
    vessel_type: NodeId,
    controller_type: NodeId,
}

impl PerfQueryFixture {
    fn new() -> Self {
        let mut address_space = AddressSpace::new();
        address_space.add_namespace(PERF_QUERY_NAMESPACE_URI, PERF_QUERY_NAMESPACE_INDEX);

        let vessel_type = NodeId::new(PERF_QUERY_NAMESPACE_INDEX, "VesselType");
        let controller_type = NodeId::new(PERF_QUERY_NAMESPACE_INDEX, "ControllerType");
        add_perf_query_types(&mut address_space, &vessel_type, &controller_type);

        for index in 0..QUERY_NODE_COUNT {
            add_vessel(&mut address_space, &vessel_type, index);
        }

        let mut type_tree = DefaultTypeTree::new();
        type_tree
            .namespaces_mut()
            .add_namespace(PERF_QUERY_NAMESPACE_URI);
        address_space.load_into_type_tree(&mut type_tree);

        Self {
            address_space,
            type_tree,
            vessel_type,
            controller_type,
        }
    }

    fn related_to_filter(&self) -> ParsedContentFilter {
        let (result, parsed) = ParsedContentFilter::parse(
            related_to_filter(&self.vessel_type, &self.controller_type),
            &self.type_tree,
            false,
            &[],
        );
        assert_eq!(
            result.element_results.expect("element results")[0].status_code,
            StatusCode::Good
        );
        parsed.expect("RelatedTo filter should parse")
    }
}

fn scan_related_to_query(
    fixture: &PerfQueryFixture,
    filter: &ParsedContentFilter,
) -> Option<NodeId> {
    let candidates = fixture
        .address_space
        .find_references(
            &fixture.vessel_type,
            Some((ReferenceTypeId::HasTypeDefinition, false)),
            &fixture.type_tree,
            BrowseDirection::Inverse,
        )
        .filter_map(|reference| {
            if fixture.address_space.node_exists(reference.target_node) {
                Some(reference.target_node.clone())
            } else {
                None
            }
        });

    QueryGraphTraversal::with_typed_candidates(
        &fixture.address_space,
        &fixture.type_tree,
        &fixture.vessel_type,
        filter,
        candidates,
    )
    .next()
}

fn add_perf_query_types(
    address_space: &mut AddressSpace,
    vessel_type: &NodeId,
    controller_type: &NodeId,
) {
    ObjectTypeBuilder::new(
        vessel_type,
        QualifiedName::new(PERF_QUERY_NAMESPACE_INDEX, "VesselType"),
        "VesselType",
    )
    .subtype_of(ObjectTypeId::BaseObjectType)
    .insert(address_space);

    ObjectTypeBuilder::new(
        controller_type,
        QualifiedName::new(PERF_QUERY_NAMESPACE_INDEX, "ControllerType"),
        "ControllerType",
    )
    .subtype_of(ObjectTypeId::BaseObjectType)
    .insert(address_space);
}

fn add_vessel(address_space: &mut AddressSpace, vessel_type: &NodeId, index: usize) {
    let vessel_name = vessel_node_name(index);
    let vessel_id = NodeId::new(PERF_QUERY_NAMESPACE_INDEX, vessel_name.as_str());

    ObjectBuilder::new(
        &vessel_id,
        QualifiedName::new(PERF_QUERY_NAMESPACE_INDEX, vessel_name.as_str()),
        vessel_name.as_str(),
    )
    .has_type_definition(vessel_type.clone())
    .organized_by(ObjectId::ObjectsFolder)
    .insert(address_space);
}

fn related_to_filter(vessel_type: &NodeId, controller_type: &NodeId) -> ContentFilter {
    ContentFilter {
        elements: Some(vec![ContentFilterElement::from((
            FilterOperator::RelatedTo,
            vec![
                Operand::literal(vessel_type.clone()),
                Operand::literal(controller_type.clone()),
                Operand::literal(NodeId::from(ReferenceTypeId::HasComponent)),
                Operand::literal(1u32),
                Operand::literal(false),
                Operand::literal(false),
            ],
        ))]),
    }
}

fn vessel_node_name(index: usize) -> String {
    format!("Vessel-{index:06}")
}
