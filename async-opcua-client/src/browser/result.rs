use futures::{Stream, TryStreamExt};
use hashbrown::HashMap;
use opcua_nodes::References;
use opcua_types::{Error, ExpandedNodeId, LocalizedText, NodeClass, NodeId, QualifiedName};

use super::BrowseResultItem;

/// Simple description of a node discovered when browsing.
#[derive(Debug)]
pub struct NodeDescription {
    /// Node class.
    pub node_class: NodeClass,
    /// Node type definition.
    pub type_definition: ExpandedNodeId,
    /// Node display name.
    pub display_name: LocalizedText,
    /// Node browse name.
    pub browse_name: QualifiedName,
}

#[derive(Debug, Default)]
/// Collected result of a browse operation.
pub struct BrowserResult {
    /// Reference map.
    pub references: References,
    /// Discovered nodes.
    pub nodes: HashMap<NodeId, NodeDescription>,
}

impl BrowserResult {
    fn new() -> Self {
        Self::default()
    }

    pub(super) async fn build_from_browser<T: Stream<Item = Result<BrowseResultItem, Error>>>(
        stream: T,
    ) -> Result<Self, Error> {
        let mut res = Self::new();

        futures::pin_mut!(stream);
        while let Some(d) = stream.try_next().await? {
            let (parent_id, refs) = d.into_results();
            for r in refs {
                res.references.insert_reference(
                    &parent_id,
                    &r.node_id.node_id,
                    r.reference_type_id,
                );

                res.nodes
                    .entry(r.node_id.node_id)
                    .or_insert_with(|| NodeDescription {
                        node_class: r.node_class,
                        type_definition: r.type_definition,
                        display_name: r.display_name,
                        browse_name: r.browse_name,
                    });
            }
        }

        Ok(res)
    }
}
