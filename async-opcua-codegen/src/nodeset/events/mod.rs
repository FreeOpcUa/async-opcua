//! Codegen for generating event types, which all implement the `Event` trait,
//! making it possible to publish them in a server.

use std::collections::HashMap;

use collector::{NodeToCollect, TypeCollector};
use gen::{EventGenerator, EventItem};
use opcua_xml::schema::ua_node_set::UANodeSet;
use syn::Item;

use crate::{base_native_type_mappings, CodeGenError, GeneratedOutput, BASE_NAMESPACE};

mod collector;
mod gen;

pub fn generate_events(nodesets: &[(&UANodeSet, &str)]) -> Result<Vec<EventItem>, CodeGenError> {
    let mut pairs = Vec::new();
    let mut namespaces = Vec::new();
    namespaces.push(BASE_NAMESPACE.to_owned());
    for (idx, (nodeset, import_path)) in nodesets.iter().enumerate() {
        let aliases: HashMap<_, _> = nodeset
            .aliases
            .iter()
            .flat_map(|a| a.aliases.iter())
            .map(|v| (v.alias.as_str(), v.id.0.as_str()))
            .collect();
        pairs.push((*nodeset, aliases, idx, import_path));
        for ns in nodeset
            .namespace_uris
            .as_ref()
            .iter()
            .flat_map(|f| f.uris.iter())
        {
            if !namespaces.iter().any(|n| n == ns) {
                namespaces.push(ns.clone());
            }
        }
    }

    let iter = pairs.iter().flat_map(|p| {
        p.0.nodes.iter().map(|n| NodeToCollect {
            node: n,
            aliases: &p.1,
            nodeset_index: p.2,
            import_path: p.3,
        })
    });

    let coll = TypeCollector::new(iter);
    let collected = coll.collect_types()?;

    let gen = EventGenerator::new(
        collected,
        &namespaces,
        base_native_type_mappings(),
        nodesets.len() - 1,
    );
    let items = gen.render()?;
    Ok(items)
}

impl GeneratedOutput for EventItem {
    fn module(&self) -> &str {
        "generated"
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn to_file(self) -> syn::File {
        syn::File {
            shebang: None,
            attrs: Vec::new(),
            items: vec![Item::Struct(self.def)],
        }
    }
}
