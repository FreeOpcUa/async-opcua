//! Code generation for nodesets.
//!
//! This generates rust code that can create nodes in an OPC UA server
//! from NodeSet2 XML files. Each node becomes a function that takes some
//! general server context and returns a node. These are chained together
//! into a large static iterator that can be used as a node set source.

mod events;
mod gen;
mod value;

use std::collections::HashMap;

pub use events::generate_events;
pub use gen::{NodeGenMethod, NodeSetCodeGenerator};
use opcua_xml::schema::xml_schema::{XsdFileItem, XsdFileType};
use proc_macro2::Span;
use quote::quote;
use serde::{Deserialize, Serialize};
use syn::{parse_quote, parse_str, File, Ident, Item, ItemFn, Path};
use tracing::info;

use crate::{
    input::{NodeSetInput, SchemaCache},
    CodeGenError, GeneratedOutput,
};

/// An imported XSD file type, with the rust path to import it from.
pub struct XsdTypeWithPath {
    pub ty: XsdFileType,
    pub path: Path,
}

#[derive(Serialize, Deserialize, Debug, Default)]
/// A nodeset XML file to load types from.
pub struct NodeSetTypes {
    /// Reference to the schema in the inputs list.
    pub file: String,
    /// Rust path to import these types from.
    pub root_path: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
/// Configuration for generating nodes from a NodeSet2 XML file.
pub struct NodeSetCodeGenTarget {
    /// A reference to the input schema, which must be defined in the `inputs` list.
    pub file: String,
    /// The root path to output generated code to.
    pub output_dir: String,
    /// Maximum number of nodes per generated file.
    /// Setting this too high or low can impact compile times.
    pub max_nodes_per_file: usize,
    /// List of XML schema files to load types from.
    pub types: Vec<NodeSetTypes>,
    /// The name of the generated module.
    pub name: String,
    #[serde(default)]
    /// Extra header to add to each generated file.
    pub extra_header: String,
    /// Optional generation of event types from the nodeset.
    pub events: Option<EventsTarget>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
/// A nodeset that the events target depends on.
pub struct DependentNodeset {
    /// Reference to the schema in the inputs list.
    pub file: String,
    /// Path to import these events from.
    pub import_path: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct EventsTarget {
    /// A reference to the input schema, which must be defined in the `inputs` list.
    pub output_dir: String,
    #[serde(default)]
    pub extra_header: String,
    #[serde(default)]
    pub dependent_nodesets: Vec<DependentNodeset>,
}

/// Create a map of type name to type definition from the given codegen target.
fn make_type_dict(
    target: &NodeSetCodeGenTarget,
    cache: &SchemaCache,
) -> Result<HashMap<String, XsdTypeWithPath>, CodeGenError> {
    let mut res = HashMap::new();
    for file in &target.types {
        let xsd_file = cache.get_xml_schema(&file.file)?;
        let path: Path = parse_str(&file.root_path)?;

        for it in &xsd_file.xml.items {
            let (ty, name) = match it {
                XsdFileItem::SimpleType(i) => {
                    if let Some(name) = i.name.clone() {
                        (XsdFileType::Simple(Box::new(i.clone())), name)
                    } else {
                        continue;
                    }
                }
                XsdFileItem::ComplexType(i) => {
                    if let Some(name) = i.name.clone() {
                        (XsdFileType::Complex(Box::new(i.clone())), name)
                    } else {
                        continue;
                    }
                }
                XsdFileItem::Element(_) => continue,
            };
            res.insert(
                name,
                XsdTypeWithPath {
                    ty,
                    path: path.clone(),
                },
            );
        }
    }
    Ok(res)
}

/// A chunk of generated node creation functions, to be output as a single file.
pub struct NodeSetChunk {
    pub root_fun: ItemFn,
    pub items: Vec<ItemFn>,
    pub name: String,
}

impl GeneratedOutput for NodeSetChunk {
    fn to_file(self) -> syn::File {
        let mut fns = Vec::new();
        fns.push(self.root_fun);
        fns.extend(self.items);

        syn::File {
            shebang: None,
            attrs: Vec::new(),
            items: fns.into_iter().map(Item::Fn).collect(),
        }
    }

    fn module(&self) -> &str {
        &self.name
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// Create the root function that returns an iterator over all the node node creation functions
/// in a chunk. The iterator is boxed, but it is in practice just a static array of function pointers.
pub fn make_root_fun(chunk: &[NodeGenMethod]) -> ItemFn {
    let mut names = chunk.iter().map(|c| Ident::new(&c.name, Span::call_site()));

    // Create a list of the functions, but as &dyn Fn, to make it easy to make an iterator.
    // Also return the value as a boxed dyn iterator, by doing it this way we don't get an
    // enormous type signature on the final iterator,
    // and the runtime cost of a little indirection is so small it doesn't matter.
    let first = names.next().unwrap();
    parse_quote! {
        pub(super) fn imported_nodes<'a>(ns_map: &'a opcua::nodes::NodeSetNamespaceMapper<'_>) -> Box<dyn Iterator<
            Item = opcua::nodes::ImportedItem
        > + 'a> {
            Box::new([
                &#first as &dyn Fn(_) -> opcua::nodes::ImportedItem,
                #(&#names),*
            ].into_iter().map(|f| f(ns_map)))
        }
    }
}

/// Generate the target code for a nodeset codegen target.
pub fn generate_target(
    config: &NodeSetCodeGenTarget,
    input: &NodeSetInput,
    preferred_locale: &str,
    cache: &SchemaCache,
) -> Result<Vec<NodeSetChunk>, CodeGenError> {
    let types = make_type_dict(config, cache)?;
    let type_info = input.get_type_names()?;

    let mut generator =
        NodeSetCodeGenerator::new(preferred_locale, &input.aliases, types, type_info)?;

    let mut fns = Vec::with_capacity(input.xml.nodes.len());
    for node in &input.xml.nodes {
        fns.push(
            generator
                .generate_item(node)
                .map_err(|e| e.in_file(&config.file))?,
        );
    }
    // We sort output functions by name to get a stable output.
    fns.sort_by(|a, b| a.name.cmp(&b.name));
    info!("Generated {} node creation methods", fns.len());

    let iter = fns.into_iter();

    let mut outputs = Vec::new();
    let mut chunk = Vec::new();
    for it in iter {
        chunk.push(it);
        if chunk.len() == config.max_nodes_per_file {
            outputs.push(NodeSetChunk {
                root_fun: make_root_fun(&chunk),
                items: chunk.into_iter().map(|c| c.func).collect(),
                name: format!("nodeset_{}", outputs.len() + 1),
            });
            chunk = Vec::new();
        }
    }

    if !chunk.is_empty() {
        outputs.push(NodeSetChunk {
            root_fun: make_root_fun(&chunk),
            items: chunk.into_iter().map(|c| c.func).collect(),
            name: format!("nodeset_{}", outputs.len() + 1),
        });
    }

    Ok(outputs)
}

/// Create the top level root module that creates a flattened iterator
/// incorporating all the chunk-level iterators from before.
pub fn make_root_module(
    chunks: &[NodeSetChunk],
    config: &NodeSetCodeGenTarget,
    input: &NodeSetInput,
) -> Result<File, CodeGenError> {
    let mut items: Vec<Item> = Vec::new();
    let mut names = Vec::new();
    for chunk in chunks {
        let ident = Ident::new(&chunk.name, Span::call_site());
        names.push(ident.clone());
        items.push(parse_quote! {
            mod #ident;
        });
    }

    let name_ident = Ident::new(&config.name, Span::call_site());

    items.push(parse_quote! {
        pub struct #name_ident;
    });

    let mut namespace_adds = quote! {};
    for (idx, ns) in input.namespaces.iter().enumerate() {
        let idx = idx as u16;
        namespace_adds.extend(quote! {
            map.add_namespace(#ns, #idx);
        });
    }

    let own_ns = &input.uri;
    let namespace_out = quote! {
        #own_ns.to_owned(),
    };

    items.push(parse_quote! {
        impl opcua::nodes::NodeSetImport for #name_ident {
            fn load<'a>(&'a self, map: &'a opcua::nodes::NodeSetNamespaceMapper) -> Box<dyn Iterator<Item = opcua::nodes::ImportedItem> + 'a> {
                Box::new([
                    #(#names::imported_nodes(map)),*
                ].into_iter().flatten())
            }

            fn register_namespaces(&self, map: &mut opcua::nodes::NodeSetNamespaceMapper) {
                #namespace_adds
            }

            fn get_own_namespaces(&self) -> Vec<String> {
                vec![#namespace_out]
            }
        }
    });

    Ok(File {
        attrs: Vec::new(),
        shebang: None,
        items,
    })
}
