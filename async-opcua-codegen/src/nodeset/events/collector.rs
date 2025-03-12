use std::collections::HashMap;

use opcua_xml::schema::ua_node_set::UANode;

use crate::{utils::split_qualified_name, CodeGenError};

#[derive(Debug, Clone)]
pub enum FieldKind<'a> {
    Object(&'a str),
    Variable(&'a str),
    Method,
}

#[derive(Debug, Clone)]
pub struct CollectedField<'a> {
    pub type_id: FieldKind<'a>,
    pub data_type_id: Option<&'a str>,
    pub placeholder: bool,
}

#[derive(Debug, Copy, Clone)]
#[allow(clippy::enum_variant_names)] // Enum variants are partially OPC-UA nodeclasses.
pub enum TypeKind {
    EventType,
    ObjectType,
    VariableType,
    DataType,
    ReferenceType,
}

#[derive(Debug, Clone)]
pub struct CollectedType<'a> {
    pub parent: Option<&'a str>,
    pub name: &'a str,
    pub data_type_id: Option<&'a str>,
    /// References to other types, each field of an event should itself be a remote type.
    pub fields: HashMap<&'a str, CollectedField<'a>>,
    pub kind: TypeKind,
    pub nodeset_index: usize,
    pub import_path: &'a str,
    pub is_abstract: bool,
}

pub struct TypeCollector<'a> {
    nodes: HashMap<String, NodeToCollect<'a>>,
    references: References<'a>,
}

#[derive(Clone, Copy, Debug)]
pub struct Reference<'a> {
    pub source: &'a str,
    pub target: &'a str,
    pub type_id: &'a str,
}

pub struct References<'a> {
    pub by_source: HashMap<&'a str, Vec<Reference<'a>>>,
    #[allow(unused)]
    pub by_target: HashMap<&'a str, Vec<Reference<'a>>>,
}

impl<'a> References<'a> {
    pub fn new(nodes: impl Iterator<Item = NodeToCollect<'a>>) -> Self {
        let mut by_source: HashMap<_, Vec<_>> = HashMap::new();
        let mut by_target: HashMap<_, Vec<_>> = HashMap::new();
        for node in nodes {
            for rf in node
                .node
                .base()
                .references
                .as_ref()
                .iter()
                .flat_map(|f| f.references.iter())
            {
                let reference = if rf.is_forward {
                    Reference {
                        source: &node.node.base().node_id.0,
                        target: &rf.node_id.0,
                        type_id: &rf.reference_type.0,
                    }
                } else {
                    Reference {
                        source: &rf.node_id.0,
                        target: &node.node.base().node_id.0,
                        type_id: &rf.reference_type.0,
                    }
                };
                by_source
                    .entry(reference.source)
                    .or_default()
                    .push(reference);

                by_target
                    .entry(reference.target)
                    .or_default()
                    .push(reference);
            }
        }

        Self {
            by_source,
            by_target,
        }
    }
}

#[derive(Clone, Copy)]
pub struct NodeToCollect<'a> {
    pub node: &'a UANode,
    pub aliases: &'a HashMap<&'a str, &'a str>,
    pub nodeset_index: usize,
    pub import_path: &'a str,
}

impl<'a> NodeToCollect<'a> {
    fn lookup_node_id(&self, key: &'a str) -> &'a str {
        if let Some(aliased) = self.aliases.get(key) {
            aliased
        } else {
            key
        }
    }
}

impl<'a> TypeCollector<'a> {
    pub fn new(nodes: impl Iterator<Item = NodeToCollect<'a>>) -> Self {
        let nodes_map: HashMap<_, _> = nodes
            .map(|n| (n.node.base().node_id.0.to_owned(), n))
            .collect();
        let references = References::new(nodes_map.values().copied());

        Self {
            nodes: nodes_map,
            references,
        }
    }

    pub fn collect_types(&self) -> Result<HashMap<&'a str, CollectedType<'a>>, CodeGenError> {
        let mut result = HashMap::new();

        self.collect_type(&mut result, "i=58", None, TypeKind::ObjectType)?;
        self.collect_type(&mut result, "i=62", None, TypeKind::VariableType)?;
        self.collect_type(&mut result, "i=24", None, TypeKind::DataType)?;
        self.collect_type(&mut result, "i=31", None, TypeKind::ReferenceType)?;

        Ok(result)
    }

    fn is_hierarchical_ref_type(&self, ty: &str, ctx: NodeToCollect<'a>) -> bool {
        if ty == "i=33" {
            return true;
        }
        let Some(parent_ref) = self
            .references
            .by_target
            .get(ty)
            .and_then(|m| m.iter().find(|f| ctx.lookup_node_id(f.type_id) == "i=45"))
        else {
            return false;
        };
        self.is_hierarchical_ref_type(parent_ref.source, ctx)
    }

    fn collect_type(
        &self,
        collected: &mut HashMap<&'a str, CollectedType<'a>>,
        type_id: &'a str,
        parent: Option<&'a str>,
        kind: TypeKind,
    ) -> Result<(), CodeGenError> {
        // Type must exist, otherwise it's going to cause trouble.
        let Some(node) = self.nodes.get(type_id) else {
            return Err(CodeGenError::other(format!(
                "Referenced type with id {type_id} not found."
            )));
        };

        let kind = if type_id == "i=2041" {
            TypeKind::EventType
        } else {
            kind
        };

        let mut fields = HashMap::new();

        for rf in self
            .references
            .by_source
            .get(type_id)
            .iter()
            .flat_map(|f| f.iter())
        {
            let rf_type_id = node.lookup_node_id(rf.type_id);
            match rf_type_id {
                // HasSubtype
                "i=45" => {
                    self.collect_type(
                        collected,
                        node.lookup_node_id(rf.target),
                        Some(type_id),
                        kind,
                    )?;
                }

                r if self.is_hierarchical_ref_type(r, *node) => {
                    let mut is_placeholder = false;
                    let mut type_def: Option<&'a str> = None;
                    let mut data_type_id: Option<&'a str> = None;
                    let target = node.lookup_node_id(rf.target);
                    for crf in self
                        .references
                        .by_source
                        .get(target)
                        .iter()
                        .flat_map(|f| f.iter())
                    {
                        let crf_type_id = node.lookup_node_id(crf.type_id);
                        if crf_type_id == "i=37" {
                            let ctarget = node.lookup_node_id(crf.target);
                            // Is the modelling rule equal to OptionalPlaceholder or
                            // MandatoryPlaceholder
                            is_placeholder = matches!(ctarget, "i=11508" | "i=11510");
                        } else if crf_type_id == "i=40" {
                            let ctarget = node.lookup_node_id(crf.target);
                            // Type definition
                            type_def = Some(node.lookup_node_id(ctarget));
                        }
                    }

                    let Some(target_node) = self.nodes.get(target) else {
                        return Err(CodeGenError::other(format!(
                            "Node {target} not found in node dict"
                        ))
                        .with_context(format!("collecting type {type_id}")));
                    };

                    let kind = match &target_node.node {
                        UANode::Object(_) => {
                            let Some(type_def) = type_def else {
                                return Err(CodeGenError::other(format!(
                                    "Property {target} is missing type definition"
                                ))
                                .with_context(format!("collecting type {type_id}")));
                            };
                            FieldKind::Object(type_def)
                        }
                        UANode::Variable(v) => {
                            let Some(type_def) = type_def else {
                                return Err(CodeGenError::other(format!(
                                    "Property {target} is missing type definition"
                                ))
                                .with_context(format!("collecting type {type_id}")));
                            };
                            data_type_id = Some(target_node.lookup_node_id(v.data_type.0.as_str()));
                            FieldKind::Variable(type_def)
                        }
                        UANode::Method(_) => FieldKind::Method,
                        _ => {
                            return Err(CodeGenError::other(format!(
                                "Property {target} has unexpected node class"
                            ))
                            .with_context(format!("collecting type {type_id}")))
                        }
                    };

                    let browse_name = target_node.node.base().browse_name.0.as_str();
                    let (name, _) = split_qualified_name(browse_name)
                        .map_err(|e| e.with_context(format!("collecting type {type_id}")))?;

                    fields.insert(
                        name,
                        CollectedField {
                            placeholder: is_placeholder,
                            type_id: kind,
                            data_type_id,
                        },
                    );
                }

                _ => (),
            }
        }

        let data_type_id = if let UANode::VariableType(v) = node.node {
            Some(node.lookup_node_id(&v.data_type.0))
        } else {
            None
        };

        collected.insert(
            node.node.base().node_id.0.as_str(),
            CollectedType {
                parent,
                fields,
                kind,
                name: split_qualified_name(&node.node.base().browse_name.0)?.0,
                data_type_id,
                nodeset_index: node.nodeset_index,
                import_path: node.import_path,
                is_abstract: match &node.node {
                    UANode::ObjectType(d) => d.base.is_abstract,
                    UANode::VariableType(d) => d.base.is_abstract,
                    UANode::DataType(d) => d.base.is_abstract,
                    UANode::ReferenceType(d) => d.base.is_abstract,
                    _ => false,
                },
            },
        );

        Ok(())
    }
}
