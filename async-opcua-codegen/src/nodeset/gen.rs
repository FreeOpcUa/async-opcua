use std::collections::HashMap;

use opcua_xml::schema::ua_node_set::{
    ArrayDimensions, DataTypeDefinition, LocalizedText, NodeId, Reference, UADataType, UAMethod,
    UANode, UANodeBase, UAObject, UAObjectType, UAReferenceType, UAVariable, UAVariableType,
    UAView,
};
use proc_macro2::{Span, TokenStream};
use syn::{parse_quote, parse_str, Expr, Ident, ItemFn};

use crate::{utils::RenderExpr, CodeGenError};

use super::{value::render_value, XsdTypeWithPath};

use quote::quote;

pub struct NodeGenMethod {
    pub func: ItemFn,
    pub name: String,
}

pub struct NodeSetCodeGenerator<'a> {
    preferred_locale: String,
    empty_text: LocalizedText,
    aliases: &'a HashMap<String, String>,
    node_counter: usize,
    types: HashMap<String, XsdTypeWithPath>,
}

impl<'a> NodeSetCodeGenerator<'a> {
    pub fn new(
        preferred_locale: &str,
        aliases: &'a HashMap<String, String>,
        types: HashMap<String, XsdTypeWithPath>,
    ) -> Result<Self, CodeGenError> {
        Ok(Self {
            preferred_locale: preferred_locale.to_owned(),
            empty_text: LocalizedText::default(),
            aliases,
            node_counter: 0,
            types,
        })
    }

    fn resolve_node_id(&self, node_id: &NodeId) -> Result<TokenStream, CodeGenError> {
        if let Some(aliased) = self.aliases.get(node_id.0.as_str()) {
            NodeId(aliased.to_owned()).render()
        } else {
            node_id.render()
        }
    }

    fn get_localized_text<'c: 'b, 'b>(&'c self, options: &'b [LocalizedText]) -> &'b LocalizedText {
        options
            .iter()
            .find(|f| f.locale.0 == self.preferred_locale)
            .or_else(|| options.first())
            .unwrap_or(&self.empty_text)
    }

    fn get_localized_text_opt<'c: 'b, 'b>(
        &'c self,
        options: &'b [LocalizedText],
    ) -> Option<&'b LocalizedText> {
        options
            .iter()
            .find(|f| f.locale.0 == self.preferred_locale)
            .or_else(|| options.first())
    }

    fn render_data_type_definition(
        &self,
        def: &DataTypeDefinition,
    ) -> Result<TokenStream, CodeGenError> {
        let is_enum = def.fields.first().is_some_and(|f| f.value != -1);
        if is_enum {
            self.render_enum_def(def)
        } else {
            self.render_structure_def(def)
        }
    }

    fn render_enum_def(&self, def: &DataTypeDefinition) -> Result<TokenStream, CodeGenError> {
        let mut fields = quote! {};
        for f in &def.fields {
            let value = f.value;
            let display_name = self
                .get_localized_text(&f.display_names)
                .render()
                .map_err(|e| {
                    e.with_context(format!(
                        "rendering field {} in enum definition {}",
                        f.name, def.name.0
                    ))
                })?;
            let description = self
                .get_localized_text(&f.descriptions)
                .render()
                .map_err(|e| {
                    e.with_context(format!(
                        "rendering field {} in enum definition {}",
                        f.name, def.name.0
                    ))
                })?;
            let name = &f.name;
            fields.extend(quote! {
                opcua::types::EnumField {
                    value: #value,
                    display_name: #display_name,
                    description: #description,
                    name: #name.into(),
                },
            });
        }

        Ok(quote! {
            opcua::types::EnumDefinition {
                fields: Some(vec![#fields])
            }
        })
    }

    fn render_structure_def(&self, def: &DataTypeDefinition) -> Result<TokenStream, CodeGenError> {
        let mut fields = quote! {};
        let mut any_optional = false;
        for f in &def.fields {
            let description = self
                .get_localized_text(&f.descriptions)
                .render()
                .map_err(|e| {
                    e.with_context(format!(
                        "rendering field {} in structure definition {}",
                        f.name, def.name.0
                    ))
                })?;
            let name = &f.name;
            let data_type = self.resolve_node_id(&f.data_type).map_err(|e| {
                e.with_context(format!(
                    "rendering field {} in structure definition {}",
                    f.name, def.name.0
                ))
            })?;
            let value_rank = f.value_rank.0;
            let array_dimensions = self
                .parse_array_dimensions(&f.array_dimensions)
                .map_err(|e| {
                    e.with_context(format!(
                        "rendering field {} in structure definition {}",
                        f.name, def.name.0
                    ))
                })?
                .as_ref()
                .render()
                .map_err(|e| {
                    e.with_context(format!(
                        "rendering field {} in structure definition {}",
                        f.name, def.name.0
                    ))
                })?;
            let max_string_length = f.max_string_length as u32;
            let is_optional = f.is_optional;
            any_optional |= is_optional;
            fields.extend(quote! {
                opcua::types::StructureField {
                    name: #name.into(),
                    description: #description,
                    data_type: #data_type,
                    value_rank: #value_rank,
                    array_dimensions: #array_dimensions,
                    max_string_length: #max_string_length,
                    is_optional: #is_optional,
                },
            });
        }
        // TODO: Try to get the default encoding ID by looking at the available nodes.
        let structure_type = Ident::new(
            if def.is_union {
                "Union"
            } else if any_optional {
                "StructureWithOptionalFields"
            } else {
                "Structure"
            },
            Span::call_site(),
        );
        Ok(quote! {
            opcua::types::StructureDefinition {
                fields: Some(vec![#fields]),
                default_encoding_id: opcua::types::NodeId::null(),
                base_data_type: opcua::types::NodeId::null(),
                structure_type: opcua::types::StructureType::#structure_type,
            }
        })
    }

    fn parse_array_dimensions(
        &self,
        dims: &ArrayDimensions,
    ) -> Result<Option<Vec<u32>>, CodeGenError> {
        if dims.0.trim().is_empty() {
            return Ok(None);
        }

        let mut values = Vec::with_capacity(1);
        for it in dims.0.split(',') {
            values.push(it.trim().parse::<u32>().map_err(|_| {
                CodeGenError::other(format!("Invalid array dimensions: {}", dims.0))
            })?);
        }

        Ok(Some(values))
    }

    fn generate_base(&self, node: &UANodeBase, node_class: &str) -> Result<Expr, CodeGenError> {
        let name = self.get_localized_text(&node.display_names).render()?;
        let description = self.get_localized_text_opt(&node.description).render()?;
        let browse_name = node.browse_name.render()?;
        let node_class: Expr = syn::parse_str(&format!("opcua::types::NodeClass::{node_class}"))?;
        let write_mask = node.write_mask.0;
        let user_write_mask = node.user_write_mask.0;
        let node_id = self.resolve_node_id(&node.node_id)?;

        Ok(parse_quote! {
            opcua::nodes::Base::new_full(
                #node_id, #node_class, #browse_name, #name, #description,
                Some(#write_mask), Some(#user_write_mask)
            )
        })
    }

    fn generate_object(&self, node: &UAObject) -> Result<Expr, CodeGenError> {
        let base = self.generate_base(&node.base.base, "Object")?;
        let event_notifier = node.event_notifier.0;
        Ok(parse_quote! {
            opcua::nodes::Object::new_full(
                #base,
                opcua::nodes::EventNotifier::from_bits_truncate(#event_notifier),
            )
        })
    }

    fn generate_variable(&self, node: &UAVariable) -> Result<Expr, CodeGenError> {
        let base = self.generate_base(&node.base.base, "Variable")?;
        let data_type = self.resolve_node_id(&node.data_type)?;
        let historizing = node.historizing;
        let value_rank = node.value_rank.0;
        let value = render_value(node.value.as_ref(), &self.types)?;
        let access_level = node.access_level.0;
        let user_access_level = node.user_access_level.0;
        let array_dimensions = self
            .parse_array_dimensions(&node.array_dimensions)?
            .as_ref()
            .render()?;
        let minimum_sampling_interval = node.minimum_sampling_interval.0.render()?;

        Ok(parse_quote! {
            opcua::nodes::Variable::new_full(
                #base,
                #data_type,
                #historizing,
                #value_rank,
                #value,
                #access_level,
                #user_access_level,
                #array_dimensions,
                Some(#minimum_sampling_interval),
            )
        })
    }

    fn generate_method(&self, node: &UAMethod) -> Result<Expr, CodeGenError> {
        let base = self.generate_base(&node.base.base, "Method")?;
        let executable = node.executable;
        let user_executable = node.user_executable;

        Ok(parse_quote! {
            opcua::nodes::Method::new_full(
                #base,
                #executable,
                #user_executable,
            )
        })
    }

    fn generate_view(&self, node: &UAView) -> Result<Expr, CodeGenError> {
        let base = self.generate_base(&node.base.base, "View")?;
        let event_notifier = node.event_notifier.0;
        let contains_no_loops = node.contains_no_loops;

        Ok(parse_quote! {
            opcua::nodes::View::new_full(
                #base,
                opcua::nodes::EventNotifier::from_bits_truncate(#event_notifier),
                #contains_no_loops,
            )
        })
    }

    fn generate_object_type(&self, node: &UAObjectType) -> Result<Expr, CodeGenError> {
        let base = self.generate_base(&node.base.base, "ObjectType")?;
        let is_abstract = node.base.is_abstract;

        Ok(parse_quote! {
            opcua::nodes::ObjectType::new_full(
                #base,
                #is_abstract,
            )
        })
    }

    fn generate_variable_type(&self, node: &UAVariableType) -> Result<Expr, CodeGenError> {
        let base = self.generate_base(&node.base.base, "VariableType")?;
        let data_type = self.resolve_node_id(&node.data_type)?;
        let is_abstract = node.base.is_abstract;
        let value_rank = node.value_rank.0;
        let value = render_value(node.value.as_ref(), &self.types)?;
        let array_dimensions = self
            .parse_array_dimensions(&node.array_dimensions)?
            .as_ref()
            .render()?;
        Ok(parse_quote! {
            opcua::nodes::VariableType::new_full(
                #base,
                #data_type,
                #is_abstract,
                #value_rank,
                Some(#value),
                #array_dimensions,
            )
        })
    }

    fn generate_data_type(&self, node: &UADataType) -> Result<Expr, CodeGenError> {
        let base = self.generate_base(&node.base.base, "DataType")?;
        let is_abstract = node.base.is_abstract;
        let data_type_definition = match &node.definition {
            Some(e) => {
                let rendered = self.render_data_type_definition(e)?;
                quote! { Some(#rendered.into()) }
            }
            None => quote! { None },
        };

        Ok(parse_quote! {
            opcua::nodes::DataType::new_full(
                #base,
                #is_abstract,
                #data_type_definition
            )
        })
    }

    fn generate_reference_type(&self, node: &UAReferenceType) -> Result<Expr, CodeGenError> {
        let base = self.generate_base(&node.base.base, "ReferenceType")?;
        let symmetric = node.symmetric;
        let is_abstract = node.base.is_abstract;
        let inverse_name = self.get_localized_text_opt(&node.inverse_names).render()?;

        Ok(parse_quote! {
            opcua::nodes::ReferenceType::new_full(
                #base,
                #symmetric,
                #is_abstract,
                #inverse_name,
            )
        })
    }

    fn generate_reference(&self, reference: &Reference) -> Result<Expr, CodeGenError> {
        let target_id = self.resolve_node_id(&reference.node_id)?;
        let type_id = self.resolve_node_id(&reference.reference_type)?;
        let is_forward = reference.is_forward;

        Ok(parse_quote! {
            opcua::nodes::ImportedReference {
                target_id: #target_id,
                type_id: #type_id,
                is_forward: #is_forward,
            }
        })
    }

    fn generate_references(&self, node: &UANodeBase) -> Result<Vec<Expr>, CodeGenError> {
        node.references
            .iter()
            .flat_map(|f| f.references.iter())
            .map(|r| self.generate_reference(r))
            .collect()
    }

    pub fn generate_item(&mut self, node: &UANode) -> Result<NodeGenMethod, CodeGenError> {
        let name = match node {
            UANode::Object(_) => "object",
            UANode::Variable(_) => "variable",
            UANode::Method(_) => "method",
            UANode::View(_) => "view",
            UANode::ObjectType(_) => "object_type",
            UANode::VariableType(_) => "variable_type",
            UANode::DataType(_) => "data_type",
            UANode::ReferenceType(_) => "reference_type",
        };
        let func_name_str = format!("make_{}_{}", name, self.node_counter);
        let func_name: Ident = parse_str(&func_name_str)?;
        self.node_counter += 1;

        let references = self.generate_references(node.base()).map_err(|e| {
            e.with_context(format!(
                "generating references for node {}",
                node.base().node_id.0
            ))
        })?;
        let node = match &node {
            UANode::Object(n) => self.generate_object(n),
            UANode::Variable(n) => self.generate_variable(n),
            UANode::Method(n) => self.generate_method(n),
            UANode::View(n) => self.generate_view(n),
            UANode::ObjectType(n) => self.generate_object_type(n),
            UANode::VariableType(n) => self.generate_variable_type(n),
            UANode::DataType(n) => self.generate_data_type(n),
            UANode::ReferenceType(n) => self.generate_reference_type(n),
        }
        .map_err(|e| e.with_context(format!("generating node {}", node.base().node_id.0)))?;

        let func: ItemFn = parse_quote! {
            #[allow(unused)]
            fn #func_name(ns_map: &opcua::nodes::NodeSetNamespaceMapper<'_>)
                -> opcua::nodes::ImportedItem
            {
                opcua::nodes::ImportedItem {
                    node: #node.into(),
                    references: vec![#(#references),*]
                }
            }
        };

        Ok(NodeGenMethod {
            func,
            name: func_name_str,
        })
    }
}
