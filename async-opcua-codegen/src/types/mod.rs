mod base_constants;
mod encoding_ids;
mod gen;
mod loaders;

pub use base_constants::*;
pub use encoding_ids::EncodingIds;
pub use gen::{CodeGenItemConfig, CodeGenerator, GeneratedItem, ItemDefinition};
use loaders::NodeSetTypeLoader;
pub use loaders::{BsdTypeLoader, LoadedType, LoadedTypes};
use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse_quote, parse_str, Item, Path};
use tracing::info;

use crate::{
    input::{BinarySchemaInput, NodeSetInput, SchemaCache},
    CodeGenError, TypeCodeGenTarget, BASE_NAMESPACE,
};

pub fn generate_types(
    target: &TypeCodeGenTarget,
    input: &BinarySchemaInput,
) -> Result<(Vec<GeneratedItem>, String), CodeGenError> {
    if target.node_ids_from_nodeset {
        return Err(CodeGenError::other("Invalid config. node_ids_from_nodeset is not valid when using a BSD file for code generation."));
    }

    info!(
        "Found {} raw elements in the type dictionary.",
        input.xml.elements.len()
    );
    let type_loader = BsdTypeLoader::new(
        target
            .ignore
            .iter()
            .cloned()
            .chain(base_ignored_types().into_iter())
            .collect(),
        base_native_type_mappings(),
        &input.xml,
    )?;
    let target_namespace = type_loader.target_namespace();
    let types = type_loader.from_bsd().map_err(|e| e.in_file(&input.path))?;
    info!("Loaded {} types", types.len());

    generate_types_inner(target, target_namespace, types)
}

pub fn generate_types_nodeset(
    target: &TypeCodeGenTarget,
    input: &NodeSetInput,
    cache: &SchemaCache,
    preferred_locale: &str,
) -> Result<(Vec<GeneratedItem>, String), CodeGenError> {
    let type_loader = NodeSetTypeLoader::new(
        target
            .ignore
            .iter()
            .cloned()
            .chain(base_ignored_types())
            .collect(),
        base_native_type_mappings(),
        input,
        preferred_locale,
    );
    let target_namespace = input.uri.clone();
    let types = type_loader.load_types(cache)?;
    info!("Loaded {} types", types.len());

    generate_types_inner(target, target_namespace, types)
}

fn generate_types_inner(
    target: &TypeCodeGenTarget,
    target_namespace: String,
    types: Vec<LoadedType>,
) -> Result<(Vec<GeneratedItem>, String), CodeGenError> {
    let mut types_import_map = basic_types_import_map();
    for (k, v) in &target.types_import_map {
        types_import_map.insert(k.clone(), v.clone());
    }

    let generator = CodeGenerator::new(
        types_import_map,
        [
            "bool", "i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64", "i32",
        ]
        .into_iter()
        .map(|v| v.to_owned())
        .collect(),
        types,
        target.default_excluded.clone(),
        CodeGenItemConfig {
            enums_single_file: target.enums_single_file,
            structs_single_file: target.structs_single_file,
            node_ids_from_nodeset: target.node_ids_from_nodeset,
        },
        target_namespace.clone(),
        target.id_path.clone(),
    );

    Ok((generator.generate_types()?, target_namespace))
}

pub fn type_loader_impl(ids: &[(EncodingIds, String)], namespace: &str) -> Vec<Item> {
    if ids.is_empty() {
        return Vec::new();
    }

    let mut ids: Vec<_> = ids.iter().collect();
    ids.sort_by(|a, b| a.1.cmp(&b.1));
    let mut res = Vec::new();

    let (bin_fields, bin_body) = binary_loader_impl(&ids, namespace);
    let (xml_fields, xml_body) = xml_loader_impl(&ids, namespace);
    let (json_fields, json_body) = json_loader_impl(&ids, namespace);

    res.push(parse_quote! {
        static TYPES: std::sync::LazyLock<opcua::types::TypeLoaderInstance> = std::sync::LazyLock::new(|| {
            let mut inst = opcua::types::TypeLoaderInstance::new();
            {
                #bin_fields
            }
            #[cfg(feature = "xml")]
            {
                #xml_fields
            }
            #[cfg(feature = "json")]
            {
                #json_fields
            }
            inst
        });
    });

    let priority_impl = if namespace == BASE_NAMESPACE {
        quote! {
            fn priority(&self) -> opcua::types::TypeLoaderPriority {
                opcua::types::TypeLoaderPriority::Core
            }
        }
    } else {
        quote! {
            fn priority(&self) -> opcua::types::TypeLoaderPriority {
                opcua::types::TypeLoaderPriority::Generated
            }
        }
    };

    res.push(parse_quote! {
        #[derive(Debug, Clone, Copy)]
        pub struct GeneratedTypeLoader;
    });

    res.push(parse_quote! {
        impl opcua::types::TypeLoader for GeneratedTypeLoader {
            #bin_body

            #xml_body

            #json_body

            #priority_impl
        }
    });

    res
}

fn binary_loader_impl(
    ids: &[&(EncodingIds, String)],
    namespace: &str,
) -> (TokenStream, TokenStream) {
    let mut fields = quote! {};
    for (ids, typ) in ids {
        let dt_expr = &ids.data_type;
        let enc_expr = &ids.binary;
        let typ_path: Path = parse_str(typ).unwrap();
        fields.extend(quote! {
            inst.add_binary_type(
                #dt_expr,
                #enc_expr,
                opcua::types::binary_decode_to_enc::<#typ_path>
            );
        });
    }

    let index_check = if namespace != BASE_NAMESPACE {
        quote! {
            let idx = ctx.namespaces().get_index(#namespace)?;
            if idx != node_id.namespace {
                return None;
            }
        }
    } else {
        quote! {
            if node_id.namespace != 0 {
                return None;
            }
        }
    };

    (
        fields,
        quote! {
            fn load_from_binary(
                &self,
                node_id: &opcua::types::NodeId,
                stream: &mut dyn std::io::Read,
                ctx: &opcua::types::Context<'_>,
            ) -> Option<opcua::types::EncodingResult<Box<dyn opcua::types::DynEncodable>>> {
                #index_check

                let Some(num_id) = node_id.as_u32() else {
                    return Some(Err(opcua::types::Error::decoding(
                        "Unsupported encoding ID. Only numeric encoding IDs are currently supported"
                    )));
                };

                TYPES.decode_binary(num_id, stream, ctx)
            }
        },
    )
}

fn json_loader_impl(ids: &[&(EncodingIds, String)], namespace: &str) -> (TokenStream, TokenStream) {
    let mut fields = quote! {};
    for (ids, typ) in ids {
        let dt_expr = &ids.data_type;
        let enc_expr = &ids.json;
        let typ_path: Path = parse_str(typ).unwrap();
        fields.extend(quote! {
            inst.add_json_type(
                #dt_expr,
                #enc_expr,
                opcua::types::json_decode_to_enc::<#typ_path>
            );
        });
    }

    let index_check = if namespace != BASE_NAMESPACE {
        quote! {
            let idx = ctx.namespaces().get_index(#namespace)?;
            if idx != node_id.namespace {
                return None;
            }
        }
    } else {
        quote! {
            if node_id.namespace != 0 {
                return None;
            }
        }
    };

    (
        fields,
        quote! {
            #[cfg(feature = "json")]
            fn load_from_json(
                &self,
                node_id: &opcua::types::NodeId,
                stream: &mut opcua::types::json::JsonStreamReader<&mut dyn std::io::Read>,
                ctx: &opcua::types::Context<'_>,
            ) -> Option<opcua::types::EncodingResult<Box<dyn opcua::types::DynEncodable>>> {
                #index_check

                let Some(num_id) = node_id.as_u32() else {
                    return Some(Err(opcua::types::Error::decoding(
                        "Unsupported encoding ID. Only numeric encoding IDs are currently supported"
                    )));
                };

                TYPES.decode_json(num_id, stream, ctx)
            }
        },
    )
}

fn xml_loader_impl(ids: &[&(EncodingIds, String)], namespace: &str) -> (TokenStream, TokenStream) {
    let mut fields = quote! {};
    for (ids, typ) in ids {
        let dt_expr = &ids.data_type;
        let enc_expr = &ids.xml;
        let typ_path: Path = parse_str(typ).unwrap();
        fields.extend(quote! {
            inst.add_xml_type(
                #dt_expr,
                #enc_expr,
                opcua::types::xml_decode_to_enc::<#typ_path>
            );
        });
    }

    let index_check = if namespace != BASE_NAMESPACE {
        quote! {
            let idx = ctx.namespaces().get_index(#namespace)?;
            if idx != node_id.namespace {
                return None;
            }
        }
    } else {
        quote! {
            if node_id.namespace != 0 {
                return None;
            }
        }
    };

    (
        fields,
        quote! {
            #[cfg(feature = "xml")]
            fn load_from_xml(
                &self,
                node_id: &opcua::types::NodeId,
                stream: &mut opcua::types::xml::XmlStreamReader<&mut dyn std::io::Read>,
                ctx: &opcua::types::Context<'_>,
            ) -> Option<opcua::types::EncodingResult<Box<dyn opcua::types::DynEncodable>>> {
                #index_check

                let Some(num_id) = node_id.as_u32() else {
                    return Some(Err(opcua::types::Error::decoding(
                        "Unsupported encoding ID. Only numeric encoding IDs are currently supported"
                    )));
                };

                TYPES.decode_xml(num_id, stream, ctx)
            }
        },
    )
}
