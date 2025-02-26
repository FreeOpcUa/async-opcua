mod base_constants;
mod enum_type;
mod gen;
mod loader;
mod structure;

pub use base_constants::*;
pub use enum_type::{EnumType, EnumValue};
pub use gen::{CodeGenItemConfig, CodeGenerator, EncodingIds, GeneratedItem, ItemDefinition};
pub use loader::{BsdTypeLoader, LoadedType, LoadedTypes};
use opcua_xml::load_bsd_file;
use proc_macro2::TokenStream;
use quote::quote;
pub use structure::{StructureField, StructureFieldType, StructuredType};
use syn::{parse_quote, parse_str, Item, Path};

use crate::{CodeGenError, TypeCodeGenTarget, BASE_NAMESPACE};

pub fn generate_types(
    target: &TypeCodeGenTarget,
    root_path: &str,
) -> Result<(Vec<GeneratedItem>, String), CodeGenError> {
    println!("Loading types from {}", target.file_path);
    let data = std::fs::read_to_string(format!("{}/{}", root_path, &target.file_path))
        .map_err(|e| CodeGenError::io(&format!("Failed to read file {}", target.file_path), e))?;
    let type_dictionary =
        load_bsd_file(&data).map_err(|e| CodeGenError::from(e).in_file(&target.file_path))?;
    println!(
        "Found {} raw elements in the type dictionary.",
        type_dictionary.elements.len()
    );
    let type_loader = BsdTypeLoader::new(
        target
            .ignore
            .iter()
            .cloned()
            .chain(base_ignored_types().into_iter())
            .collect(),
        base_native_type_mappings(),
        type_dictionary,
    )?;
    let target_namespace = type_loader.target_namespace();
    let types = type_loader
        .from_bsd()
        .map_err(|e| e.in_file(&target.file_path))?;
    println!("Generated code for {} types", types.len());

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
        },
        target_namespace.clone(),
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
        let dt_ident = &ids.data_type;
        let enc_ident = &ids.binary;
        let typ_path: Path = parse_str(typ).unwrap();
        fields.extend(quote! {
            inst.add_binary_type(
                crate::DataTypeId::#dt_ident as u32,
                crate::ObjectId::#enc_ident as u32,
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
        let dt_ident = &ids.data_type;
        let enc_ident = &ids.json;
        let typ_path: Path = parse_str(typ).unwrap();
        fields.extend(quote! {
            inst.add_json_type(
                crate::DataTypeId::#dt_ident as u32,
                crate::ObjectId::#enc_ident as u32,
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
        let dt_ident = &ids.data_type;
        let enc_ident = &ids.xml;
        let typ_path: Path = parse_str(typ).unwrap();
        fields.extend(quote! {
            inst.add_xml_type(
                crate::DataTypeId::#dt_ident as u32,
                crate::ObjectId::#enc_ident as u32,
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
