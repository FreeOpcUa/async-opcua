//! Code generation for data types from BSD or NodeSet files.
//!
//! This generates rust structs, enums and bitsets from type definitions in
//! the input files.

mod base_constants;
mod encoding_ids;
mod gen;
mod loaders;

use std::collections::{HashMap, HashSet};

pub use base_constants::*;
pub use encoding_ids::EncodingIds;
pub use gen::{CodeGenItemConfig, CodeGenerator, GeneratedItem};
use loaders::NodeSetTypeLoader;
pub use loaders::{BsdTypeLoader, LoadedType};
use proc_macro2::TokenStream;
use quote::quote;
use serde::{Deserialize, Serialize};
use syn::{parse_quote, parse_str, Item, Path};
use tracing::info;

use crate::{
    input::{BinarySchemaInput, NodeSetInput, SchemaCache},
    CodeGenError, DependentNodeset, BASE_NAMESPACE,
};

#[derive(Serialize, Deserialize, Debug)]
/// Target for code generation of data types.
pub struct TypeCodeGenTarget {
    /// Reference to the input file, which needs to be added to the input list.
    pub file: String,
    /// Output directory.
    pub output_dir: String,
    #[serde(default)]
    /// List of type names to ignore.
    pub ignore: Vec<String>,
    #[serde(default)]
    /// Map of external types to import. This is used, for example, to
    /// include the manually written `ignore` types.
    pub types_import_map: HashMap<String, ExternalType>,
    #[serde(default)]
    /// List of type names to not generate `Default` implementations for.
    /// This is useful for types that require a manual default implementation.
    pub default_excluded: HashSet<String>,
    #[serde(default)]
    /// Put all the enums in a single file.
    pub enums_single_file: bool,
    #[serde(default)]
    /// Put all the structs in a single file.
    pub structs_single_file: bool,
    #[serde(default)]
    /// Extra header to add to each generated file.
    pub extra_header: String,
    #[serde(default = "defaults::id_path")]
    /// Path to the crate where the `DataTypeIds` and `ObjectIds` enums are located.
    /// Defaults to `crate`.
    pub id_path: String,
    #[serde(default)]
    /// If true, instead of using `id_path` and ID enums, generate the node IDs from the nodeset file.
    pub node_ids_from_nodeset: bool,
    /// List of dependent nodesets to load types from. Only valid when using a NodeSet input.
    #[serde(default)]
    pub dependent_nodesets: Vec<DependentNodeset>,
}

impl Default for TypeCodeGenTarget {
    fn default() -> Self {
        Self {
            file: String::new(),
            output_dir: String::new(),
            ignore: Vec::new(),
            types_import_map: HashMap::new(),
            default_excluded: HashSet::new(),
            enums_single_file: false,
            structs_single_file: false,
            extra_header: String::new(),
            id_path: defaults::id_path(),
            node_ids_from_nodeset: false,
            dependent_nodesets: Vec::new(),
        }
    }
}

mod defaults {
    pub fn id_path() -> String {
        "crate".to_owned()
    }
}

/// Generate types from the given BSD file input.
///
/// This returns a list of output _files_ according to config. Each file contains one or more
/// generated struct or enum definition, and in some cases some impls, though mostly just
/// derives.
///
/// This form of code generation is deprecated.
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
    let types = type_loader
        .load_types()
        .map_err(|e| e.in_file(&input.path))?;
    info!("Loaded {} types", types.len());

    generate_types_inner(target, target_namespace, types, HashMap::new())
}

/// Generate types from the given NodeSet file input.
///
/// This returns a list of output _files_ according to config. Each file contains one or more
/// generated struct or enum definition, and in some cases some impls, though mostly just
/// derives.
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

    let mut namespace_to_import_path = HashMap::new();
    for dependent_nodeset in &target.dependent_nodesets {
        let dep_input = cache.get_nodeset(&dependent_nodeset.file)?;
        namespace_to_import_path
            .insert(dep_input.uri.clone(), dependent_nodeset.import_path.clone());
    }

    generate_types_inner(target, target_namespace, types, namespace_to_import_path)
}

fn generate_types_inner(
    target: &TypeCodeGenTarget,
    target_namespace: String,
    types: Vec<LoadedType>,
    namespace_to_import_path: HashMap<String, String>,
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
        namespace_to_import_path,
    );

    Ok((generator.generate_types()?, target_namespace))
}

/// Generate a static type loader implementation for the given encoding IDs.
///
/// This generates a `TypeLoader` implementation that can load types from binary, XML, and JSON
/// encodings, based on the provided encoding IDs and type names.
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
                _length: Option<usize>,
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
                _name: &str,
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
