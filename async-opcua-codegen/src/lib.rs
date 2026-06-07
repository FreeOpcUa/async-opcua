#![warn(missing_docs)]

//! Code generation library for async-opcua.
//! The purpose of this library is to facilitate generating code used as part of
//! the async-opcua library, as well as make it possible to generate code for companion
//! standards.
//!
//! Note that this is in many ways more limited than the official .NET code generation
//! libraries from OPC Foundation. Some of this is due to the fact that OPC-UA code generation
//! is _very_ object oriented, and representing class hierarchies in rust is hard and may not be
//! very useful.

mod config;
mod derives;
mod error;
mod events;
pub mod generator;
mod ids;
pub mod input;
mod nodeset;
mod types;
mod utils;

use std::path::PathBuf;
use std::{collections::HashSet, io::Write, path::Path};

use config::load_schemas;
pub use error::CodeGenError;
use ids::generate_node_ids;
use nodeset::{generate_target, make_root_module};
use serde::{Deserialize, Serialize};
use syn::{parse_str, File};
use tracing::info;
use types::base_native_type_mappings;
use types::{generate_types, generate_types_nodeset, type_loader_impl, EncodingIds};
use utils::{create_module_file, GeneratedOutput};

use crate::events::EventsCodeGenTarget;
pub use crate::ids::NodeIdCodeGenTarget;
use crate::nodeset::make_type_dict;
pub use crate::nodeset::{DependentNodeset, NodeSetCodeGenTarget, NodeSetTypes};
pub use crate::types::{ExternalIds, ExternalType, TypeCodeGenTarget};
pub use config::CodeGenSource;
use events::generate_events;

fn join_paths(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

/// Write all generated items to the specified directory. Each generated item maps to one
/// file. Returns the list of generated modules, which need to be added to the mod.rs file.
fn write_to_directory_in_order<T: GeneratedOutput>(
    dir: &Path,
    root_path: &Path,
    header: &str,
    items: Vec<T>,
) -> Result<Vec<String>, CodeGenError> {
    let mut modules = Vec::new();
    let mut modules_seen = HashSet::new();
    let dir_path = join_paths(root_path, dir);
    let _ = std::fs::remove_dir_all(&dir_path);

    std::fs::create_dir_all(&dir_path)
        .map_err(|e| CodeGenError::io(&format!("Failed to create dir {}", dir.display()), e))?;

    for gen in items {
        let module = gen.module().to_owned();
        let path = dir_path.join(format!("{module}.rs"));
        let is_new = !path.exists();
        let mut file = std::fs::File::options()
            .append(true)
            .create(true)
            .open(path)
            .map_err(|e| {
                CodeGenError::io(
                    &format!("Failed to open file {}/{module}.rs", dir.display()),
                    e,
                )
            })?;
        if is_new {
            file.write_all(header.as_bytes()).map_err(|e| {
                CodeGenError::io(
                    &format!("Failed to write to file {}/{module}.rs", dir.display()),
                    e,
                )
            })?;
        }
        // Do it this way so that we keep a stable ordering.
        if modules_seen.insert(module.clone()) {
            modules.push(module.clone());
        }
        file.write_all(prettyplease::unparse(&gen.to_file()).as_bytes())
            .map_err(|e| {
                CodeGenError::io(
                    &format!("Failed to write to file {}/{module}.rs", dir.display()),
                    e,
                )
            })?;
    }

    Ok(modules)
}

/// Write all generated items to the specified directory. Each generated item maps to one
/// file. Returns the list of generated modules, which need to be added to the mod.rs file.
fn write_to_directory<T: GeneratedOutput>(
    dir: &Path,
    root_path: &Path,
    header: &str,
    mut items: Vec<T>,
) -> Result<Vec<String>, CodeGenError> {
    items.sort_by_key(|a| a.name().to_lowercase());
    write_to_directory_in_order(dir, root_path, header, items)
}

/// Write a `mod.rs` file to the specified directory, with the specified header and content.
pub fn write_module_file(
    dir: &Path,
    root_path: &Path,
    header: &str,
    file: File,
) -> Result<(), CodeGenError> {
    let mod_path = join_paths(root_path, dir).join("mod.rs");
    let mut mod_file = std::fs::File::options()
        .append(true)
        .create(true)
        .open(mod_path)
        .map_err(|e| {
            CodeGenError::io(&format!("Failed to open file {}/mod.rs", dir.display()), e)
        })?;
    mod_file.write_all(header.as_bytes()).map_err(|e| {
        CodeGenError::io(
            &format!("Failed to write to file {}/mod.rs", dir.display()),
            e,
        )
    })?;
    mod_file
        .write_all(prettyplease::unparse(&file).as_bytes())
        .map_err(|e| {
            CodeGenError::io(
                &format!("Failed to write to file {}/mod.rs", dir.display()),
                e,
            )
        })?;

    Ok(())
}

fn make_header(path: &str, extra: &[&str]) -> String {
    let mut header = format!(
        r#"// This file was autogenerated from {path} by async-opcua-codegen
//
// DO NOT EDIT THIS FILE
"#
    );

    for extra in extra {
        if !extra.is_empty() {
            header.push('\n');
            header.push_str(extra.trim());
        }
    }
    if !header.ends_with('\n') {
        header.push('\n');
    }

    header
}

/// Main entrypoint for running code generation. This will write to output files as specified by
/// the provided code gen config.
/// `root_path` is the path the config is loaded from. Paths in the code gen config are
/// relative to this, which means that we can generate the same output files independent of where
/// the codegen binary is called from.
pub fn run_codegen(config: &CodeGenConfig, root_path: &Path) -> Result<(), CodeGenError> {
    let cache = load_schemas(root_path, &config.sources)?;

    let sorted_targets = generator::sort_targets_topologically(config.targets.clone())?;
    for target in &sorted_targets {
        match target {
            CodeGenTarget::Types(t) => {
                info!("Running data type code generation for {}", t.file);
                let (types, target_namespace, path) = if t.file.ends_with(".xml") {
                    let input = cache.get_nodeset(&t.file)?;
                    let r = generate_types_nodeset(t, input, &cache, &config.preferred_locale)
                        .map_err(|e| e.in_file(input.path().to_string_lossy()))?;
                    (r.0, r.1, input.path().to_owned())
                } else {
                    let input = cache.get_binary_schema(&t.file)?;
                    let r = generate_types(t, input).map_err(|e| e.in_file(&t.file))?;
                    (r.0, r.1, input.path().to_owned())
                };
                info!(
                    "Writing {} types to {}",
                    types.len(),
                    t.output_dir.display()
                );

                let header = make_header(
                    &path.to_string_lossy(),
                    &[&config.extra_header, &t.extra_header],
                );

                let mut object_ids: Vec<_> = types
                    .iter()
                    .filter_map(|v| v.encoding_ids.as_ref().map(|i| (i.clone(), v.name.clone())))
                    .collect();
                let id_path: syn::Path = parse_str(&t.id_path).map_err(|e| {
                    CodeGenError::from(e)
                        .with_context(format!("Failed to parse id_path: {}", t.id_path))
                })?;
                for (name, typ) in t.types_import_map.iter() {
                    if typ.add_to_type_loader {
                        object_ids.push((
                            EncodingIds::new_external(&id_path, name, typ)?,
                            format!("{}::{}", typ.path, name),
                        ));
                    }
                }

                let modules = write_to_directory_in_order(&t.output_dir, root_path, &header, types)
                    .map_err(|e| e.in_file(path.to_string_lossy()))?;
                let mut module_file = create_module_file(modules);
                let type_loader_items = type_loader_impl(&object_ids, &target_namespace)
                    .map_err(|e| e.in_file(path.to_string_lossy()))?;
                module_file.items.extend(type_loader_items);

                write_module_file(&t.output_dir, root_path, &header, module_file)
                    .map_err(|e| e.in_file(path.to_string_lossy()))?;
            }
            CodeGenTarget::Nodes(n) => {
                info!("Running node set code generation for {}", n.file);
                let node_set = cache.get_nodeset(&n.file)?;
                info!("Found {} nodes in node set", node_set.xml().nodes.len());

                let types = make_type_dict(&n.types, &cache)
                    .map_err(|e| e.in_file(node_set.path().to_string_lossy()))?;

                let chunks = generate_target(n, node_set, &config.preferred_locale, &types)
                    .map_err(|e| e.in_file(node_set.path().to_string_lossy()))?;
                let module_file = make_root_module(&chunks, n, node_set)
                    .map_err(|e| e.in_file(node_set.path().to_string_lossy()))?;

                info!(
                    "Writing {} files to {}",
                    chunks.len() + 1,
                    n.output_dir.display()
                );

                let header = make_header(
                    &node_set.path().to_string_lossy(),
                    &[&config.extra_header, &n.extra_header],
                );

                write_to_directory(&n.output_dir, root_path, &header, chunks)?;
                write_module_file(&n.output_dir, root_path, &header, module_file)?;
            }
            CodeGenTarget::Ids(n) => {
                info!(
                    "Running node ID code generation for {}",
                    n.file_path.display()
                );
                let gen = generate_node_ids(n, root_path)
                    .map_err(|e| e.in_file(n.file_path.to_string_lossy()))?;
                let out_path = join_paths(root_path, &n.output_file);
                let mut file = std::fs::File::options()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(out_path)
                    .map_err(|e| {
                        CodeGenError::io(
                            &format!("Failed to open file {}", n.output_file.display()),
                            e,
                        )
                    })?;
                let header = make_header(
                    &n.file_path.to_string_lossy(),
                    &[&config.extra_header, &n.extra_header],
                );
                file.write_all(header.as_bytes()).map_err(|e| {
                    CodeGenError::io(
                        &format!("Failed to write to file {}", n.output_file.display()),
                        e,
                    )
                })?;
                file.write_all(prettyplease::unparse(&gen).as_bytes())
                    .map_err(|e| {
                        CodeGenError::io(
                            &format!("Failed to write to file {}", n.output_file.display()),
                            e,
                        )
                    })?;
            }
            CodeGenTarget::Events(events_target) => {
                info!(
                    "Generating events to {}",
                    events_target.output_dir.display()
                );

                let node_set = cache.get_nodeset(&events_target.file)?;
                let types = make_type_dict(&events_target.types, &cache)
                    .map_err(|e| e.in_file(node_set.path().to_string_lossy()))?;

                let mut sets = Vec::with_capacity(events_target.dependent_nodesets.len() + 1);
                for nodeset_file in &events_target.dependent_nodesets {
                    info!("Loading dependent node set {}", nodeset_file.file);
                    let set = cache.get_nodeset(&nodeset_file.file)?;
                    sets.push((set.xml(), nodeset_file.import_path.as_str()));
                }

                sets.push((node_set.xml(), ""));

                let events = generate_events(&sets, &types)?;
                let cnt = events.len();
                let header = make_header(
                    &node_set.path().to_string_lossy(),
                    &[&config.extra_header, &events_target.extra_header],
                );
                let modules =
                    write_to_directory(&events_target.output_dir, root_path, &header, events)
                        .map_err(|e| e.in_file(node_set.path().to_string_lossy()))?;
                write_module_file(
                    &events_target.output_dir,
                    root_path,
                    &header,
                    create_module_file(modules),
                )
                .map_err(|e| e.in_file(node_set.path().to_string_lossy()))?;
                info!("Created {} event types", cnt);
            }
        }
    }

    Ok(())
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
/// A top level code generation target.
pub enum CodeGenTarget {
    /// Code gen target for data types. This generates a struct with derives, and
    /// some impls for each struct/enum in a bsd or nodeset2 file.
    Types(TypeCodeGenTarget),
    /// Code gen target for node sets. This generates a function per node, and
    /// larger functions to call the underlying functions, to produce a node set source.
    Nodes(NodeSetCodeGenTarget),
    /// Code gen target for node IDs. This produces an enum for each node ID type from
    /// a NodeId csv file.
    Ids(NodeIdCodeGenTarget),
    /// Code gen target for generating event types. This creates structs for
    /// each event type in a nodeset, which all implement the `Event` trait. To do this,
    /// it also generates types for some `ObjectType`s and `VariableType`s which are used
    /// as event fields.
    Events(EventsCodeGenTarget),
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
/// Top level code-gen config.
pub struct CodeGenConfig {
    #[serde(default)]
    /// Extra header to add to each generated file.
    pub extra_header: String,
    #[serde(default)]
    /// Preferred locale to use when loading localized text.
    /// Defaults to nothing, which picks the first available. Most nodesets have only one locale.
    pub preferred_locale: String,
    /// List of code gen targets.
    pub targets: Vec<CodeGenTarget>,
    /// List of input files. This must include all inputs, even if they are only referenced by other inputs.
    pub sources: Vec<CodeGenSource>,
}

const BASE_NAMESPACE: &str = "http://opcfoundation.org/UA/";
