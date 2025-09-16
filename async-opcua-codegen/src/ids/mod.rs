//! Codegen for generating enums for NodeIds defined in CSV files.
//! This is currently quite simple, we may want to extend it in the future,
//! and perhaps support generating node ID enums from NodeSet2 files as well.

use std::fs::File;

use crate::CodeGenError;
use gen::{parse, render};

mod gen;

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct NodeIdCodeGenTarget {
    pub file_path: String,
    pub output_file: String,
    pub type_name: Option<String>,
    #[serde(default)]
    pub extra_header: String,
}

pub fn generate_node_ids(
    target: &NodeIdCodeGenTarget,
    root_path: &str,
) -> Result<syn::File, CodeGenError> {
    let file = File::open(format!("{}/{}", root_path, target.file_path))
        .map_err(|e| CodeGenError::io("Failed to open node ID file", e))?;
    let data = parse(file, &target.file_path, target.type_name.as_deref())?;
    let mut pairs = data.into_iter().collect::<Vec<_>>();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let mut items = Vec::new();
    for (_, item) in pairs {
        items.extend(render(item)?.into_iter());
    }
    Ok(syn::File {
        shebang: None,
        attrs: Vec::new(),
        items,
    })
}
