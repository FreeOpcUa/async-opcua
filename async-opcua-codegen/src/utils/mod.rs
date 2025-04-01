use convert_case::{Case, Casing};
use proc_macro2::Span;
use syn::{parse_quote, File, Ident};

mod node_id;
mod qualified_name;
mod render;

pub use node_id::{NodeIdVariant, ParsedNodeId};
pub use qualified_name::split_qualified_name;
pub use render::RenderExpr;

pub fn to_snake_case(v: &str) -> String {
    v.to_case(Case::Snake)
}

pub fn create_module_file(modules: Vec<String>) -> File {
    let mut items = Vec::new();
    for md in modules {
        let ident = Ident::new(&md, Span::call_site());
        items.push(parse_quote! {
            pub mod #ident;
        });
        items.push(parse_quote! {
            pub use #ident::*;
        });
    }

    File {
        shebang: None,
        attrs: Vec::new(),
        items,
    }
}

pub trait GeneratedOutput {
    fn to_file(self) -> File;

    fn module(&self) -> &str;

    fn name(&self) -> &str;
}

pub fn safe_ident(val: &str) -> (Ident, bool) {
    let mut val = val.to_string();
    let mut changed = false;
    if val.starts_with(['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'])
        || val == "type"
        || val.contains(['/'])
    {
        val = format!("__{}", val.replace(['/'], "_"));
        changed = true;
    }

    (Ident::new(&val, Span::call_site()), changed)
}
