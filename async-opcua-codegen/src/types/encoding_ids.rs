use proc_macro2::Span;
use syn::{parse_quote, Expr, Ident, Path};

use crate::{
    input::RawEncodingIds,
    utils::{ParsedNodeId, RenderExpr},
    CodeGenError,
};

use super::ExternalType;

#[derive(Clone)]
pub struct EncodingIds {
    pub data_type: Expr,
    pub xml: Expr,
    pub json: Expr,
    pub binary: Expr,
}

impl EncodingIds {
    pub fn new(id_path: Path, root: &str) -> Result<Self, CodeGenError> {
        let data_type = Ident::new(root, Span::call_site());
        let xml = Ident::new(&format!("{}_Encoding_DefaultXml", root), Span::call_site());
        let json = Ident::new(&format!("{}_Encoding_DefaultJson", root), Span::call_site());
        let bin = Ident::new(
            &format!("{}_Encoding_DefaultBinary", root),
            Span::call_site(),
        );
        Ok(Self {
            data_type: parse_quote! { #id_path::DataTypeId::#data_type as u32 },
            xml: parse_quote! { #id_path::ObjectId::#xml as u32 },
            json: parse_quote! { #id_path::ObjectId::#json as u32 },
            binary: parse_quote! { #id_path::ObjectId::#bin as u32 },
        })
    }

    pub fn new_external(
        id_path: &Path,
        name: &str,
        ty: &ExternalType,
    ) -> Result<Self, CodeGenError> {
        if let Some(ids) = &ty.ids {
            let data_type = ids
                .id
                .as_ref()
                .ok_or_else(|| CodeGenError::other("Missing data type ID in external type"))?;
            let binary = ids.binary.as_ref().unwrap_or(data_type);
            let xml = ids.xml.as_ref().unwrap_or(data_type);
            let json = ids.json.as_ref().unwrap_or(data_type);

            let data_type = ParsedNodeId::parse(data_type)?.value.render()?;
            let binary = ParsedNodeId::parse(binary)?.value.render()?;
            let xml = ParsedNodeId::parse(xml)?.value.render()?;
            let json = ParsedNodeId::parse(json)?.value.render()?;

            Ok(Self {
                data_type: parse_quote!( #data_type ),
                xml: parse_quote!( #xml ),
                json: parse_quote!( #json ),
                binary: parse_quote!( #binary ),
            })
        } else {
            Self::new(id_path.clone(), name)
        }
    }

    pub fn new_raw(raw: &RawEncodingIds) -> Result<Self, CodeGenError> {
        let data_type = raw
            .data_type
            .as_ref()
            .ok_or_else(|| CodeGenError::other("Missing data type ID"))?;
        let binary = raw.binary.as_ref().unwrap_or(data_type).value.render()?;
        let xml = raw.xml.as_ref().unwrap_or(data_type).value.render()?;
        let json = raw.json.as_ref().unwrap_or(data_type).value.render()?;
        let data_type = data_type.value.render()?;
        Ok(Self {
            data_type: parse_quote!( #data_type ),
            xml: parse_quote!( #xml ),
            json: parse_quote!( #json ),
            binary: parse_quote!( #binary ),
        })
    }
}
