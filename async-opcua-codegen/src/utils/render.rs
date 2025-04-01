use proc_macro2::TokenStream;
use syn::parse_quote;

use crate::CodeGenError;

use quote::quote;

pub trait RenderExpr {
    fn render(&self) -> Result<TokenStream, CodeGenError>;
}

impl<T> RenderExpr for Option<&T>
where
    T: RenderExpr,
{
    fn render(&self) -> Result<TokenStream, CodeGenError> {
        Ok(match self {
            Some(t) => {
                let rendered = t.render()?;
                parse_quote! {
                    Some(#rendered)
                }
            }
            None => parse_quote! { None },
        })
    }
}

impl RenderExpr for Vec<u32> {
    fn render(&self) -> Result<TokenStream, CodeGenError> {
        let r = self;
        Ok(quote! {
            vec![#(#r),*]
        })
    }
}

impl RenderExpr for f64 {
    fn render(&self) -> Result<TokenStream, CodeGenError> {
        let r = self;
        Ok(quote! {
            #r
        })
    }
}

impl RenderExpr for opcua_xml::schema::ua_node_set::LocalizedText {
    fn render(&self) -> Result<TokenStream, CodeGenError> {
        let locale = &self.locale.0;
        let text = &self.text;
        Ok(quote! {
            opcua::types::LocalizedText::new(#locale, #text)
        })
    }
}
