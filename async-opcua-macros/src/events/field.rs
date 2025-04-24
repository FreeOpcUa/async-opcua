use convert_case::{Case, Casing};
use proc_macro2::TokenStream;
use syn::DeriveInput;

use crate::utils::{expect_struct, EmptyAttribute, StructItem};

use super::parse::EventFieldAttribute;

use quote::quote;

pub(crate) type EventFieldStruct = StructItem<EventFieldAttribute, EmptyAttribute>;

pub(crate) fn parse_event_field_struct(input: DeriveInput) -> syn::Result<EventFieldStruct> {
    EventFieldStruct::from_input(expect_struct(input.data)?, input.attrs, input.ident)
}

pub(crate) fn generate_event_field_impls(event: EventFieldStruct) -> syn::Result<TokenStream> {
    let ident = event.ident;
    let mut get_arms = quote! {};
    let mut final_arm = quote! {
        opcua::types::Variant::Empty
    };
    let mut pre_check_block = quote! {};
    let mut placeholder_fields = quote! {};
    for field in event.fields {
        if field.attr.ignore {
            continue;
        }

        let has_rename = field.attr.rename.is_some();

        let name = field
            .attr
            .rename
            .unwrap_or_else(|| field.ident.to_string().to_case(Case::Pascal));
        let ident = field.ident;

        if field.attr.placeholder {
            placeholder_fields.extend(quote! {
                if let Some(value) = self.#ident.try_get_value(field, attribute_id, index_range, browse_path.get(1..).unwrap_or(&[])) {
                    return value;
                }
            })
        } else if !has_rename {
            match ident.to_string().as_str() {
                "base" => {
                    final_arm = quote! {
                        self.base.get_value(attribute_id, index_range, browse_path)
                    }
                }
                "node_id" => pre_check_block.extend(quote! {
                    if browse_path.is_empty() && attribute_id == opcua::types::AttributeId::NodeId {
                        let val: opcua::types::Variant = self.node_id.clone().into();
                        return val.range_of_owned(index_range).unwrap_or(opcua::types::Variant::Empty);
                    }
                }),
                "value" => pre_check_block.extend(quote! {
                    if browse_path.is_empty() && attribute_id == opcua::types::AttributeId::Value {
                        return self.value.get_value(attribute_id, index_range, browse_path);
                    }
                }),
                _ => get_arms.extend(quote! {
                    #name => self.#ident.get_value(attribute_id, index_range, browse_path.get(1..).unwrap_or(&[])),
                })
            }
        } else {
            get_arms.extend(quote! {
                #name => self.#ident.get_value(attribute_id, index_range, browse_path.get(1..).unwrap_or(&[])),
            });
        }
    }
    final_arm = quote! {
        _ => {
            #placeholder_fields
            #final_arm
        }
    };

    Ok(quote! {
        impl opcua::nodes::EventField for #ident {
            fn get_value(
                &self,
                attribute_id: opcua::types::AttributeId,
                index_range: &opcua::types::NumericRange,
                browse_path: &[opcua::types::QualifiedName],
            ) -> opcua::types::Variant {
                #pre_check_block
                if browse_path.is_empty() {
                    return opcua::types::Variant::Empty;
                }
                let field = &browse_path[0];
                match field.name.as_ref() {
                    #get_arms
                    #final_arm
                }
            }
        }
    })
}
