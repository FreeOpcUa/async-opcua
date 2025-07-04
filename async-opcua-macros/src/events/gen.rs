use super::parse::{EventStruct, Identifier};
use convert_case::{Case, Casing};
use proc_macro2::TokenStream;
use quote::quote;

pub(crate) fn generate_event_impls(event: EventStruct) -> syn::Result<TokenStream> {
    let ident = event.ident;
    let mut get_arms = quote! {};
    let mut init_items = quote! {};
    let mut placeholder_fields = quote! {};
    for field in event.fields {
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
        } else if !field.attr.ignore {
            get_arms.extend(quote! {
                #name => self.#ident.get_value(attribute_id, index_range, browse_path.get(1..).unwrap_or(&[])),
            });
        }
        init_items.extend(quote! {
            #ident: Default::default(),
        });
    }

    let Some(idf) = event.attribute.identifier else {
        return Err(syn::Error::new_spanned(
            ident,
            "Event must have an attribute `#[opcua(identifier = \"...\")]",
        ));
    };
    let identifier_body = match idf {
        Identifier::Number(i) => quote! {
            #i
        },
        Identifier::String(s) => quote! {
            #s
        },
        Identifier::Guid(v) => {
            let bytes = v.as_bytes();
            quote! {
                {
                    let idf: &[u8; 16] = &[#(#bytes),*];
                    idf
                }
            }
        }
        Identifier::ByteString(v) => {
            quote! {
                {
                    let idf: &[u8] = &[#(#v),*];
                    idf
                }
            }
        }
    };

    let type_id_body = if event.attribute.namespace.is_some() {
        quote! {
            type_definition_id == &(self.own_namespace_index, #identifier_body)
        }
    } else {
        quote! {
            type_definition_id == &(0, #identifier_body)
        }
    };

    let get_namespace = if let Some(ns) = &event.attribute.namespace {
        quote! {
            namespaces.get_index(#ns).unwrap_or_else(||
                panic!("Attempted to create event with unknown namespace {}", #ns))
        }
    } else {
        quote! { 0 }
    };

    let base_type = event.attribute.base_type.unwrap();

    if event.attribute.namespace.is_some() {
        init_items.extend(quote! {
            own_namespace_index: #get_namespace,
        });
    }

    let mut ctors = quote! {
        pub fn new_event_now(
            type_id: opcua::types::NodeId,
            event_id: opcua::types::ByteString,
            message: impl Into<opcua::types::LocalizedText>,
            namespaces: &opcua::nodes::NamespaceMap,
        ) -> Self {
            Self::new_event(type_id, event_id, message, namespaces, opcua::types::DateTime::now())
        }

        pub fn new_event(
            type_id: opcua::types::NodeId,
            event_id: opcua::types::ByteString,
            message: impl Into<opcua::types::LocalizedText>,
            namespaces: &opcua::nodes::NamespaceMap,
            time: opcua::types::DateTime,
        ) -> Self {
            Self {
                base: #base_type::new_event(type_id, event_id, message, namespaces, time),
                #init_items
            }
        }
    };

    if event.attribute.namespace.is_some() {
        ctors.extend(quote! {
            pub fn event_type_id(namespaces: &opcua::nodes::NamespaceMap) -> opcua::types::NodeId {
                Self::event_type_id_from_index(#get_namespace)
            }

            pub fn event_type_id_from_index(namespace: u16) -> opcua::types::NodeId {
                opcua::types::NodeId::new(namespace, #identifier_body)
            }
        });
    } else {
        ctors.extend(quote! {
            pub fn event_type_id() -> opcua::types::NodeId {
                opcua::types::NodeId::new(0, #identifier_body)
            }
        })
    }

    Ok(quote! {
        impl opcua::nodes::Event for #ident {
            fn get_field(
                &self,
                type_definition_id: &opcua::types::NodeId,
                attribute_id: opcua::types::AttributeId,
                index_range: &opcua::types::NumericRange,
                browse_path: &[opcua::types::QualifiedName],
            ) -> opcua::types::Variant {
                use opcua::nodes::EventField;

                if type_definition_id != &opcua::types::ObjectTypeId::BaseEventType && !{
                    #type_id_body
                } {
                    return self.base.get_field(
                        type_definition_id, attribute_id, index_range, browse_path
                    );
                }

                self.get_value(attribute_id, index_range, browse_path)
            }

            fn time(&self) -> &opcua::types::DateTime {
                self.base.time()
            }

            fn event_type_id(&self) -> &opcua::types::NodeId {
                self.base.event_type_id()
            }
        }

        impl opcua::nodes::EventField for #ident {
            fn get_value(
                &self,
                attribute_id: opcua::types::AttributeId,
                index_range: &opcua::types::NumericRange,
                browse_path: &[opcua::types::QualifiedName],
            ) -> opcua::types::Variant {
                if browse_path.is_empty() {
                    return opcua::types::Variant::Empty;
                }
                let field = &browse_path[0];
                match field.name.as_ref() {
                    #get_arms
                    _ => {
                        #placeholder_fields
                        self.base.get_value(attribute_id, index_range, browse_path)
                    }
                }
            }
        }

        impl #ident {
            #ctors
        }
    })
}
