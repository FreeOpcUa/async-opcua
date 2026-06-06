use proc_macro2::Span;
use syn::{parse::Parse, Attribute, Data, DataStruct, Field, Ident, Type};

#[derive(Debug, Default)]
pub(crate) struct EmptyAttribute;

impl Parse for EmptyAttribute {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        if !input.is_empty() {
            return Err(syn::Error::new(input.span(), "Unexpected attribute"));
        }
        Ok(EmptyAttribute)
    }
}

impl ItemAttr for EmptyAttribute {
    fn combine(&mut self, _other: Self) {}
}

pub(crate) trait ItemAttr {
    fn combine(&mut self, other: Self);
}

pub(crate) struct StructField<T> {
    pub ident: Ident,
    pub typ: Type,
    pub attr: T,
}

pub(crate) struct StructItem<TFieldAttr, TAttr> {
    pub ident: Ident,
    pub fields: Vec<StructField<TFieldAttr>>,
    pub attribute: TAttr,
}

impl<TFieldAttr: Parse + ItemAttr + Default, TAttr: Parse + ItemAttr + Default>
    StructItem<TFieldAttr, TAttr>
{
    pub(crate) fn from_input(
        input: DataStruct,
        attributes: Vec<Attribute>,
        ident: Ident,
    ) -> syn::Result<Self> {
        let fields = input
            .fields
            .into_iter()
            .map(StructField::from_field)
            .collect::<Result<Vec<_>, _>>()?;

        let mut final_attr = TAttr::default();
        for attr in attributes {
            if attr.path().segments.len() == 1
                && attr
                    .path()
                    .segments
                    .first()
                    .is_some_and(|s| s.ident == "opcua")
            {
                let data: TAttr = attr.parse_args()?;
                final_attr.combine(data);
            }
        }

        Ok(Self {
            ident,
            fields,
            attribute: final_attr,
        })
    }
}

impl<T: Parse + ItemAttr + Default> StructField<T> {
    pub(crate) fn from_field(field: Field) -> syn::Result<Self> {
        let Some(ident) = field.ident else {
            return Err(syn::Error::new_spanned(
                field,
                "Derive macro input must have named fields",
            ));
        };
        let mut final_attr = T::default();
        for attr in field.attrs {
            if attr.path().segments.len() == 1
                && attr
                    .path()
                    .segments
                    .first()
                    .is_some_and(|s| s.ident == "opcua")
            {
                let data: T = attr.parse_args()?;
                final_attr.combine(data);
            }
        }
        Ok(StructField {
            ident,
            typ: field.ty,
            attr: final_attr,
        })
    }
}

pub(crate) fn expect_struct(input: Data) -> syn::Result<DataStruct> {
    match input {
        syn::Data::Struct(s) => Ok(s),
        _ => Err(syn::Error::new(
            Span::call_site(),
            "Derive macro input must be a struct",
        )),
    }
}
