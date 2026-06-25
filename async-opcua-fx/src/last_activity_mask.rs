mod opcua {
    pub(super) use opcua_types as types;
}

bitflags::bitflags! {
    #[derive(Debug, Copy, Clone, PartialEq)]
    pub struct LastActivityMask: u16 {
        const EstablishEnabled = 1u16;
        const EstablishDisabled = 2u16;
        const Establish = 4u16;
        const Remove = 8u16;
        const Enable = 16u16;
        const Disable = 32u16;
        const Error = 32768u16;
    }
}

impl opcua::types::UaNullable for LastActivityMask {
    fn is_ua_null(&self) -> bool {
        self.is_empty()
    }
}

opcua::types::impl_encoded_as!(
    LastActivityMask,
    |v| Ok(LastActivityMask::from_bits_truncate(v)),
    |v: &LastActivityMask| Ok::<_, opcua::types::Error>(v.bits()),
    |v: &LastActivityMask| v.bits().byte_len()
);

impl Default for LastActivityMask {
    fn default() -> Self {
        Self::empty()
    }
}

impl opcua::types::IntoVariant for LastActivityMask {
    fn into_variant(self) -> opcua::types::Variant {
        self.bits().into_variant()
    }
}

#[cfg(feature = "xml")]
impl opcua::types::xml::XmlType for LastActivityMask {
    const TAG: &'static str = "LastActivityMask";
}
