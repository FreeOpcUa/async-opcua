#[derive(serde::Serialize, Debug)]
pub struct EnumValue {
    pub name: String,
    pub value: i64,
    pub documentation: Option<String>,
}

#[derive(serde::Serialize, Debug)]
#[allow(non_camel_case_types)]
pub enum EnumReprType {
    u8,
    i16,
    i32,
    i64,
}

impl std::fmt::Display for EnumReprType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnumReprType::u8 => write!(f, "u8"),
            EnumReprType::i16 => write!(f, "i16"),
            EnumReprType::i32 => write!(f, "i32"),
            EnumReprType::i64 => write!(f, "i64"),
        }
    }
}

#[derive(serde::Serialize, Debug)]
pub struct EnumType {
    pub name: String,
    pub values: Vec<EnumValue>,
    pub documentation: Option<String>,
    pub typ: EnumReprType,
    pub size: u64,
    pub option: bool,
    pub default_value: Option<String>,
}
