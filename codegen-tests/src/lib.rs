//! This is a library for testing async-opcua-codegen, primarily.
#![allow(missing_docs)]
#![allow(clippy::disallowed_names)]
#![allow(clippy::derivable_impls)]

use crate::generated::base::SimpleEnum;

pub mod generated {
    pub mod base {
        include!(concat!(env!("OPCUA_GENERATED_DIR"), "/base/mod.rs"));
    }
    pub mod ext {
        include!(concat!(env!("OPCUA_GENERATED_DIR"), "/ext/mod.rs"));
    }
}

impl Default for SimpleEnum {
    fn default() -> Self {
        SimpleEnum::Foo
    }
}

#[cfg(test)]
mod tests;
