//! This is a library for testing async-opcua-codegen, primarily.
#![allow(missing_docs)]
#![allow(clippy::disallowed_names)]
#![allow(clippy::derivable_impls)]

use crate::generated::SimpleEnum;

pub mod generated {
    include!(concat!(env!("OPCUA_GENERATED_DIR"), "/mod.rs"));
}

impl Default for SimpleEnum {
    fn default() -> Self {
        SimpleEnum::Foo
    }
}

#[cfg(test)]
mod tests;
