use crate::xml::*;
use std::{
    io::{Read, Write},
    str::FromStr,
};

use super::NodeId;

impl XmlType for NodeId {
    const TAG: &'static str = "NodeId";
}

impl XmlEncodable for NodeId {
    fn encode(
        &self,
        writer: &mut XmlStreamWriter<&mut dyn Write>,
        ctx: &crate::xml::Context<'_>,
    ) -> Result<(), Error> {
        let namespace_index = ctx.resolve_namespace_index_inverse(self.namespace)?;

        let self_str = if namespace_index > 0 {
            format!("ns={};{}", namespace_index, self.identifier)
        } else {
            self.identifier.to_string()
        };
        let val = ctx.resolve_alias_inverse(&self_str);
        writer.encode_child("Identifier", val, ctx)
    }
}

impl XmlDecodable for NodeId {
    fn decode(
        read: &mut XmlStreamReader<&mut dyn Read>,
        context: &Context<'_>,
    ) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let val: Option<String> = read.decode_single_child("Identifier", context)?;
        let Some(val) = val else {
            return Ok(NodeId::null());
        };

        let val_str = context.resolve_alias(&val);
        let mut id = NodeId::from_str(val_str)
            .map_err(|e| Error::new(e, format!("Invalid node ID: {val_str}")))?;
        id.namespace = context.resolve_namespace_index(id.namespace)?;
        Ok(id)
    }
}
