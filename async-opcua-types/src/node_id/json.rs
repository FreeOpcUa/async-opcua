use std::io::{Read, Write};
use std::str::FromStr;

use super::{Identifier, NodeId};
use crate::{json::*, Error, StatusCode};

const OPC_UA_NAMESPACE_URI: &str = "http://opcfoundation.org/UA/";

fn namespace_uri_for_index<'a>(ctx: &'a Context<'_>, namespace: u16) -> Option<&'a str> {
    ctx.namespaces()
        .known_namespaces()
        .iter()
        .find_map(|(uri, index)| (*index == namespace).then_some(uri.as_str()))
}

fn escape_namespace_uri(namespace_uri: &str) -> String {
    namespace_uri.replace('%', "%25").replace(';', "%3b")
}

fn unescape_namespace_uri(namespace_uri: &str) -> String {
    namespace_uri.replace("%3b", ";").replace("%25", "%")
}

fn invalid_node_id(value: &str) -> Error {
    Error::new(
        StatusCode::BadNodeIdInvalid,
        format!("invalid NodeId JSON string {value:?}"),
    )
}

impl JsonEncodable for NodeId {
    fn encode(
        &self,
        stream: &mut JsonStreamWriter<&mut dyn Write>,
        ctx: &crate::json::Context<'_>,
    ) -> crate::EncodingResult<()> {
        if self.namespace == 0 {
            stream.string_value(&self.identifier.to_string())?;
        } else if let Some(namespace_uri) = namespace_uri_for_index(ctx, self.namespace) {
            if namespace_uri == OPC_UA_NAMESPACE_URI {
                stream.string_value(&self.identifier.to_string())?;
            } else {
                stream.string_value(&format!(
                    "nsu={};{}",
                    escape_namespace_uri(namespace_uri),
                    self.identifier
                ))?;
            }
        } else {
            stream.string_value(&self.to_string())?;
        }
        Ok(())
    }
}

impl JsonDecodable for NodeId {
    fn decode(
        stream: &mut JsonStreamReader<&mut dyn Read>,
        ctx: &Context<'_>,
    ) -> crate::EncodingResult<Self> {
        match stream.peek()? {
            ValueType::Null => {
                stream.next_null()?;
                Ok(Self::null())
            }
            ValueType::String => {
                let value = stream.next_str()?;
                decode_node_id_string(value, ctx)
            }
            _ => Err(Error::decoding(
                "invalid NodeId JSON value, expected string",
            )),
        }
    }
}

fn decode_node_id_string(value: &str, ctx: &Context<'_>) -> crate::EncodingResult<NodeId> {
    let Some(rest) = value.strip_prefix("nsu=") else {
        return NodeId::from_str(value).map_err(|_| invalid_node_id(value));
    };

    let (namespace_uri, identifier) = rest.split_once(';').ok_or_else(|| invalid_node_id(value))?;
    if namespace_uri.is_empty() || identifier.starts_with("ns=") {
        return Err(invalid_node_id(value));
    }

    let namespace_uri = unescape_namespace_uri(namespace_uri);
    let Some(namespace) = ctx.namespaces().get_index(&namespace_uri) else {
        return Ok(NodeId::new(0, value));
    };

    let identifier = Identifier::from_str(identifier).map_err(|_| invalid_node_id(value))?;
    Ok(NodeId::new(namespace, identifier))
}
