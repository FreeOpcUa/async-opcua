use std::sync::Arc;

use opcua::{
    client::Session,
    types::{
        errors::OpcUaError, BrowsePath, ExpandedNodeId, ExtensionObject, NodeId, ObjectId,
        TimestampsToReturn, Variant, WriteValue,
    },
};
use opcua_structure_client::{client_connect, NAMESPACE_URI};

const STRUCT_ENC_TYPE_ID: u32 = 3324;
const STRUCT_DATA_TYPE_ID: u32 = 3325;
//const ENUM_DATA_TYPE_ID: u32 = 3326;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (session, handle, ns) = client_connect().await?;
    read_structure_var(&session, ns).await?;

    session.disconnect().await?;
    handle.await.unwrap();
    Ok(())
}

async fn read_structure_var(session: &Arc<Session>, ns: u16) -> Result<(), OpcUaError> {
    // Register our loader that will parse UA struct into our Rust struc
    session.add_type_loader(Arc::new(CustomTypeLoader));

    //get node_id using browsepath
    let res = session
        .translate_browse_paths_to_node_ids(&[BrowsePath {
            starting_node: ObjectId::ObjectsFolder.into(),
            relative_path: format!("/{0}:ErrorFolder/{0}:ErrorData", ns).try_into()?,
        }])
        .await?;
    let Some(target) = &res[0].targets else {
        panic!("translate browse path did not return a NodeId")
    };
    let node_id = &target[0].target_id.node_id;

    // value of node variable
    let dv = session
        .read(&[node_id.into()], TimestampsToReturn::Neither, 0.0)
        .await?
        .into_iter()
        .next()
        .unwrap();

    if let Some(Variant::ExtensionObject(obj)) = dv.value {
        dbg!("Native rust object: ", &obj.body.unwrap());
    }

    // Now show how to write a value from client
    let new = ErrorData {
        message: "New message".into(),
        error_id: 100,
        last_state: AxisState::Error,
    };

    let res = session
        .write(&[WriteValue::value_attr(
            node_id.clone(),
            Variant::ExtensionObject(ExtensionObject {
                body: Some(Box::new(new)),
            }),
        )])
        .await?;
    dbg!(res);
    Ok(())
}

// The struct and enum code after this line could/should be shared with demo server,
// but having it here makes the example self-contained.

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    opcua::types::UaEnum,
    opcua::types::BinaryEncodable,
    opcua::types::BinaryDecodable,
)]
#[cfg_attr(
    feature = "json",
    derive(opcua::types::JsonEncodable, opcua::types::JsonDecodable)
)]
#[cfg_attr(feature = "xml", derive(opcua::types::FromXml))]
#[derive(Default)]
#[repr(i32)]
pub enum AxisState {
    #[default]
    Disabled = 1i32,
    Enabled = 2i32,
    Idle = 3i32,
    MoveAbs = 4i32,
    Error = 5i32,
}

#[derive(Debug, Clone, PartialEq, opcua::types::BinaryEncodable, opcua::types::BinaryDecodable)]
#[cfg_attr(
    feature = "json",
    derive(opcua::types::JsonEncodable, opcua::types::JsonDecodable)
)]
#[cfg_attr(feature = "xml", derive(opcua::types::FromXml))]
#[derive(Default)]
pub struct ErrorData {
    message: opcua::types::UAString,
    error_id: u32,
    last_state: AxisState,
}

static TYPES: std::sync::LazyLock<opcua::types::TypeLoaderInstance> =
    std::sync::LazyLock::new(|| {
        let mut inst = opcua::types::TypeLoaderInstance::new();
        {
            inst.add_binary_type(
                STRUCT_DATA_TYPE_ID,
                STRUCT_ENC_TYPE_ID,
                opcua::types::binary_decode_to_enc::<ErrorData>,
            );

            inst
        }
    });

#[derive(Debug, Clone, Copy)]
pub struct CustomTypeLoader;
impl opcua::types::TypeLoader for CustomTypeLoader {
    fn load_from_binary(
        &self,
        node_id: &opcua::types::NodeId,
        stream: &mut dyn std::io::Read,
        ctx: &opcua::types::Context<'_>,
    ) -> Option<opcua::types::EncodingResult<Box<dyn opcua::types::DynEncodable>>> {
        let idx = ctx.namespaces().get_index(NAMESPACE_URI)?;
        if idx != node_id.namespace {
            return None;
        }
        let Some(num_id) = node_id.as_u32() else {
            return Some(Err(opcua::types::Error::decoding(
                "Unsupported encoding ID. Only numeric encoding IDs are currently supported",
            )));
        };
        TYPES.decode_binary(num_id, stream, ctx)
    }
    #[cfg(feature = "xml")]
    fn load_from_xml(
        &self,
        _node_id: &opcua::types::NodeId,
        _stream: &opcua::types::xml::XmlElement,
        _ctx: &opcua::types::xml::XmlContext<'_>,
    ) -> Option<Result<Box<dyn opcua::types::DynEncodable>, opcua::types::xml::FromXmlError>> {
        todo!()
    }
    #[cfg(feature = "json")]
    fn load_from_json(
        &self,
        _node_id: &opcua::types::NodeId,
        _stream: &mut opcua::types::json::JsonStreamReader<&mut dyn std::io::Read>,
        _ctx: &opcua::types::Context<'_>,
    ) -> Option<opcua::types::EncodingResult<Box<dyn opcua::types::DynEncodable>>> {
        todo!()
    }
    fn priority(&self) -> opcua::types::TypeLoaderPriority {
        opcua::types::TypeLoaderPriority::Generated
    }
}

impl opcua::types::ExpandedMessageInfo for ErrorData {
    fn full_type_id(&self) -> opcua::types::ExpandedNodeId {
        ExpandedNodeId {
            node_id: NodeId::new(0, STRUCT_ENC_TYPE_ID),
            namespace_uri: NAMESPACE_URI.into(),
            server_index: 0,
        }
    }

    fn full_json_type_id(&self) -> opcua::types::ExpandedNodeId {
        todo!()
    }

    fn full_xml_type_id(&self) -> opcua::types::ExpandedNodeId {
        todo!()
    }

    fn full_data_type_id(&self) -> opcua::types::ExpandedNodeId {
        ExpandedNodeId {
            node_id: NodeId::new(0, STRUCT_DATA_TYPE_ID),
            namespace_uri: NAMESPACE_URI.into(),
            server_index: 0,
        }
    }
}
