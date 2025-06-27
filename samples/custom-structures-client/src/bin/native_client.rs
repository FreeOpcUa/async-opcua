use std::sync::Arc;

use opcua::{
    client::Session,
    types::{
        errors::OpcUaError, ua_encodable, BrowsePath, ExpandedNodeId, ExtensionObject, NodeId,
        ObjectId, StaticTypeLoader, TimestampsToReturn, Variant, WriteValue,
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
            relative_path: format!("/{ns}:ErrorFolder/{ns}:ErrorData").try_into()?,
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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[ua_encodable]
#[repr(i32)]
pub enum AxisState {
    #[opcua(default)]
    Disabled = 1i32,
    Enabled = 2i32,
    Idle = 3i32,
    MoveAbs = 4i32,
    Error = 5i32,
}

#[derive(Debug, Clone, PartialEq, Default)]
#[ua_encodable]
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

impl StaticTypeLoader for CustomTypeLoader {
    fn instance() -> &'static opcua::types::TypeLoaderInstance {
        &TYPES
    }

    fn namespace() -> &'static str {
        NAMESPACE_URI
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
