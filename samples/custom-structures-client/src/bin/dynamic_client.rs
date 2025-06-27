// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! This simple OPC UA client will do the following:
//!
//! 1. Create a client configuration
//! 2. Connect to an endpoint specified by the url with security None
//! 3. Read a variable on server with data type being a custom structure

use std::sync::Arc;

use opcua::{
    client::{custom_types::DataTypeTreeBuilder, Session},
    types::{
        custom::{DynamicStructure, DynamicTypeLoader},
        errors::OpcUaError,
        BrowsePath, ObjectId, TimestampsToReturn, TypeLoader, Variant,
    },
};
use opcua_structure_client::client_connect;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (session, handle, ns) = client_connect().await?;
    read_structure_var(&session, ns).await?;

    session.disconnect().await?;
    handle.await.unwrap();
    Ok(())
}

async fn read_structure_var(session: &Arc<Session>, ns: u16) -> Result<(), OpcUaError> {
    let type_tree = DataTypeTreeBuilder::new(|f| f.namespace <= ns)
        .build(session)
        .await
        .unwrap();
    let type_tree = Arc::new(type_tree);
    let loader = Arc::new(DynamicTypeLoader::new(type_tree.clone())) as Arc<dyn TypeLoader>;
    session.add_type_loader(loader.clone());

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
    let dv = session
        .read(&[node_id.into()], TimestampsToReturn::Neither, 0.0)
        .await?
        .into_iter()
        .next()
        .unwrap();
    dbg!(&dv);

    let Some(Variant::ExtensionObject(val)) = dv.value else {
        panic!("Unexpected variant type");
    };

    let val: DynamicStructure = *val.into_inner_as().unwrap();
    dbg!(&val.get_field(0));
    dbg!(&val.get_field(1));
    dbg!(&val.get_field(2));

    Ok(())
}
