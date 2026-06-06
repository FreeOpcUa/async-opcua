// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2026 Adam Lock

//! Global Discovery Server (GDS) registration client implementation.
//! Provides mechanisms to register client or server applications with a GDS directory.

use crate::Session;
use opcua_types::{ApplicationDescription, CallMethodRequest, NodeId, StatusCode, Variant};
use tracing::{error, info};

/// Client helper for interacting with the GDS registration and directory services.
pub struct GdsRegistrationClient {
    /// NodeId of the GDS Directory object (standard ns=0;i=22384)
    pub directory_object_id: NodeId,
    /// NodeId of the RegisterApplication method (standard ns=0;i=22385)
    pub register_method_id: NodeId,
}

impl Default for GdsRegistrationClient {
    fn default() -> Self {
        Self {
            directory_object_id: NodeId::new(0, 22384),
            register_method_id: NodeId::new(0, 22385),
        }
    }
}

impl GdsRegistrationClient {
    /// Creates a new `GdsRegistrationClient` with default standard GDS NodeIds.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an application with the GDS directory.
    /// Returns the assigned unique `NodeId` of the registered application.
    pub async fn register_application(
        &self,
        session: &Session,
        application_description: ApplicationDescription,
    ) -> Result<NodeId, StatusCode> {
        let request = CallMethodRequest {
            object_id: self.directory_object_id.clone(),
            method_id: self.register_method_id.clone(),
            input_arguments: Some(vec![Variant::from(application_description)]),
        };

        match session.call_one(request).await {
            Ok(result) => {
                if result.status_code.is_good() {
                    if let Some(args) = result.output_arguments {
                        if !args.is_empty() {
                            match &args[0] {
                                Variant::NodeId(node_id) => {
                                    info!("Application successfully registered with GDS, assigned ID: {}", node_id);
                                    return Ok(*node_id.clone());
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(StatusCode::BadUnexpectedError)
                } else {
                    Err(result.status_code)
                }
            }
            Err(err) => {
                error!("Failed to register application with GDS: {}", err);
                Err(err.status())
            }
        }
    }
}
