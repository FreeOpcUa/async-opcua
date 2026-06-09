use std::sync::Arc;
use tokio::task;

use opcua_core::sync::RwLock;
use opcua_server::address_space::{AddressSpace, NodeType, VariableBuilder};
use opcua_types::{DataTypeId, NodeId, NumericRange, QualifiedName, Variant};

#[tokio::test]
async fn test_concurrent_read_write() {
    let address_space = Arc::new(RwLock::new(AddressSpace::new()));

    // Create some variables
    const NUM_VARIABLES: usize = 100;
    const NUM_TASKS: usize = 20;
    const ITERATIONS: usize = 1000;

    {
        let mut aspace = address_space.write();
        aspace.add_namespace("urn:test", 1);
        for i in 0..NUM_VARIABLES {
            let node_id = NodeId::new(1, format!("var_{}", i));
            VariableBuilder::new(
                &node_id,
                QualifiedName::new(1, format!("var_{}", i).as_str()),
                format!("var_{}", i).as_str(),
            )
            .data_type(DataTypeId::Int32)
            .value(Variant::from(0i32))
            .insert(&mut *aspace);
        }
    }

    let mut handles = Vec::new();

    // Spawn readers and writers
    for task_id in 0..NUM_TASKS {
        let aspace_clone = address_space.clone();

        let handle = task::spawn(async move {
            for i in 0..ITERATIONS {
                let var_index = (task_id + i) % NUM_VARIABLES;
                let node_id = NodeId::new(1, format!("var_{}", var_index));

                // Even tasks write, odd tasks read
                if task_id % 2 == 0 {
                    let aspace = aspace_clone.write();
                    if let Some(NodeType::Variable(ref mut var)) =
                        aspace.find_mut(&node_id).as_deref_mut()
                    {
                        let _ = var.set_value(&NumericRange::None, Variant::from(i as i32));
                    };
                } else {
                    let aspace = aspace_clone.read();
                    if let Some(NodeType::Variable(ref var)) = aspace.find(&node_id).as_deref() {
                        let _val = var.value(
                            opcua_types::TimestampsToReturn::Neither,
                            &NumericRange::None,
                            &opcua_types::DataEncoding::default(),
                            0.0,
                        );
                    };
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }
}
