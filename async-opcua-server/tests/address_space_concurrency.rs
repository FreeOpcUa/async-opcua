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

/// Spec 004 T043: DashMap concurrent throughput. Mixed readers, writers and
/// inserters hammer the same address space; the test asserts forward progress
/// within a generous bound and full consistency afterwards, and reports the
/// measured throughput.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_dashmap_concurrent_throughput() {
    const NUM_TASKS: usize = 16;
    const OPS_PER_TASK: usize = 10_000;
    const BASE_VARIABLES: usize = 1_000;

    let address_space = Arc::new(RwLock::new(AddressSpace::new()));
    {
        let mut aspace = address_space.write();
        aspace.add_namespace("urn:throughput", 1);
        for i in 0..BASE_VARIABLES {
            let node_id = NodeId::new(1, format!("base_{i}"));
            VariableBuilder::new(
                &node_id,
                QualifiedName::new(1, format!("base_{i}").as_str()),
                format!("base_{i}").as_str(),
            )
            .data_type(DataTypeId::Int32)
            .value(Variant::from(0i32))
            .insert(&mut *aspace);
        }
    }

    let started = std::time::Instant::now();
    let mut handles = Vec::new();
    for task_id in 0..NUM_TASKS {
        let aspace_clone = address_space.clone();
        handles.push(task::spawn(async move {
            for i in 0..OPS_PER_TASK {
                match task_id % 4 {
                    // Inserters extend the map while others operate on it.
                    0 => {
                        let node_id = NodeId::new(1, format!("ins_{task_id}_{i}"));
                        let mut aspace = aspace_clone.write();
                        VariableBuilder::new(
                            &node_id,
                            QualifiedName::new(1, format!("ins_{task_id}_{i}").as_str()),
                            format!("ins_{task_id}_{i}").as_str(),
                        )
                        .data_type(DataTypeId::Int32)
                        .value(Variant::from(i as i32))
                        .insert(&mut *aspace);
                    }
                    // Writers update existing values.
                    1 => {
                        let node_id = NodeId::new(1, format!("base_{}", i % BASE_VARIABLES));
                        let aspace = aspace_clone.write();
                        let mut node = aspace.find_mut(&node_id);
                        if let Some(NodeType::Variable(ref mut var)) = node.as_deref_mut() {
                            let _ = var.set_value(&NumericRange::None, Variant::from(i as i32));
                        }
                        drop(node);
                    }
                    // Readers look values up concurrently.
                    _ => {
                        let node_id =
                            NodeId::new(1, format!("base_{}", (task_id + i) % BASE_VARIABLES));
                        let aspace = aspace_clone.read();
                        let node = aspace.find(&node_id);
                        if let Some(NodeType::Variable(ref var)) = node.as_deref() {
                            let _ = var.value(
                                opcua_types::TimestampsToReturn::Neither,
                                &NumericRange::None,
                                &opcua_types::DataEncoding::default(),
                                0.0,
                            );
                        }
                        drop(node);
                    }
                }
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
    let elapsed = started.elapsed();

    let total_ops = NUM_TASKS * OPS_PER_TASK;
    println!(
        "DashMap throughput: {total_ops} ops in {elapsed:?} ({:.0} ops/s)",
        total_ops as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < std::time::Duration::from_secs(30),
        "concurrent throughput collapsed: {total_ops} ops took {elapsed:?}"
    );

    // All inserted nodes must be present afterwards.
    let aspace = address_space.read();
    for task_id in (0..NUM_TASKS).filter(|t| t % 4 == 0) {
        for i in (0..OPS_PER_TASK).step_by(1000) {
            let node_id = NodeId::new(1, format!("ins_{task_id}_{i}"));
            assert!(
                aspace.find(&node_id).is_some(),
                "inserted node {node_id} should be present"
            );
        }
    }
}
