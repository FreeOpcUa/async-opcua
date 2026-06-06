//! This is a sample server that implements two different node managers,
//! to demonstrate the purpose of different levels of abstraction.
//!
//! It creates a simulated underlying system, that has behavior similar to what
//! you might expect a real underlying system to have, then reads data from
//! that dynamically from the node managers.

use std::{sync::Arc, time::Duration};

use log::warn;
use node_managers::{MetadataNodeManagerBuilder, TagNodeManagerBuilder, CURRENT_TICK};
use opcua::{
    crypto::SecurityPolicy,
    server::{
        node_manager::memory::InMemoryNodeManagerBuilder, ServerBuilder, ServerEndpoint,
        ServerHandle, ANONYMOUS_USER_TOKEN_ID,
    },
    sync::RwLock,
    types::{AttributeId, DataTypeId, DataValue, MessageSecurityMode, NodeId},
};
use sim::{
    gen::{CosValue, JustLinearTime, SineValue, SomeFunction},
    Simulation, TagRef,
};

mod node_managers;
mod sim;

#[tokio::main]
async fn main() {
    env_logger::init();

    let metadata_namespace = "urn:async_opcua_node_managers_meta";
    let tag_namespace = "urn:async_opcua_node_managers_tags";

    let mut sim = Simulation::new();

    // Add some initial nodes. We can add more later.
    sim.add_tag("sine", "Sine 1", "Sine wave", SineValue::default())
        .add_metadata("meta 1", "value 1")
        .add_metadata("stuff", "things");
    sim.add_tag("cos", "Cos 1", "Cosine wave", CosValue::default());
    sim.add_tag("time", "Time 1", "Linear time", JustLinearTime::default())
        .add_metadata("Hello", "there");

    let sim = Arc::new(RwLock::new(sim));

    let (server, handle) = ServerBuilder::new()
        .application_name("Async OPC-UA Node Managers sample")
        .application_uri("urn:async_opcua_node_managers")
        .product_uri("urn:async_opcua_node_managers")
        .create_sample_keypair(true)
        .host("localhost")
        .port(4855)
        .add_endpoint(
            "standard",
            ServerEndpoint::new(
                "/",
                SecurityPolicy::None,
                MessageSecurityMode::None,
                // Allow the anonymous identity on this endpoint.
                &[ANONYMOUS_USER_TOKEN_ID.to_owned()],
            ),
        )
        .discovery_urls(vec!["opc.tcp://localhost:4855/".to_owned()])
        // Add our custom node managers.
        .with_node_manager(InMemoryNodeManagerBuilder::new(
            MetadataNodeManagerBuilder::new(metadata_namespace, sim.clone()),
        ))
        .with_node_manager(TagNodeManagerBuilder::new(
            tag_namespace,
            metadata_namespace,
            sim.clone(),
        ))
        .trust_client_certs(true)
        .diagnostics_enabled(true)
        .build()
        .unwrap();

    let handle_c = handle.clone();
    tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            warn!("Failed to register CTRL-C handler: {e}");
            return;
        }
        handle_c.cancel();
    });

    // Spawn some background processes. These will modify the
    // simulation and notify the server of any changes.
    tokio::spawn(add_new_tags(sim.clone()));
    tokio::spawn(run_sim(
        sim.clone(),
        handle.clone(),
        tag_namespace.to_owned(),
        metadata_namespace.to_owned(),
    ));

    // Run the server. This does not ordinarily exit so you must Ctrl+C to terminate
    server.run().await.unwrap();
}

async fn add_new_tags(sim: Arc<RwLock<Simulation>>) {
    let mut counter = 0;
    loop {
        // Make sure we don't hold the lock for too long! Recall that the server
        // requires a read lock on the simulation to read values from it.
        {
            // Add a new tag every 10 seconds.
            // Since our tag node manager is completely dynamic, all we need to do is
            // add them to the simulation.
            let mut sim = sim.write();
            let counter_c = counter;
            sim.add_tag(
                format!("add_{counter}"),
                format!("Added {counter}"),
                format!("Grown node {counter}"),
                SomeFunction::new(move |t| (t * counter_c).into(), DataTypeId::UInt64),
            )
            .add_metadata("Field", format!("Some value {counter}"));
        }
        counter += 1;
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

async fn run_sim(
    sim: Arc<RwLock<Simulation>>,
    handle: ServerHandle,
    tag_namespace: String,
    meta_namespace: String,
) {
    let ns_index = handle
        .type_tree()
        .read()
        .namespaces()
        .get_index(&tag_namespace)
        .expect("Tag namespace not registered yet");
    let meta_ns_index = handle
        .type_tree()
        .read()
        .namespaces()
        .get_index(&meta_namespace)
        .expect("Meta namespace not registered yet");

    let tick_id = NodeId::new(meta_ns_index, CURRENT_TICK);

    let mut counter = 0;
    loop {
        // This is one possible approach to dealing with subscriptions.
        // In this case, the simulation is responsible for notifying the server of _all_ changes that
        // happen. This may be inefficient in some systems, but it's a relatively easy way to do this.
        {
            let mut sim = sim.write();
            sim.tick(counter);

            let mut notifier = handle.subscriptions().data_notifier();

            // Notify any listening clients of changes to the tags. Note that we only sample the value if
            // anyone is actually listening.
            for tag in sim.iter_tag_meta() {
                if let Some(mut batch) =
                    notifier.notify_for((ns_index, tag.tag), AttributeId::Value)
                {
                    let Some(value) = sim.get_tag_value(tag.tag) else {
                        continue;
                    };
                    batch.data_value(DataValue::new_at(value, sim.last_tick_timestamp()));
                }
            }

            // Also notify about changes to the "counter" value.
            notifier.notify(
                &tick_id,
                AttributeId::Value,
                DataValue::new_at(counter + 1, sim.last_tick_timestamp()),
            );
        }
        counter += 1;

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
