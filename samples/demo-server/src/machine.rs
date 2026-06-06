// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

use std::{
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    },
    time::Duration,
};

use opcua::{
    crypto::random,
    nodes::BaseEventType,
    server::{
        address_space::{
            AddressSpace, EventNotifier, ObjectBuilder, ObjectTypeBuilder, VariableBuilder,
        },
        node_manager::memory::SimpleNodeManager,
        SubscriptionCache,
    },
    types::{
        DataTypeId, DataValue, DateTime, NodeId, ObjectId, ObjectTypeId, UAString, VariableTypeId,
    },
    Event,
};
use tokio_util::sync::CancellationToken;

pub fn add_machinery(
    ns: u16,
    manager: Arc<SimpleNodeManager>,
    subscriptions: Arc<SubscriptionCache>,
    raise_event: bool,
    token: CancellationToken,
) {
    let address_space = manager.address_space();
    let machine1_counter = Arc::new(AtomicU16::new(0));
    let machine2_counter = Arc::new(AtomicU16::new(50));

    let (machine1_id, machine2_id) = {
        let mut address_space = address_space.write();
        add_machinery_model(&mut address_space, ns);

        // Create a folder under static folder
        let devices_folder_id = NodeId::new(ns, "devices");
        address_space.add_folder(
            &devices_folder_id,
            "Devices",
            "Devices",
            &NodeId::objects_folder_id(),
        );

        // Create the machine events folder
        let _ = address_space.add_folder(
            &machine_events_folder_id(ns),
            "Events",
            "Events",
            &devices_folder_id,
        );

        // Create an object representing a machine that cycles from 0 to 100. Each time it cycles it will create an event
        let machine1_id = add_machine(
            &mut address_space,
            &manager,
            ns,
            devices_folder_id.clone(),
            "Machine 1",
            machine1_counter.clone(),
        );
        let machine2_id = add_machine(
            &mut address_space,
            &manager,
            ns,
            devices_folder_id,
            "Machine 2",
            machine2_counter.clone(),
        );
        (machine1_id, machine2_id)
    };

    tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(300));
        while !token.is_cancelled() {
            interval.tick().await;

            increment_counter(
                &manager,
                &subscriptions,
                ns,
                machine1_counter.clone(),
                &machine1_id,
                raise_event,
            );
            increment_counter(
                &manager,
                &subscriptions,
                ns,
                machine2_counter.clone(),
                &machine2_id,
                raise_event,
            );
        }
    });
}

fn machine_type_id(ns: u16) -> NodeId {
    NodeId::new(ns, "MachineTypeId")
}

fn machine_events_folder_id(ns: u16) -> NodeId {
    NodeId::new(ns, "MachineEvents")
}

fn add_machinery_model(address_space: &mut AddressSpace, ns: u16) {
    // Create a machine counter type derived from BaseObjectType
    let machine_type_id = machine_type_id(ns);
    ObjectTypeBuilder::new(&machine_type_id, "MachineCounterType", "MachineCounterType")
        .is_abstract(false)
        .subtype_of(ObjectTypeId::BaseObjectType)
        .generates_event(MachineCycledEventType::event_type_id_from_index(ns))
        .insert(address_space);

    // Add some variables to the type
    let counter_id = NodeId::next_numeric(ns);
    VariableBuilder::new(&counter_id, "Counter", "Counter")
        .data_type(DataTypeId::UInt16)
        .property_of(machine_type_id.clone())
        .has_type_definition(VariableTypeId::PropertyType)
        .has_modelling_rule(ObjectId::ModellingRule_Mandatory)
        .insert(address_space);

    // Create a counter cycled event type
    let machine_cycled_event_type_id = MachineCycledEventType::event_type_id_from_index(ns);
    ObjectTypeBuilder::new(
        &machine_cycled_event_type_id,
        "MachineCycledEventType",
        "MachineCycledEventType",
    )
    .is_abstract(false)
    .subtype_of(ObjectTypeId::BaseEventType)
    .insert(address_space);
}

fn add_machine(
    address_space: &mut AddressSpace,
    manager: &SimpleNodeManager,
    ns: u16,
    folder_id: NodeId,
    name: &str,
    counter: Arc<AtomicU16>,
) -> NodeId {
    let machine_id = NodeId::new(ns, UAString::from(name));
    // Create a machine. Since machines generate events, the event notifier says that it does.
    ObjectBuilder::new(&machine_id, name, name)
        .event_notifier(EventNotifier::SUBSCRIBE_TO_EVENTS)
        .organized_by(folder_id)
        .has_type_definition(machine_type_id(ns))
        .insert(address_space);

    let counter_id = NodeId::new(ns, format!("{name} Counter"));
    VariableBuilder::new(&counter_id, "Counter", "Counter")
        .property_of(machine_id.clone())
        .data_type(DataTypeId::UInt16)
        .has_type_definition(VariableTypeId::PropertyType)
        .insert(address_space);

    manager
        .inner()
        .add_read_callback(counter_id, move |_, _, _| {
            let value = counter.load(Ordering::Relaxed);
            Ok(DataValue::new_now(value))
        });

    machine_id
}

#[derive(Event)]
#[opcua(identifier = "s=MachineCycledEventId", namespace = "urn:DemoServer")]
pub struct MachineCycledEventType {
    base: BaseEventType,
    own_namespace_index: u16,
}

impl MachineCycledEventType {
    fn new(machine_name: &str, ns: u16, source_node: impl Into<NodeId>, time: DateTime) -> Self {
        let event_type_id = MachineCycledEventType::event_type_id_from_index(ns);
        let source_node: NodeId = source_node.into();
        MachineCycledEventType {
            base: BaseEventType::new(
                event_type_id,
                random::byte_string(128),
                format!("A machine cycled event from machine {source_node}"),
                time,
            )
            .set_source_node(source_node.clone())
            .set_source_name(UAString::from(machine_name))
            .set_severity(rand::random::<u16>() % 999u16 + 1u16),
            own_namespace_index: ns,
        }
    }
}

fn raise_machine_cycled_event(
    manager: &SimpleNodeManager,
    subscriptions: &SubscriptionCache,
    ns: u16,
    source_machine_id: &NodeId,
) {
    let machine_name = {
        let address_space = manager.address_space();
        let address_space_lck = address_space.read();
        if let Some(node) = address_space_lck.find_node(source_machine_id) {
            format!("{}", node.as_node().display_name().text)
        } else {
            "Machine ???".to_string()
        }
    };

    // New event
    let now = DateTime::now();
    let event = MachineCycledEventType::new(&machine_name, ns, source_machine_id, now);

    // create an event object in a folder with the

    subscriptions.notify_events(
        [(&event as &dyn opcua::nodes::Event, &ObjectId::Server.into())].into_iter(),
    );
}

fn increment_counter(
    manager: &SimpleNodeManager,
    subscriptions: &SubscriptionCache,
    ns: u16,
    machine_counter: Arc<AtomicU16>,
    machine_id: &NodeId,
    raise_event: bool,
) {
    let c = machine_counter.load(Ordering::Relaxed);
    let c = if c < 99 {
        c + 1
    } else {
        if raise_event {
            // Raise new event
            raise_machine_cycled_event(manager, subscriptions, ns, machine_id);
        }
        0
    };
    machine_counter.store(c, Ordering::Relaxed);
}
