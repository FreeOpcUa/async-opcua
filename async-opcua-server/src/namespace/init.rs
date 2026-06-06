//! Server namespace initializer.
//! Provides helper functions to register Alarm Conditions and associate their callbacks in the node manager.

use crate::address_space::AddressSpace;
use crate::alarms::{AlarmMethodHandler, ConditionStateMachine};
use opcua_types::NodeId;
use std::sync::Arc;

/// Registers a new Alarm Condition state machine and its associated Acknowledge/Confirm methods in the AddressSpace.
pub fn register_alarm_condition(
    address_space: &Arc<opcua_core::sync::RwLock<AddressSpace>>,
    node_manager: &crate::node_manager::memory::SimpleNodeManager,
    device: &str,
    alarm_type: &str,
    source_node_id: NodeId,
    condition_name: &str,
) -> ConditionStateMachine {
    // 1. Create the state machine nodes in the Address Space
    let state_machine = {
        let mut space = opcua_core::trace_write_lock!(address_space);
        ConditionStateMachine::create_in_address_space(
            &mut space,
            device,
            alarm_type,
            source_node_id,
            condition_name,
        )
    };

    // 2. Add the Method nodes to the address space under the alarm object
    let base_s = format!("Alarm_{}_{}", device, alarm_type);
    let ack_method_id = NodeId::new(2, format!("{}_Acknowledge", base_s));
    let confirm_method_id = NodeId::new(2, format!("{}_Confirm", base_s));

    {
        let mut space = opcua_core::trace_write_lock!(address_space);

        let ack_input_args = vec![
            opcua_types::Argument {
                name: "EventId".into(),
                data_type: opcua_types::NodeId::new(0, 15),
                value_rank: -1,
                array_dimensions: None,
                description: opcua_types::LocalizedText::null(),
            },
            opcua_types::Argument {
                name: "Comment".into(),
                data_type: opcua_types::NodeId::new(0, 21),
                value_rank: -1,
                array_dimensions: None,
                description: opcua_types::LocalizedText::null(),
            },
        ];

        let ack_method =
            opcua_nodes::MethodBuilder::new(&ack_method_id, "Acknowledge", "Acknowledge")
                .component_of(state_machine.condition_id.clone())
                .input_args(
                    &mut *space,
                    &NodeId::new(2, format!("{}_InputArguments", base_s)),
                    &ack_input_args,
                )
                .build();
        space.insert(
            ack_method,
            Some(&[(
                &state_machine.condition_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        let confirm_input_args = vec![
            opcua_types::Argument {
                name: "EventId".into(),
                data_type: opcua_types::NodeId::new(0, 15),
                value_rank: -1,
                array_dimensions: None,
                description: opcua_types::LocalizedText::null(),
            },
            opcua_types::Argument {
                name: "Comment".into(),
                data_type: opcua_types::NodeId::new(0, 21),
                value_rank: -1,
                array_dimensions: None,
                description: opcua_types::LocalizedText::null(),
            },
        ];

        let confirm_method =
            opcua_nodes::MethodBuilder::new(&confirm_method_id, "Confirm", "Confirm")
                .component_of(state_machine.condition_id.clone())
                .input_args(
                    &mut *space,
                    &NodeId::new(2, format!("{}_ConfirmInputArguments", base_s)),
                    &confirm_input_args,
                )
                .build();
        space.insert(
            confirm_method,
            Some(&[(
                &state_machine.condition_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );
    }

    // 3. Register their callbacks with SimpleNodeManager using method callbacks
    let handler = Arc::new(AlarmMethodHandler::new(
        state_machine.clone(),
        address_space.clone(),
    ));

    let handler_clone1 = handler.clone();
    node_manager
        .inner()
        .add_method_callback_with_context(ack_method_id, move |ctx, args| {
            handler_clone1.handle_ack_method(ctx, args)
        });

    node_manager
        .inner()
        .add_method_callback_with_context(confirm_method_id, move |ctx, args| {
            handler.handle_confirm_method(ctx, args)
        });

    state_machine
}
