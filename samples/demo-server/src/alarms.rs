// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

use std::{sync::Arc, time::Duration};

use opcua::{
    nodes::Event,
    server::{
        address_space::VariableBuilder,
        alarms::{
            register_condition_methods, transitions::trigger_alarm_transition, ConditionRegistry,
            LimitAlarm, LimitConfig, LimitDef, LimitMode, ServerAlarmEvent,
        },
        namespace::{register_alarm_condition, register_limit_alarm},
        node_manager::memory::{CoreNodeManager, SimpleNodeManager},
        SubscriptionCache,
    },
    types::{DataTypeId, DataValue, LocalizedText, NodeId, StatusCode},
};
use tokio_util::sync::CancellationToken;

pub fn add_alarm_demo(
    ns: u16,
    manager: Arc<SimpleNodeManager>,
    core_node_manager: Arc<CoreNodeManager>,
    subscriptions: Arc<SubscriptionCache>,
    token: CancellationToken,
) {
    let source_node_id = NodeId::new(ns, "DemoAlarmSource");
    let tank_level_node_id = NodeId::new(ns, "TankLevel");
    let alarms_folder_id = NodeId::new(ns, "alarms");

    {
        let mut address_space = manager.address_space().write();
        address_space.add_folder(
            &alarms_folder_id,
            "Alarms",
            "Alarms",
            &NodeId::objects_folder_id(),
        );

        VariableBuilder::new(&source_node_id, "DemoAlarmSource", "Demo Alarm Source")
            .data_type(DataTypeId::Boolean)
            .value(false)
            .organized_by(&alarms_folder_id)
            .insert(&mut *address_space);

        VariableBuilder::new(&tank_level_node_id, "TankLevel", "Tank Level")
            .data_type(DataTypeId::Double)
            .value(50.0)
            .organized_by(&alarms_folder_id)
            .insert(&mut *address_space);
    }

    let condition = register_alarm_condition(
        manager.address_space(),
        &manager,
        "Demo",
        "Boolean",
        source_node_id.clone(),
        "Demo boolean alarm",
    );

    let limit_alarm_config = LimitConfig::new(LimitMode::Exclusive)
        .with_high_high(LimitDef {
            value: 90.0,
            deadband: 2.0,
            severity: 700,
        })
        .with_high(LimitDef {
            value: 80.0,
            deadband: 2.0,
            severity: 400,
        })
        .with_low(LimitDef {
            value: 20.0,
            deadband: 2.0,
            severity: 400,
        })
        .with_low_low(LimitDef {
            value: 10.0,
            deadband: 2.0,
            severity: 700,
        })
        .build()
        .expect("demo limit alarm configuration is valid");
    let limit_alarm = register_limit_alarm(
        manager.address_space(),
        &manager,
        "Demo",
        "TankLevelLimit",
        tank_level_node_id.clone(),
        limit_alarm_config,
    );

    let registry = ConditionRegistry::new();
    registry.register(condition.clone());
    registry.register(limit_alarm.condition_state_machine());
    register_condition_methods(
        &core_node_manager,
        registry,
        manager.address_space().clone(),
    );

    let limit_manager = manager.clone();
    let limit_subscriptions = subscriptions.clone();
    let limit_token = token.clone();
    tokio::task::spawn(async move {
        let mut active = false;
        let mut interval = tokio::time::interval(Duration::from_secs(5));

        while !token.is_cancelled() {
            interval.tick().await;
            active = !active;

            if let Err(status) = drive_alarm(
                &manager,
                &subscriptions,
                &condition,
                &source_node_id,
                active,
            ) {
                warn!("failed to drive demo alarm: {status:?}");
            }
        }
    });

    tokio::task::spawn(async move {
        let mut level = 50.0;
        let mut step = 5.0;
        let mut interval = tokio::time::interval(Duration::from_secs(2));

        while !limit_token.is_cancelled() {
            interval.tick().await;

            level += step;
            if level >= 95.0 {
                level = 95.0;
                step = -step;
            } else if level <= 5.0 {
                level = 5.0;
                step = -step;
            }

            if let Err(status) = drive_limit_alarm(
                &limit_manager,
                &limit_subscriptions,
                &limit_alarm,
                &tank_level_node_id,
                level,
            ) {
                warn!("failed to drive tank level limit alarm: {status:?}");
            }
        }
    });
}

fn drive_alarm(
    manager: &SimpleNodeManager,
    subscriptions: &SubscriptionCache,
    condition: &opcua::server::alarms::ConditionStateMachine,
    source_node_id: &NodeId,
    active: bool,
) -> Result<(), StatusCode> {
    manager.set_value(
        subscriptions,
        source_node_id,
        None,
        DataValue::new_now(active),
    )?;

    let event = {
        let address_space = manager.address_space();
        let mut address_space = address_space.write();
        trigger_alarm_transition(
            &mut address_space,
            condition,
            active,
            if active { 700 } else { 100 },
            if active {
                LocalizedText::new("en", "Demo alarm active")
            } else {
                LocalizedText::new("en", "Demo alarm inactive")
            },
        )?
    };

    if let Some(event) = event {
        let wrapper = ServerAlarmEvent { event: &event };
        subscriptions.notify_events(std::iter::once((
            &wrapper as &dyn Event,
            &event.source_node,
        )));
    }

    Ok(())
}

fn drive_limit_alarm(
    manager: &SimpleNodeManager,
    subscriptions: &SubscriptionCache,
    alarm: &LimitAlarm,
    source_node_id: &NodeId,
    level: f64,
) -> Result<(), StatusCode> {
    manager.set_value(
        subscriptions,
        source_node_id,
        None,
        DataValue::new_now(level),
    )?;

    let event = {
        let address_space = manager.address_space();
        let mut address_space = address_space.write();
        alarm.update_value(&mut address_space, level)
    };

    if let Some(event) = event {
        let wrapper = ServerAlarmEvent { event: &event };
        subscriptions.notify_events(std::iter::once((
            &wrapper as &dyn Event,
            &event.source_node,
        )));
    }

    Ok(())
}
