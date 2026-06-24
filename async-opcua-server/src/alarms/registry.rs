//! Shared registry of alarm conditions for ConditionRefresh.

use crate::address_space::AddressSpace;
use crate::alarms::state_machine::ConditionStateMachine;
use opcua_core::sync::RwLock;
use opcua_types::NodeId;
use std::collections::HashMap;
use std::sync::Arc;

/// App-populated set of conditions available for refresh replay.
#[derive(Debug, Clone)]
pub struct ConditionRegistry {
    conditions: Arc<RwLock<HashMap<NodeId, ConditionStateMachine>>>,
}

impl Default for ConditionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ConditionRegistry {
    /// Creates an empty condition registry.
    pub fn new() -> Self {
        Self {
            conditions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Registers or replaces a condition by its condition id.
    pub fn register(&self, condition: ConditionStateMachine) {
        self.conditions
            .write()
            .insert(condition.condition_id.clone(), condition);
    }

    /// Returns a registered condition by condition id.
    pub fn get(&self, condition_id: &NodeId) -> Option<ConditionStateMachine> {
        self.conditions.read().get(condition_id).cloned()
    }

    /// Returns registered conditions whose Retain property currently reads true.
    pub fn iter_retained(&self, address_space: &AddressSpace) -> Vec<ConditionStateMachine> {
        self.conditions
            .read()
            .values()
            .filter(|condition| condition.get_retain(address_space))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iter_retained_returns_only_conditions_with_retain_true() {
        let mut address_space = AddressSpace::new();
        address_space.add_namespace("urn:test", 2);
        let retained = ConditionStateMachine::create_in_address_space(
            &mut address_space,
            "DeviceA",
            "High",
            NodeId::new(2, "DeviceA"),
            "Retained alarm",
        );
        let not_retained = ConditionStateMachine::create_in_address_space(
            &mut address_space,
            "DeviceB",
            "High",
            NodeId::new(2, "DeviceB"),
            "Cleared alarm",
        );
        retained.set_retain(&mut address_space, true);
        not_retained.set_retain(&mut address_space, false);

        let registry = ConditionRegistry::new();
        registry.register(retained.clone());
        registry.register(not_retained);

        let retained_conditions = registry.iter_retained(&address_space);

        assert_eq!(retained_conditions.len(), 1);
        assert_eq!(retained_conditions[0].condition_id, retained.condition_id);
    }
}
