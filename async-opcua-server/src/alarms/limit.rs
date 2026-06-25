//! Limit-alarm evaluation and address-space wiring for ExclusiveLimitAlarmType and
//! NonExclusiveLimitAlarmType.

use crate::address_space::{AddressSpace, ObjectBuilder, VariableBuilder};
use crate::alarms::replace_condition_type_definition;
use crate::alarms::state_machine::ConditionStateMachine;
use opcua_core::events::AlarmEvent;
use opcua_nodes::{DefaultTypeTree, NodeType};
use opcua_types::{
    AttributeId, BrowseDirection, DataEncoding, DataTypeId, DateTime, LocalizedText, NodeId,
    NumericRange, ObjectTypeId, QualifiedName, Range, ReferenceTypeId, StatusCode,
    TimestampsToReturn, VariableTypeId, Variant,
};
use std::sync::Mutex;

const EXCLUSIVE_LIMIT_ALARM_TYPE_ID: u32 = 9341;
const NON_EXCLUSIVE_LIMIT_ALARM_TYPE_ID: u32 = 9906;
const EXCLUSIVE_STATE_HIGH_HIGH_ID: u32 = 9329;
const EXCLUSIVE_STATE_HIGH_ID: u32 = 9331;
const EXCLUSIVE_STATE_LOW_ID: u32 = 9333;
const EXCLUSIVE_STATE_LOW_LOW_ID: u32 = 9335;

/// Selects whether limit state is mutually exclusive or independently tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitMode {
    /// Only one currently exceeded limit can be active.
    Exclusive,
    /// Each configured limit is evaluated independently.
    NonExclusive,
}

/// One of the four process alarm limit bands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitLevel {
    /// High-high process limit.
    HighHigh,
    /// High process limit.
    High,
    /// Low process limit.
    Low,
    /// Low-low process limit.
    LowLow,
}

/// Threshold, hysteresis deadband, and severity for one process limit.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LimitDef {
    /// Threshold value that trips the limit.
    pub value: f64,
    /// Hysteresis distance used when clearing an exceeded limit.
    pub deadband: f64,
    /// OPC UA condition severity to report while this limit is active.
    pub severity: u16,
}

/// Configured process limits for an exclusive or non-exclusive limit alarm.
#[derive(Debug, Clone, PartialEq)]
pub struct LimitConfig {
    /// Evaluation mode for this limit alarm.
    pub mode: LimitMode,
    /// Optional high-high limit definition.
    pub high_high: Option<LimitDef>,
    /// Optional high limit definition.
    pub high: Option<LimitDef>,
    /// Optional low limit definition.
    pub low: Option<LimitDef>,
    /// Optional low-low limit definition.
    pub low_low: Option<LimitDef>,
}

impl LimitConfig {
    /// Starts building a limit configuration for the selected mode.
    #[must_use]
    pub fn new(mode: LimitMode) -> Self {
        Self {
            mode,
            high_high: None,
            high: None,
            low: None,
            low_low: None,
        }
    }

    /// Sets the high-high limit definition.
    #[must_use]
    pub fn with_high_high(mut self, limit: LimitDef) -> Self {
        self.high_high = Some(limit);
        self
    }

    /// Sets the high limit definition.
    #[must_use]
    pub fn with_high(mut self, limit: LimitDef) -> Self {
        self.high = Some(limit);
        self
    }

    /// Sets the low limit definition.
    #[must_use]
    pub fn with_low(mut self, limit: LimitDef) -> Self {
        self.low = Some(limit);
        self
    }

    /// Sets the low-low limit definition.
    #[must_use]
    pub fn with_low_low(mut self, limit: LimitDef) -> Self {
        self.low_low = Some(limit);
        self
    }

    /// Validates and returns the completed configuration.
    pub fn build(self) -> Result<Self, StatusCode> {
        self.validate()?;
        Ok(self)
    }

    /// Validates ordering, finite values, and deadband ranges.
    pub fn validate(&self) -> Result<(), StatusCode> {
        let limits = self.configured_limits();

        for (_, limit) in &limits {
            if !limit.value.is_finite()
                || !limit.deadband.is_finite()
                || limit.deadband.is_sign_negative()
            {
                return Err(StatusCode::BadOutOfRange);
            }
        }

        for pair in limits.windows(2) {
            let upper = pair[0].1;
            let lower = pair[1].1;
            if upper.value < lower.value {
                return Err(StatusCode::BadOutOfRange);
            }
        }

        for (index, (_, limit)) in limits.iter().enumerate() {
            let mut nearest_gap = f64::INFINITY;

            if let Some((_, upper)) = index
                .checked_sub(1)
                .and_then(|previous| limits.get(previous))
            {
                nearest_gap = nearest_gap.min(upper.value - limit.value);
            }

            if let Some((_, lower)) = limits.get(index + 1) {
                nearest_gap = nearest_gap.min(limit.value - lower.value);
            }

            if nearest_gap.is_finite() && limit.deadband >= nearest_gap {
                return Err(StatusCode::BadOutOfRange);
            }
        }

        Ok(())
    }

    /// Validates that all configured limit values fit inside the source variable EURange.
    pub fn validate_against_eurange(&self, low: f64, high: f64) -> Result<(), StatusCode> {
        for (_, limit) in self.configured_limits() {
            if limit.value < low || limit.value > high {
                return Err(StatusCode::BadOutOfRange);
            }
        }

        Ok(())
    }

    fn configured_limits(&self) -> Vec<(LimitLevel, LimitDef)> {
        let mut limits = Vec::with_capacity(4);

        if let Some(limit) = self.high_high {
            limits.push((LimitLevel::HighHigh, limit));
        }

        if let Some(limit) = self.high {
            limits.push((LimitLevel::High, limit));
        }

        if let Some(limit) = self.low {
            limits.push((LimitLevel::Low, limit));
        }

        if let Some(limit) = self.low_low {
            limits.push((LimitLevel::LowLow, limit));
        }

        limits
    }
}

/// Reads the EURange property of an AnalogItem source variable.
#[must_use]
pub fn read_eurange(address_space: &AddressSpace, source_node_id: &NodeId) -> Option<(f64, f64)> {
    let type_tree = DefaultTypeTree::new();
    let eurange_node = address_space.find_node_by_browse_name(
        source_node_id,
        Some((ReferenceTypeId::HasProperty, false)),
        &type_tree,
        BrowseDirection::Forward,
        QualifiedName::from("EURange"),
    )?;

    let value = eurange_node
        .as_node()
        .get_attribute(
            TimestampsToReturn::Neither,
            AttributeId::Value,
            &NumericRange::None,
            &DataEncoding::Binary,
        )
        .and_then(|data_value| data_value.value)?;

    match value {
        Variant::ExtensionObject(eurange) => eurange
            .inner_as::<Range>()
            .map(|range| (range.low, range.high)),
        _ => None,
    }
}

/// Active flags for a non-exclusive limit alarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NonExclusiveState {
    /// Whether the high-high limit is active.
    pub high_high: bool,
    /// Whether the high limit is active.
    pub high: bool,
    /// Whether the low limit is active.
    pub low: bool,
    /// Whether the low-low limit is active.
    pub low_low: bool,
}

/// Current active limit state for either alarm mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveLimits {
    /// Exclusive mode state; `None` means inactive.
    Exclusive(Option<LimitLevel>),
    /// Non-exclusive mode state.
    NonExclusive(NonExclusiveState),
}

/// Result of evaluating a process value against limit alarm configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitOutcome {
    /// Active limit state after evaluation.
    pub limits: ActiveLimits,
    /// Whether any limit is active.
    pub active: bool,
    /// Effective severity for the active limit state.
    pub severity: u16,
    /// Human-readable condition message.
    pub message: String,
}

/// Id properties for configured NonExclusiveLimitAlarmType state variables.
#[derive(Debug, Clone, Default)]
pub struct NonExclusiveLimitStateIds {
    /// HighHighState.Id node, when HighHigh is configured.
    pub high_high: Option<NodeId>,
    /// HighState.Id node, when High is configured.
    pub high: Option<NodeId>,
    /// LowState.Id node, when Low is configured.
    pub low: Option<NodeId>,
    /// LowLowState.Id node, when LowLow is configured.
    pub low_low: Option<NodeId>,
}

impl NonExclusiveLimitStateIds {
    fn set(&mut self, level: LimitLevel, id: NodeId) {
        match level {
            LimitLevel::HighHigh => self.high_high = Some(id),
            LimitLevel::High => self.high = Some(id),
            LimitLevel::Low => self.low = Some(id),
            LimitLevel::LowLow => self.low_low = Some(id),
        }
    }
}

/// Pure limit alarm evaluator with deadband hysteresis.
pub struct LimitEvaluator;

impl LimitEvaluator {
    /// Evaluates a new process value against the configuration and previous state.
    #[must_use]
    pub fn evaluate(value: f64, cfg: &LimitConfig, prev: &ActiveLimits) -> LimitOutcome {
        if !value.is_finite() {
            return outcome_for_existing_state(previous_for_mode(cfg.mode, prev), cfg);
        }

        match cfg.mode {
            LimitMode::Exclusive => evaluate_exclusive(value, cfg, prev),
            LimitMode::NonExclusive => evaluate_non_exclusive(value, cfg, prev),
        }
    }
}

/// Address-space nodes and runtime state for a process limit alarm.
#[derive(Debug)]
pub struct LimitAlarm {
    /// Base A&C lifecycle state machine.
    pub condition: ConditionStateMachine,
    /// Limit thresholds, deadbands, severities, and evaluation mode.
    pub config: LimitConfig,
    /// Exclusive LimitState.CurrentState variable node.
    pub limit_current_state_id: NodeId,
    /// Exclusive LimitState.CurrentState.Id property node.
    pub limit_current_state_id_id: NodeId,
    /// Non-exclusive state Id property nodes.
    pub non_exclusive_state_ids: NonExclusiveLimitStateIds,
    /// Previous evaluator state used for deadband hysteresis.
    pub prev: Mutex<ActiveLimits>,
}

impl LimitAlarm {
    /// Returns the base condition state machine for registry integration.
    #[must_use]
    pub fn condition_state_machine(&self) -> ConditionStateMachine {
        self.condition.clone()
    }

    /// Creates an ExclusiveLimitAlarmType instance and its LimitState nodes in the address space.
    pub fn create_exclusive_in_address_space(
        address_space: &mut AddressSpace,
        ns: u16,
        device: &str,
        alarm_name: &str,
        source_node_id: NodeId,
        cfg: LimitConfig,
    ) -> Self {
        let condition = ConditionStateMachine::create_in_address_space(
            address_space,
            device,
            alarm_name,
            source_node_id,
            alarm_name,
        );

        replace_condition_type_definition(
            address_space,
            &condition.condition_id,
            NodeId::from(ObjectTypeId::ExclusiveLimitAlarmType),
        );

        let base_s = format!("Alarm_{}_{}", device, alarm_name);
        for (level, limit) in cfg.configured_limits() {
            add_limit_property(
                address_space,
                ns,
                &condition.condition_id,
                &base_s,
                level,
                limit,
            );
            add_deadband_property(
                address_space,
                ns,
                &condition.condition_id,
                &base_s,
                level,
                limit,
            );
        }

        let limit_state_id = NodeId::new(ns, format!("{}_LimitState", base_s));
        let limit_current_state_id = NodeId::new(ns, format!("{}_LimitState_CurrentState", base_s));
        let limit_current_state_id_id =
            NodeId::new(ns, format!("{}_LimitState_CurrentState_Id", base_s));

        ObjectBuilder::new(&limit_state_id, "LimitState", "LimitState")
            .has_type_definition(ObjectTypeId::ExclusiveLimitStateMachineType)
            .component_of(condition.condition_id.clone())
            .insert(address_space);

        VariableBuilder::new(&limit_current_state_id, "CurrentState", "CurrentState")
            .data_type(DataTypeId::LocalizedText)
            .has_type_definition(VariableTypeId::StateVariableType)
            .value(LocalizedText::null())
            .writable()
            .component_of(limit_state_id.clone())
            .insert(address_space);

        VariableBuilder::new(&limit_current_state_id_id, "Id", "Id")
            .data_type(DataTypeId::NodeId)
            .has_type_definition(VariableTypeId::PropertyType)
            .value(NodeId::null())
            .writable()
            .property_of(limit_current_state_id.clone())
            .insert(address_space);

        let initial_prev = inactive_limits_for_mode(cfg.mode);

        Self {
            condition,
            config: cfg,
            limit_current_state_id,
            limit_current_state_id_id,
            non_exclusive_state_ids: NonExclusiveLimitStateIds::default(),
            prev: Mutex::new(initial_prev),
        }
    }

    /// Creates a NonExclusiveLimitAlarmType instance and its limit state nodes in the address space.
    pub fn create_non_exclusive_in_address_space(
        address_space: &mut AddressSpace,
        ns: u16,
        device: &str,
        alarm_name: &str,
        source_node_id: NodeId,
        cfg: LimitConfig,
    ) -> Self {
        let condition = ConditionStateMachine::create_in_address_space(
            address_space,
            device,
            alarm_name,
            source_node_id,
            alarm_name,
        );

        replace_condition_type_definition(
            address_space,
            &condition.condition_id,
            NodeId::from(ObjectTypeId::NonExclusiveLimitAlarmType),
        );

        let base_s = format!("Alarm_{}_{}", device, alarm_name);
        let mut non_exclusive_state_ids = NonExclusiveLimitStateIds::default();

        for (level, limit) in cfg.configured_limits() {
            add_limit_property(
                address_space,
                ns,
                &condition.condition_id,
                &base_s,
                level,
                limit,
            );
            add_deadband_property(
                address_space,
                ns,
                &condition.condition_id,
                &base_s,
                level,
                limit,
            );

            let state_id = add_non_exclusive_limit_state(
                address_space,
                ns,
                &condition.condition_id,
                &base_s,
                level,
            );
            non_exclusive_state_ids.set(level, state_id);
        }

        let initial_prev = inactive_limits_for_mode(cfg.mode);

        Self {
            condition,
            config: cfg,
            limit_current_state_id: NodeId::null(),
            limit_current_state_id_id: NodeId::null(),
            non_exclusive_state_ids,
            prev: Mutex::new(initial_prev),
        }
    }

    /// Evaluates and writes a new process value, returning an alarm event when the limit state changes.
    pub fn update_value(&self, address_space: &mut AddressSpace, value: f64) -> Option<AlarmEvent> {
        if !self.condition.get_enabled(address_space) {
            return None;
        }

        let (previous, outcome) = {
            let mut prev = self.prev.lock().unwrap();
            let previous = *prev;
            let outcome = LimitEvaluator::evaluate(value, &self.config, &previous);
            *prev = outcome.limits;
            (previous, outcome)
        };

        if previous == outcome.limits {
            return None;
        }

        let message = LocalizedText::new("en", &outcome.message);
        let was_active = self.condition.get_active(address_space);
        let was_acked = self.condition.get_acked(address_space);
        if was_active && !was_acked && !outcome.active {
            self.condition.create_branch(address_space);
        }
        self.condition.set_active(address_space, outcome.active);
        self.condition.set_severity(address_space, outcome.severity);
        self.condition.set_message(address_space, message.clone());

        if outcome.active {
            self.condition.set_acked(address_space, false);
            self.condition.set_confirmed(address_space, false);
        }

        let acked = self.condition.get_acked(address_space);
        let confirmed = self.condition.get_confirmed(address_space);
        let retain = outcome.active || !acked || !confirmed;
        self.condition.set_retain(address_space, retain);
        self.write_limit_state(address_space, outcome.limits);

        let event_id = uuid::Uuid::new_v4().as_bytes().to_vec();
        self.condition.set_current_event_id(&event_id);

        Some(AlarmEvent {
            event_id,
            event_type: event_type_id(self.config.mode),
            source_node: self.condition.source_node_id.clone(),
            source_name: self.condition.condition_name.clone(),
            time: DateTime::now(),
            message,
            severity: outcome.severity,
            condition_id: self.condition.condition_id.clone(),
            branch_id: NodeId::null(),
            condition_name: self.condition.condition_name.clone(),
            active_state: outcome.active,
            acked_state: acked,
            confirmed_state: confirmed,
            retain,
        })
    }

    fn write_limit_state(&self, address_space: &mut AddressSpace, limits: ActiveLimits) {
        match self.config.mode {
            LimitMode::Exclusive => self.write_exclusive_limit_state(address_space, limits),
            LimitMode::NonExclusive => self.write_non_exclusive_limit_state(address_space, limits),
        }
    }

    fn write_exclusive_limit_state(&self, address_space: &mut AddressSpace, limits: ActiveLimits) {
        let level = match limits {
            ActiveLimits::Exclusive(level) => level,
            ActiveLimits::NonExclusive(_) => None,
        };

        let (text, id) = level.map_or_else(
            || (LocalizedText::null(), NodeId::null()),
            |level| {
                (
                    LocalizedText::new("en", level_name(level)),
                    exclusive_state_id(level),
                )
            },
        );

        set_variable_value(
            address_space,
            &self.limit_current_state_id,
            Variant::from(text),
        );
        set_variable_value(
            address_space,
            &self.limit_current_state_id_id,
            Variant::from(id),
        );
    }

    fn write_non_exclusive_limit_state(
        &self,
        address_space: &mut AddressSpace,
        limits: ActiveLimits,
    ) {
        let state = match limits {
            ActiveLimits::NonExclusive(state) => state,
            ActiveLimits::Exclusive(_) => NonExclusiveState::default(),
        };

        if let Some(id) = &self.non_exclusive_state_ids.high_high {
            set_variable_value(address_space, id, Variant::from(state.high_high));
        }
        if let Some(id) = &self.non_exclusive_state_ids.high {
            set_variable_value(address_space, id, Variant::from(state.high));
        }
        if let Some(id) = &self.non_exclusive_state_ids.low {
            set_variable_value(address_space, id, Variant::from(state.low));
        }
        if let Some(id) = &self.non_exclusive_state_ids.low_low {
            set_variable_value(address_space, id, Variant::from(state.low_low));
        }
    }
}

fn evaluate_exclusive(value: f64, cfg: &LimitConfig, prev: &ActiveLimits) -> LimitOutcome {
    let previous = match prev {
        ActiveLimits::Exclusive(level) => *level,
        ActiveLimits::NonExclusive(_) => None,
    };

    let high_high = cfg
        .high_high
        .map(|limit| high_exceeded(value, limit, previous == Some(LimitLevel::HighHigh)))
        .unwrap_or(false);
    let high = cfg
        .high
        .map(|limit| high_exceeded(value, limit, previous == Some(LimitLevel::High)))
        .unwrap_or(false);
    let low = cfg
        .low
        .map(|limit| low_exceeded(value, limit, previous == Some(LimitLevel::Low)))
        .unwrap_or(false);
    let low_low = cfg
        .low_low
        .map(|limit| low_exceeded(value, limit, previous == Some(LimitLevel::LowLow)))
        .unwrap_or(false);

    let level = if high_high {
        Some(LimitLevel::HighHigh)
    } else if high {
        Some(LimitLevel::High)
    } else if low_low {
        Some(LimitLevel::LowLow)
    } else if low {
        Some(LimitLevel::Low)
    } else {
        None
    };

    outcome_for_existing_state(ActiveLimits::Exclusive(level), cfg)
}

fn evaluate_non_exclusive(value: f64, cfg: &LimitConfig, prev: &ActiveLimits) -> LimitOutcome {
    let previous = match prev {
        ActiveLimits::NonExclusive(state) => *state,
        ActiveLimits::Exclusive(_) => NonExclusiveState::default(),
    };

    let state = NonExclusiveState {
        high_high: cfg
            .high_high
            .map(|limit| high_exceeded(value, limit, previous.high_high))
            .unwrap_or(false),
        high: cfg
            .high
            .map(|limit| high_exceeded(value, limit, previous.high))
            .unwrap_or(false),
        low: cfg
            .low
            .map(|limit| low_exceeded(value, limit, previous.low))
            .unwrap_or(false),
        low_low: cfg
            .low_low
            .map(|limit| low_exceeded(value, limit, previous.low_low))
            .unwrap_or(false),
    };

    outcome_for_existing_state(ActiveLimits::NonExclusive(state), cfg)
}

fn high_exceeded(value: f64, limit: LimitDef, was_exceeded: bool) -> bool {
    if value > limit.value {
        return true;
    }

    limit.deadband > 0.0 && was_exceeded && value >= limit.value - limit.deadband
}

fn low_exceeded(value: f64, limit: LimitDef, was_exceeded: bool) -> bool {
    if value < limit.value {
        return true;
    }

    limit.deadband > 0.0 && was_exceeded && value <= limit.value + limit.deadband
}

fn previous_for_mode(mode: LimitMode, prev: &ActiveLimits) -> ActiveLimits {
    match (mode, prev) {
        (LimitMode::Exclusive, ActiveLimits::Exclusive(level)) => ActiveLimits::Exclusive(*level),
        (LimitMode::Exclusive, ActiveLimits::NonExclusive(_)) => ActiveLimits::Exclusive(None),
        (LimitMode::NonExclusive, ActiveLimits::NonExclusive(state)) => {
            ActiveLimits::NonExclusive(*state)
        }
        (LimitMode::NonExclusive, ActiveLimits::Exclusive(_)) => {
            ActiveLimits::NonExclusive(NonExclusiveState::default())
        }
    }
}

fn inactive_limits_for_mode(mode: LimitMode) -> ActiveLimits {
    match mode {
        LimitMode::Exclusive => ActiveLimits::Exclusive(None),
        LimitMode::NonExclusive => ActiveLimits::NonExclusive(NonExclusiveState::default()),
    }
}

fn outcome_for_existing_state(limits: ActiveLimits, cfg: &LimitConfig) -> LimitOutcome {
    match limits {
        ActiveLimits::Exclusive(level) => {
            let severity = level
                .and_then(|level| cfg.limit_def(level))
                .map_or(0, |limit| limit.severity);
            let active = level.is_some();
            let message = level.map_or_else(|| "Normal".to_string(), limit_message);

            LimitOutcome {
                limits: ActiveLimits::Exclusive(level),
                active,
                severity,
                message,
            }
        }
        ActiveLimits::NonExclusive(state) => {
            let mut active_levels = Vec::with_capacity(4);
            let mut severity = 0;

            for (is_active, level) in [
                (state.high_high, LimitLevel::HighHigh),
                (state.high, LimitLevel::High),
                (state.low, LimitLevel::Low),
                (state.low_low, LimitLevel::LowLow),
            ] {
                if is_active {
                    active_levels.push(level);
                    if let Some(limit) = cfg.limit_def(level) {
                        severity = severity.max(limit.severity);
                    }
                }
            }

            let active = !active_levels.is_empty();
            let message = if active {
                active_set_message(&active_levels)
            } else {
                "Normal".to_string()
            };

            LimitOutcome {
                limits: ActiveLimits::NonExclusive(state),
                active,
                severity,
                message,
            }
        }
    }
}

impl LimitConfig {
    fn limit_def(&self, level: LimitLevel) -> Option<LimitDef> {
        match level {
            LimitLevel::HighHigh => self.high_high,
            LimitLevel::High => self.high,
            LimitLevel::Low => self.low,
            LimitLevel::LowLow => self.low_low,
        }
    }
}

fn limit_message(level: LimitLevel) -> String {
    format!("{} limit exceeded", level_name(level))
}

fn active_set_message(levels: &[LimitLevel]) -> String {
    let names = levels
        .iter()
        .map(|level| level_name(*level))
        .collect::<Vec<_>>()
        .join(", ");

    if levels.len() == 1 {
        format!("{names} limit exceeded")
    } else {
        format!("{names} limits exceeded")
    }
}

fn level_name(level: LimitLevel) -> &'static str {
    match level {
        LimitLevel::HighHigh => "HighHigh",
        LimitLevel::High => "High",
        LimitLevel::Low => "Low",
        LimitLevel::LowLow => "LowLow",
    }
}

fn add_limit_property(
    address_space: &mut AddressSpace,
    ns: u16,
    condition_id: &NodeId,
    base_s: &str,
    level: LimitLevel,
    limit: LimitDef,
) {
    let (name, _) = limit_property_names(level);
    add_double_property(
        address_space,
        &NodeId::new(ns, format!("{}_{}", base_s, name)),
        condition_id,
        name,
        limit.value,
    );
}

fn add_deadband_property(
    address_space: &mut AddressSpace,
    ns: u16,
    condition_id: &NodeId,
    base_s: &str,
    level: LimitLevel,
    limit: LimitDef,
) {
    let (_, name) = limit_property_names(level);
    add_double_property(
        address_space,
        &NodeId::new(ns, format!("{}_{}", base_s, name)),
        condition_id,
        name,
        limit.deadband,
    );
}

fn add_double_property(
    address_space: &mut AddressSpace,
    node_id: &NodeId,
    parent_id: &NodeId,
    name: &str,
    value: f64,
) {
    VariableBuilder::new(node_id, name, name)
        .data_type(DataTypeId::Double)
        .has_type_definition(VariableTypeId::PropertyType)
        .value(value)
        .writable()
        .property_of(parent_id.clone())
        .insert(address_space);
}

fn add_non_exclusive_limit_state(
    address_space: &mut AddressSpace,
    ns: u16,
    condition_id: &NodeId,
    base_s: &str,
    level: LimitLevel,
) -> NodeId {
    let browse_name = non_exclusive_state_browse_name(level);
    let state_id = NodeId::new(ns, format!("{}_{}", base_s, browse_name));
    let id_id = NodeId::new(ns, format!("{}_{}_Id", base_s, browse_name));
    let true_state_id = NodeId::new(ns, format!("{}_{}_TrueState", base_s, browse_name));
    let false_state_id = NodeId::new(ns, format!("{}_{}_FalseState", base_s, browse_name));

    VariableBuilder::new(&state_id, browse_name, browse_name)
        .data_type(DataTypeId::Boolean)
        .has_type_definition(VariableTypeId::TwoStateVariableType)
        .value(false)
        .writable()
        .component_of(condition_id.clone())
        .insert(address_space);

    VariableBuilder::new(&id_id, "Id", "Id")
        .data_type(DataTypeId::Boolean)
        .has_type_definition(VariableTypeId::PropertyType)
        .value(false)
        .writable()
        .property_of(state_id.clone())
        .insert(address_space);

    add_localized_text_property(
        address_space,
        &true_state_id,
        &state_id,
        "TrueState",
        LocalizedText::new("en", non_exclusive_state_text(level, true)),
    );
    add_localized_text_property(
        address_space,
        &false_state_id,
        &state_id,
        "FalseState",
        LocalizedText::new("en", non_exclusive_state_text(level, false)),
    );

    id_id
}

fn add_localized_text_property(
    address_space: &mut AddressSpace,
    node_id: &NodeId,
    parent_id: &NodeId,
    name: &str,
    value: LocalizedText,
) {
    VariableBuilder::new(node_id, name, name)
        .data_type(DataTypeId::LocalizedText)
        .has_type_definition(VariableTypeId::PropertyType)
        .value(value)
        .writable()
        .property_of(parent_id.clone())
        .insert(address_space);
}

fn limit_property_names(level: LimitLevel) -> (&'static str, &'static str) {
    match level {
        LimitLevel::HighHigh => ("HighHighLimit", "HighHighDeadband"),
        LimitLevel::High => ("HighLimit", "HighDeadband"),
        LimitLevel::Low => ("LowLimit", "LowDeadband"),
        LimitLevel::LowLow => ("LowLowLimit", "LowLowDeadband"),
    }
}

fn exclusive_state_id(level: LimitLevel) -> NodeId {
    match level {
        LimitLevel::HighHigh => NodeId::new(0, EXCLUSIVE_STATE_HIGH_HIGH_ID),
        LimitLevel::High => NodeId::new(0, EXCLUSIVE_STATE_HIGH_ID),
        LimitLevel::Low => NodeId::new(0, EXCLUSIVE_STATE_LOW_ID),
        LimitLevel::LowLow => NodeId::new(0, EXCLUSIVE_STATE_LOW_LOW_ID),
    }
}

fn event_type_id(mode: LimitMode) -> NodeId {
    match mode {
        LimitMode::Exclusive => NodeId::new(0, EXCLUSIVE_LIMIT_ALARM_TYPE_ID),
        LimitMode::NonExclusive => NodeId::new(0, NON_EXCLUSIVE_LIMIT_ALARM_TYPE_ID),
    }
}

fn non_exclusive_state_browse_name(level: LimitLevel) -> &'static str {
    match level {
        LimitLevel::HighHigh => "HighHighState",
        LimitLevel::High => "HighState",
        LimitLevel::Low => "LowState",
        LimitLevel::LowLow => "LowLowState",
    }
}

fn non_exclusive_state_text(level: LimitLevel, active: bool) -> &'static str {
    match (level, active) {
        (LimitLevel::HighHigh, true) => "High High active",
        (LimitLevel::HighHigh, false) => "High High inactive",
        (LimitLevel::High, true) => "High active",
        (LimitLevel::High, false) => "High inactive",
        (LimitLevel::Low, true) => "Low active",
        (LimitLevel::Low, false) => "Low inactive",
        (LimitLevel::LowLow, true) => "Low Low active",
        (LimitLevel::LowLow, false) => "Low Low inactive",
    }
}

fn set_variable_value(address_space: &mut AddressSpace, node_id: &NodeId, value: Variant) {
    if let Some(mut node) = address_space.find_mut(node_id) {
        if let NodeType::Variable(ref mut var) = &mut *node {
            let _ = var.set_value(&opcua_types::NumericRange::None, value);
        }
    }
}
