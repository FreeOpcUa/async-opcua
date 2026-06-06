//! Client method acknowledgment callbacks and identity validation handlers for Alarms.

use crate::address_space::AddressSpace;
use crate::alarms::dispatch::ServerAlarmEvent;
use crate::alarms::state_machine::ConditionStateMachine;
use crate::alarms::transitions::{acknowledge_alarm, confirm_alarm};
use crate::node_manager::RequestContext;
use opcua_core::traits::ConditionMethodHandler;
use opcua_nodes::Event;
use opcua_types::{DateTime, LocalizedText, NodeId, StatusCode, Variant};
use std::sync::Arc;

/// Handler for Alarm Acknowledge/Confirm method calls.
pub struct AlarmMethodHandler {
    /// Associated Alarm condition state machine
    pub state_machine: ConditionStateMachine,
    /// Thread-safe reference to the AddressSpace
    pub address_space: Arc<opcua_core::sync::RwLock<AddressSpace>>,
}

impl ConditionMethodHandler for AlarmMethodHandler {
    fn handle_acknowledgment(
        &self,
        _session_id: &NodeId,
        condition_id: &NodeId,
        _event_id: &[u8],
        comment: &LocalizedText,
    ) -> Result<StatusCode, StatusCode> {
        if condition_id != &self.state_machine.condition_id {
            return Err(StatusCode::BadConditionDisabled);
        }

        let mut address_space = opcua_core::trace_write_lock!(self.address_space);
        match acknowledge_alarm(&mut address_space, &self.state_machine, comment.clone()) {
            Ok(_) => Ok(StatusCode::Good),
            Err(e) => Err(e),
        }
    }
}

impl AlarmMethodHandler {
    /// Creates a new `AlarmMethodHandler` instance.
    pub fn new(
        state_machine: ConditionStateMachine,
        address_space: Arc<opcua_core::sync::RwLock<AddressSpace>>,
    ) -> Self {
        Self {
            state_machine,
            address_space,
        }
    }

    /// Callback executed when the Acknowledge method is called by a client.
    pub fn handle_ack_method(
        &self,
        context: &RequestContext,
        args: &[Variant],
    ) -> Result<Vec<Variant>, StatusCode> {
        // FR-019: Trace user token securely (masking unencrypted token/key and logging SHA-256 hash)
        {
            let session = opcua_core::trace_read_lock!(context.session);
            if let crate::identity_token::IdentityToken::IssuedToken(ref token) =
                session.user_identity()
            {
                let token_str = String::from_utf8_lossy(token.token_data.as_ref());
                let hashed = opcua_core::logging::hash_jwt(&token_str);
                tracing::info!(
                    "Acknowledge called on alarm {} by user with token hash: {}",
                    self.state_machine.condition_name,
                    hashed
                );
            }
        }

        if args.len() < 2 {
            return Err(StatusCode::BadArgumentsMissing);
        }

        let event_id = match &args[0] {
            Variant::ByteString(ref b) => b.as_ref(),
            _ => return Err(StatusCode::BadTypeMismatch),
        };

        let comment = match &args[1] {
            Variant::LocalizedText(ref t) => (**t).clone(),
            _ => return Err(StatusCode::BadTypeMismatch),
        };

        let session_id = opcua_core::trace_read_lock!(context.session)
            .session_id()
            .clone();

        // Perform transition
        let res = self.handle_acknowledgment(
            &session_id,
            &self.state_machine.condition_id,
            event_id,
            &comment,
        );
        if let Err(status) = res {
            return Err(status);
        }

        // Prepare and route the event notification
        let address_space = opcua_core::trace_read_lock!(self.address_space);
        let active = self.state_machine.get_active(&address_space);
        let confirmed = self.state_machine.get_confirmed(&address_space);
        let severity = self.state_machine.get_severity(&address_space);
        let retain = active || !confirmed;

        let event = opcua_core::events::AlarmEvent {
            event_id: event_id.to_vec(),
            event_type: NodeId::new(0, 2915),
            source_node: self.state_machine.source_node_id.clone(),
            source_name: self.state_machine.condition_name.clone(),
            time: DateTime::now(),
            message: comment,
            severity,
            condition_id: self.state_machine.condition_id.clone(),
            condition_name: self.state_machine.condition_name.clone(),
            active_state: active,
            acked_state: true,
            confirmed_state: confirmed,
            retain,
        };

        let wrapper = ServerAlarmEvent { event: &event };
        let items = std::iter::once((&wrapper as &dyn Event, &event.source_node));
        context.subscriptions.notify_events(items);

        Ok(vec![])
    }

    /// Callback executed when the Confirm method is called by a client.
    pub fn handle_confirm_method(
        &self,
        context: &RequestContext,
        args: &[Variant],
    ) -> Result<Vec<Variant>, StatusCode> {
        {
            let session = opcua_core::trace_read_lock!(context.session);
            if let crate::identity_token::IdentityToken::IssuedToken(ref token) =
                session.user_identity()
            {
                let token_str = String::from_utf8_lossy(token.token_data.as_ref());
                let hashed = opcua_core::logging::hash_jwt(&token_str);
                tracing::info!(
                    "Confirm called on alarm {} by user with token hash: {}",
                    self.state_machine.condition_name,
                    hashed
                );
            }
        }

        if args.len() < 2 {
            return Err(StatusCode::BadArgumentsMissing);
        }

        let _event_id = match &args[0] {
            Variant::ByteString(ref b) => b.as_ref(),
            _ => return Err(StatusCode::BadTypeMismatch),
        };

        let comment = match &args[1] {
            Variant::LocalizedText(ref t) => (**t).clone(),
            _ => return Err(StatusCode::BadTypeMismatch),
        };

        let mut address_space = opcua_core::trace_write_lock!(self.address_space);
        match confirm_alarm(&mut address_space, &self.state_machine, comment) {
            Ok(Some(event)) => {
                let wrapper = ServerAlarmEvent { event: &event };
                let items = std::iter::once((&wrapper as &dyn Event, &event.source_node));
                context.subscriptions.notify_events(items);
                Ok(vec![])
            }
            Ok(None) => Ok(vec![]),
            Err(e) => Err(e),
        }
    }
}
