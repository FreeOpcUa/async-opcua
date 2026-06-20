use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::address_space::AddressSpace;
use opcua_core::sync::RwLock;
use opcua_nodes::NodeType;
use opcua_types::{DataValue, NodeId, StatusCode, Variant};

use crate::programs::state::{ProgramState, ProgramStateMachine};

/// The execution engine for a Program instance.
pub struct ProgramEngine {
    address_space: Arc<RwLock<AddressSpace>>,
    parent_id: NodeId,
    state_machine: Arc<RwLock<ProgramStateMachine>>,
    cancel_token: Arc<RwLock<CancellationToken>>,
    suspend_notify: Arc<Notify>,
    progress: Arc<RwLock<u8>>,
    task_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

impl ProgramEngine {
    /// Creates a new ProgramEngine for the specified parent NodeId.
    pub fn new(address_space: Arc<RwLock<AddressSpace>>, parent_id: NodeId) -> Self {
        let state_machine = Arc::new(RwLock::new(ProgramStateMachine::new(parent_id.clone())));
        Self {
            address_space,
            parent_id,
            state_machine,
            cancel_token: Arc::new(RwLock::new(CancellationToken::new())),
            suspend_notify: Arc::new(Notify::new()),
            progress: Arc::new(RwLock::new(0)),
            task_handle: Arc::new(RwLock::new(None)),
        }
    }

    /// Gets the current state of the program.
    pub fn state(&self) -> ProgramState {
        self.state_machine.read().state()
    }

    /// Gets the NodeId of the program.
    pub fn parent_id(&self) -> &NodeId {
        &self.parent_id
    }

    /// Gets the current progress (0-100).
    pub fn progress(&self) -> u8 {
        *self.progress.read()
    }

    #[cfg(test)]
    fn task_handle_for_test(&self) -> Arc<RwLock<Option<tokio::task::JoinHandle<()>>>> {
        Arc::clone(&self.task_handle)
    }

    /// Gets the NodeIds of sub-variables.
    fn sub_node_id(&self, suffix: &str) -> NodeId {
        let parent_str = match &self.parent_id.identifier {
            opcua_types::Identifier::String(s) => s.to_string(),
            other => other.to_string(),
        };
        NodeId::new(
            self.parent_id.namespace,
            format!("{}_{}", parent_str, suffix),
        )
    }

    /// Helper to update a variable value in the Address Space.
    fn update_variable<T: Into<Variant>>(&self, suffix: &str, value: T) {
        let var_id = self.sub_node_id(suffix);
        let space = self.address_space.write();
        if let Some(mut node) = space.find_mut(&var_id) {
            if let NodeType::Variable(ref mut var) = &mut *node {
                var.set_data_value(DataValue::value_only(value.into()));
            }
        };
    }

    /// Updates all Program state and permission variables in the Address Space.
    fn sync_address_space(&self, transition_name: &str) {
        let state = self.state();
        let state_machine = self.state_machine.read();

        self.update_variable("CurrentState", state.as_str().to_string());
        if !transition_name.is_empty() {
            self.update_variable("LastTransition", transition_name.to_string());
        }
        self.update_variable("Haltable", state_machine.can_halt());
        self.update_variable("Suspendable", state_machine.can_suspend());
        self.update_variable("Resumable", state_machine.can_resume());
        self.update_variable("Resetable", state_machine.can_reset());
        self.update_variable("Progress", self.progress() as i32);
    }

    /// Triggers the `Start` transition and spawns the background execution task.
    pub fn start(&self) -> Result<(), StatusCode> {
        {
            let mut sm = self.state_machine.write();
            sm.start()?;
        }

        // Reset progress and cancel token
        *self.progress.write() = 0;
        let cancel_token = CancellationToken::new();
        *self.cancel_token.write() = cancel_token.clone();

        self.sync_address_space("Start");

        // Spawn background task
        let progress = self.progress.clone();
        let sm_clone = self.state_machine.clone();
        let address_space = self.address_space.clone();
        let suspend_notify = self.suspend_notify.clone();
        let engine_parent_id = self.parent_id.clone();
        let parent_str = match &engine_parent_id.identifier {
            opcua_types::Identifier::String(s) => s.to_string(),
            other => other.to_string(),
        };

        let handle = tokio::spawn(async move {
            for i in 1..=100 {
                // Check for cancel
                if cancel_token.is_cancelled() {
                    break;
                }

                // If suspended, wait until notified
                while sm_clone.read().state() == ProgramState::Suspended {
                    tokio::select! {
                        _ = cancel_token.cancelled() => break,
                        _ = suspend_notify.notified() => {}
                    }
                }

                if cancel_token.is_cancelled() {
                    break;
                }

                tokio::time::sleep(Duration::from_millis(10)).await;

                *progress.write() = i;

                // Sync progress to AddressSpace dynamically
                let progress_id = NodeId::new(
                    engine_parent_id.namespace,
                    format!("{}_Progress", parent_str),
                );
                let space = address_space.write();
                if let Some(mut node) = space.find_mut(&progress_id) {
                    if let NodeType::Variable(ref mut var) = &mut *node {
                        var.set_data_value(DataValue::value_only(Variant::from(i as i32)));
                    }
                };
            }

            // Task complete: transition to Halted
            let mut sm_lock = sm_clone.write();
            if sm_lock.state() == ProgramState::Running {
                let _ = sm_lock.halt();
            }
            drop(sm_lock);

            // Sync state machine to AddressSpace
            let current_state_id = NodeId::new(
                engine_parent_id.namespace,
                format!("{}_CurrentState", parent_str),
            );
            let haltable_id = NodeId::new(
                engine_parent_id.namespace,
                format!("{}_Haltable", parent_str),
            );
            let suspendable_id = NodeId::new(
                engine_parent_id.namespace,
                format!("{}_Suspendable", parent_str),
            );
            let resumable_id = NodeId::new(
                engine_parent_id.namespace,
                format!("{}_Resumable", parent_str),
            );
            let resetable_id = NodeId::new(
                engine_parent_id.namespace,
                format!("{}_Resetable", parent_str),
            );

            let space = address_space.write();
            if let Some(mut node) = space.find_mut(&current_state_id) {
                if let NodeType::Variable(ref mut var) = &mut *node {
                    var.set_data_value(DataValue::value_only(Variant::from("Halted".to_string())));
                }
            };
            if let Some(mut node) = space.find_mut(&haltable_id) {
                if let NodeType::Variable(ref mut var) = &mut *node {
                    var.set_data_value(DataValue::value_only(Variant::from(false)));
                }
            };
            if let Some(mut node) = space.find_mut(&suspendable_id) {
                if let NodeType::Variable(ref mut var) = &mut *node {
                    var.set_data_value(DataValue::value_only(Variant::from(false)));
                }
            };
            if let Some(mut node) = space.find_mut(&resumable_id) {
                if let NodeType::Variable(ref mut var) = &mut *node {
                    var.set_data_value(DataValue::value_only(Variant::from(false)));
                }
            };
            if let Some(mut node) = space.find_mut(&resetable_id) {
                if let NodeType::Variable(ref mut var) = &mut *node {
                    var.set_data_value(DataValue::value_only(Variant::from(true)));
                }
            };
        });

        *self.task_handle.write() = Some(handle);
        Ok(())
    }

    /// Triggers the `Suspend` transition.
    pub fn suspend(&self) -> Result<(), StatusCode> {
        {
            let mut sm = self.state_machine.write();
            sm.suspend()?;
        }
        self.sync_address_space("Suspend");
        Ok(())
    }

    /// Triggers the `Resume` transition.
    pub fn resume(&self) -> Result<(), StatusCode> {
        {
            let mut sm = self.state_machine.write();
            sm.resume()?;
        }
        self.sync_address_space("Resume");
        // Notify the execution loop to continue
        self.suspend_notify.notify_one();
        Ok(())
    }

    /// Triggers the `Halt` transition and cancels execution.
    pub fn halt(&self) -> Result<(), StatusCode> {
        {
            let mut sm = self.state_machine.write();
            sm.halt()?;
        }
        self.cancel_token.read().cancel();
        self.sync_address_space("Halt");
        Ok(())
    }

    /// Triggers the `Reset` transition.
    pub fn reset(&self) -> Result<(), StatusCode> {
        {
            let mut sm = self.state_machine.write();
            sm.reset()?;
        }
        *self.progress.write() = 0;
        self.sync_address_space("Reset");
        Ok(())
    }
}

impl Drop for ProgramEngine {
    fn drop(&mut self) {
        self.cancel_token.read().cancel();
        self.suspend_notify.notify_waiters();

        if let Some(handle) = self.task_handle.read().as_ref() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use opcua_core::sync::RwLock;
    use opcua_types::NodeId;

    use crate::address_space::AddressSpace;

    use super::ProgramEngine;

    #[tokio::test]
    async fn dropping_suspended_engine_aborts_background_task() {
        let engine = ProgramEngine::new(
            Arc::new(RwLock::new(AddressSpace::new())),
            NodeId::new(2, "drop-suspended-engine"),
        );
        engine.reset().expect("reset should transition to Ready");
        engine.start().expect("start should spawn the task");
        let task_handle = engine.task_handle_for_test();

        engine
            .suspend()
            .expect("suspend should transition to Suspended");
        tokio::time::sleep(Duration::from_millis(30)).await;

        drop(engine);

        let finished = tokio::time::timeout(Duration::from_millis(75), async {
            loop {
                if task_handle
                    .read()
                    .as_ref()
                    .is_some_and(tokio::task::JoinHandle::is_finished)
                {
                    break true;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or(false);

        assert!(
            finished,
            "dropping a suspended ProgramEngine should abort its parked background task"
        );
    }
}
