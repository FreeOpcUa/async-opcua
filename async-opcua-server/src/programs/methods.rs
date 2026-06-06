//! Client method callbacks and registration for Program execution.

use crate::address_space::{AddressSpace, ObjectBuilder, VariableBuilder};
use crate::node_manager::RequestContext;
use crate::programs::engine::ProgramEngine;
use opcua_types::{NodeId, StatusCode, Variant};
use std::sync::Arc;

/// Handler for Program control method calls.
pub struct ProgramMethodHandler {
    /// Associated Program execution engine
    pub engine: Arc<ProgramEngine>,
}

impl ProgramMethodHandler {
    /// Creates a new `ProgramMethodHandler` instance.
    pub fn new(engine: Arc<ProgramEngine>) -> Self {
        Self { engine }
    }

    /// Callback executed when the Start method is called.
    pub fn handle_start(
        &self,
        context: &RequestContext,
        _args: &[Variant],
    ) -> Result<Vec<Variant>, StatusCode> {
        self.trace_user_token("Start", context);
        self.engine.start()?;
        Ok(vec![])
    }

    /// Callback executed when the Suspend method is called.
    pub fn handle_suspend(
        &self,
        context: &RequestContext,
        _args: &[Variant],
    ) -> Result<Vec<Variant>, StatusCode> {
        self.trace_user_token("Suspend", context);
        self.engine.suspend()?;
        Ok(vec![])
    }

    /// Callback executed when the Resume method is called.
    pub fn handle_resume(
        &self,
        context: &RequestContext,
        _args: &[Variant],
    ) -> Result<Vec<Variant>, StatusCode> {
        self.trace_user_token("Resume", context);
        self.engine.resume()?;
        Ok(vec![])
    }

    /// Callback executed when the Halt method is called.
    pub fn handle_halt(
        &self,
        context: &RequestContext,
        _args: &[Variant],
    ) -> Result<Vec<Variant>, StatusCode> {
        self.trace_user_token("Halt", context);
        self.engine.halt()?;
        Ok(vec![])
    }

    /// Callback executed when the Reset method is called.
    pub fn handle_reset(
        &self,
        context: &RequestContext,
        _args: &[Variant],
    ) -> Result<Vec<Variant>, StatusCode> {
        self.trace_user_token("Reset", context);
        self.engine.reset()?;
        Ok(vec![])
    }

    fn trace_user_token(&self, method: &str, context: &RequestContext) {
        let session = opcua_core::trace_read_lock!(context.session);
        if let crate::identity_token::IdentityToken::IssuedToken(ref token) =
            session.user_identity()
        {
            let token_str = String::from_utf8_lossy(token.token_data.as_ref());
            let hashed = opcua_core::logging::hash_jwt(&token_str);
            tracing::info!(
                "{} called on program {} by user with token hash: {}",
                method,
                self.engine.parent_id(),
                hashed
            );
        }
    }
}

/// Registers a new Program and its associated control methods in the AddressSpace.
pub fn register_program(
    address_space: &Arc<opcua_core::sync::RwLock<AddressSpace>>,
    node_manager: &crate::node_manager::memory::SimpleNodeManager,
    device: &str,
    name: &str,
) -> Arc<ProgramEngine> {
    let ns_idx = 2; // Dynamic namespace
    let base_s = format!("Program_{}_{}", device, name);
    let parent_id = NodeId::new(ns_idx, base_s.clone());

    // 1. Create the Program object node
    // ProgramStateMachineType (i=2393)
    let program_obj = ObjectBuilder::new(&parent_id, base_s.clone(), name)
        .has_type_definition(NodeId::new(0, 2393))
        .build();

    {
        let mut space = opcua_core::trace_write_lock!(address_space);
        space.insert::<_, NodeId>(program_obj, None);
    }

    // 2. Create the associated engine
    let engine = Arc::new(ProgramEngine::new(address_space.clone(), parent_id.clone()));

    // 3. Create the state, permission, and progress variable nodes
    let current_state_id = NodeId::new(ns_idx, format!("{}_CurrentState", base_s));
    let last_transition_id = NodeId::new(ns_idx, format!("{}_LastTransition", base_s));
    let haltable_id = NodeId::new(ns_idx, format!("{}_Haltable", base_s));
    let suspendable_id = NodeId::new(ns_idx, format!("{}_Suspendable", base_s));
    let resumable_id = NodeId::new(ns_idx, format!("{}_Resumable", base_s));
    let resetable_id = NodeId::new(ns_idx, format!("{}_Resetable", base_s));
    let progress_id = NodeId::new(ns_idx, format!("{}_Progress", base_s));

    {
        let mut space = opcua_core::trace_write_lock!(address_space);

        // CurrentState (String)
        let current_state_var =
            VariableBuilder::new(&current_state_id, "CurrentState", "CurrentState")
                .data_type(opcua_types::DataTypeId::String)
                .value("Halted".to_string())
                .build();
        space.insert(
            current_state_var,
            Some(&[(
                &parent_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        // LastTransition (String)
        let last_transition_var =
            VariableBuilder::new(&last_transition_id, "LastTransition", "LastTransition")
                .data_type(opcua_types::DataTypeId::String)
                .value("".to_string())
                .build();
        space.insert(
            last_transition_var,
            Some(&[(
                &parent_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        // Haltable (Boolean)
        let haltable_var = VariableBuilder::new(&haltable_id, "Haltable", "Haltable")
            .data_type(opcua_types::DataTypeId::Boolean)
            .value(false)
            .build();
        space.insert(
            haltable_var,
            Some(&[(
                &parent_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        // Suspendable (Boolean)
        let suspendable_var = VariableBuilder::new(&suspendable_id, "Suspendable", "Suspendable")
            .data_type(opcua_types::DataTypeId::Boolean)
            .value(false)
            .build();
        space.insert(
            suspendable_var,
            Some(&[(
                &parent_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        // Resumable (Boolean)
        let resumable_var = VariableBuilder::new(&resumable_id, "Resumable", "Resumable")
            .data_type(opcua_types::DataTypeId::Boolean)
            .value(false)
            .build();
        space.insert(
            resumable_var,
            Some(&[(
                &parent_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        // Resetable (Boolean)
        let resetable_var = VariableBuilder::new(&resetable_id, "Resetable", "Resetable")
            .data_type(opcua_types::DataTypeId::Boolean)
            .value(true)
            .build();
        space.insert(
            resetable_var,
            Some(&[(
                &parent_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        // Progress (Int32)
        let progress_var = VariableBuilder::new(&progress_id, "Progress", "Progress")
            .data_type(opcua_types::DataTypeId::Int32)
            .value(0i32)
            .build();
        space.insert(
            progress_var,
            Some(&[(
                &parent_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );
    }

    // 4. Create the method nodes under the Program object
    let start_method_id = NodeId::new(ns_idx, format!("{}_Start", base_s));
    let suspend_method_id = NodeId::new(ns_idx, format!("{}_Suspend", base_s));
    let resume_method_id = NodeId::new(ns_idx, format!("{}_Resume", base_s));
    let halt_method_id = NodeId::new(ns_idx, format!("{}_Halt", base_s));
    let reset_method_id = NodeId::new(ns_idx, format!("{}_Reset", base_s));

    {
        let mut space = opcua_core::trace_write_lock!(address_space);

        let start_method = opcua_nodes::MethodBuilder::new(&start_method_id, "Start", "Start")
            .component_of(parent_id.clone())
            .build();
        space.insert(
            start_method,
            Some(&[(
                &parent_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        let suspend_method =
            opcua_nodes::MethodBuilder::new(&suspend_method_id, "Suspend", "Suspend")
                .component_of(parent_id.clone())
                .build();
        space.insert(
            suspend_method,
            Some(&[(
                &parent_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        let resume_method = opcua_nodes::MethodBuilder::new(&resume_method_id, "Resume", "Resume")
            .component_of(parent_id.clone())
            .build();
        space.insert(
            resume_method,
            Some(&[(
                &parent_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        let halt_method = opcua_nodes::MethodBuilder::new(&halt_method_id, "Halt", "Halt")
            .component_of(parent_id.clone())
            .build();
        space.insert(
            halt_method,
            Some(&[(
                &parent_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        let reset_method = opcua_nodes::MethodBuilder::new(&reset_method_id, "Reset", "Reset")
            .component_of(parent_id.clone())
            .build();
        space.insert(
            reset_method,
            Some(&[(
                &parent_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );
    }

    // 5. Register the callbacks with the SimpleNodeManager using method callbacks
    let handler = Arc::new(ProgramMethodHandler::new(engine.clone()));

    let h_start = handler.clone();
    node_manager
        .inner()
        .add_method_callback_with_context(start_method_id, move |ctx, args| {
            h_start.handle_start(ctx, args)
        });

    let h_suspend = handler.clone();
    node_manager
        .inner()
        .add_method_callback_with_context(suspend_method_id, move |ctx, args| {
            h_suspend.handle_suspend(ctx, args)
        });

    let h_resume = handler.clone();
    node_manager
        .inner()
        .add_method_callback_with_context(resume_method_id, move |ctx, args| {
            h_resume.handle_resume(ctx, args)
        });

    let h_halt = handler.clone();
    node_manager
        .inner()
        .add_method_callback_with_context(halt_method_id, move |ctx, args| {
            h_halt.handle_halt(ctx, args)
        });

    let h_reset = handler;
    node_manager
        .inner()
        .add_method_callback_with_context(reset_method_id, move |ctx, args| {
            h_reset.handle_reset(ctx, args)
        });

    engine
}
