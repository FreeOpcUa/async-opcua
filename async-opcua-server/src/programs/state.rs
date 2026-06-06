use opcua_types::{NodeId, StatusCode};

/// The states of a Program State Machine (Part 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramState {
    /// Initial or stopped state.
    Halted,
    /// Ready to start execution.
    Ready,
    /// Actively executing task.
    Running,
    /// Execution paused.
    Suspended,
}

impl ProgramState {
    /// Returns the localized string representation of the state.
    pub fn as_str(&self) -> &'static str {
        match self {
            ProgramState::Halted => "Halted",
            ProgramState::Ready => "Ready",
            ProgramState::Running => "Running",
            ProgramState::Suspended => "Suspended",
        }
    }
}

/// Manages standard transitions for the Program State Machine.
#[derive(Debug, Clone)]
pub struct ProgramStateMachine {
    node_id: NodeId,
    state: ProgramState,
}

impl ProgramStateMachine {
    /// Creates a new ProgramStateMachine with the given NodeId, starting in `Halted`.
    pub fn new(node_id: NodeId) -> Self {
        Self {
            node_id,
            state: ProgramState::Halted,
        }
    }

    /// Creates a new ProgramStateMachine starting in a specific state.
    pub fn with_state(node_id: NodeId, state: ProgramState) -> Self {
        Self { node_id, state }
    }

    /// Gets the NodeId of the program instance.
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Gets the current state of the Program.
    pub fn state(&self) -> ProgramState {
        self.state
    }

    /// Checks if a transition to `Running` (Start) is valid.
    pub fn can_start(&self) -> bool {
        self.state == ProgramState::Ready
    }

    /// Transitions the state from `Ready` to `Running`.
    pub fn start(&mut self) -> Result<(), StatusCode> {
        if self.can_start() {
            self.state = ProgramState::Running;
            Ok(())
        } else {
            Err(StatusCode::BadStateNotActive)
        }
    }

    /// Checks if a transition to `Suspended` (Suspend) is valid.
    pub fn can_suspend(&self) -> bool {
        self.state == ProgramState::Running
    }

    /// Transitions the state from `Running` to `Suspended`.
    pub fn suspend(&mut self) -> Result<(), StatusCode> {
        if self.can_suspend() {
            self.state = ProgramState::Suspended;
            Ok(())
        } else {
            Err(StatusCode::BadStateNotActive)
        }
    }

    /// Checks if a transition to `Running` (Resume) is valid.
    pub fn can_resume(&self) -> bool {
        self.state == ProgramState::Suspended
    }

    /// Transitions the state from `Suspended` to `Running`.
    pub fn resume(&mut self) -> Result<(), StatusCode> {
        if self.can_resume() {
            self.state = ProgramState::Running;
            Ok(())
        } else {
            Err(StatusCode::BadStateNotActive)
        }
    }

    /// Checks if a transition to `Halted` (Halt) is valid.
    pub fn can_halt(&self) -> bool {
        matches!(
            self.state,
            ProgramState::Ready | ProgramState::Running | ProgramState::Suspended
        )
    }

    /// Transitions the state to `Halted`.
    pub fn halt(&mut self) -> Result<(), StatusCode> {
        if self.can_halt() {
            self.state = ProgramState::Halted;
            Ok(())
        } else {
            Err(StatusCode::BadStateNotActive)
        }
    }

    /// Checks if a transition to `Ready` (Reset) is valid.
    pub fn can_reset(&self) -> bool {
        self.state == ProgramState::Halted
    }

    /// Transitions the state from `Halted` to `Ready`.
    pub fn reset(&mut self) -> Result<(), StatusCode> {
        if self.can_reset() {
            self.state = ProgramState::Ready;
            Ok(())
        } else {
            Err(StatusCode::BadStateNotActive)
        }
    }
}
