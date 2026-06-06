use opcua_types::{DataValue, ServerDiagnosticsSummaryDataType, VariableId};

use super::LocalValue;

/// The server diagnostics struct, containing shared
/// types for various forms of server diagnostics.
#[derive(Default)]
pub struct ServerDiagnostics {
    /// Server diagnostics summary.
    pub summary: ServerDiagnosticsSummary,
    /// Whether diagnostics are enabled or not.
    /// Set on server startup.
    pub enabled: bool,
}

impl ServerDiagnostics {
    /// Check if the given variable ID is managed by this object.
    pub fn is_mapped(&self, variable_id: VariableId) -> bool {
        self.enabled && self.summary.is_mapped(variable_id)
    }

    /// Get the value of a diagnostics element by its ID.
    pub fn get(&self, variable_id: VariableId) -> Option<DataValue> {
        self.summary.get(variable_id)
    }

    /// Set the current session count.
    pub fn set_current_session_count(&self, count: u32) {
        if self.enabled {
            self.summary.current_session_count.set(count);
        }
    }

    /// Set the current subscription count.
    pub fn set_current_subscription_count(&self, count: u32) {
        if self.enabled {
            self.summary.current_subscription_count.set(count);
        }
    }

    /// Increment the cumulated session count.
    pub fn inc_session_count(&self) {
        if self.enabled {
            self.summary.cumulated_session_count.increment();
        }
    }

    /// Increment the cumulated subscription count.
    pub fn inc_subscription_count(&self) {
        if self.enabled {
            self.summary.cumulated_subscription_count.increment();
        }
    }

    /// Increment the rejected requests count.
    pub fn inc_rejected_requests(&self) {
        if self.enabled {
            self.summary.rejected_requests_count.increment();
        }
    }

    /// Increment the security rejected requests count.
    pub fn inc_security_rejected_requests(&self) {
        if self.enabled {
            self.summary.security_rejected_requests_count.increment();
        }
    }

    /// Increment the security rejected session count.
    pub fn inc_security_rejected_session_count(&self) {
        if self.enabled {
            self.summary.security_rejected_session_count.increment();
        }
    }

    /// Set the number of server-created views.
    pub fn set_server_view_count(&self, count: u32) {
        if self.enabled {
            self.summary.server_view_count.set(count);
        }
    }

    /// Increment the session abort count.
    pub fn inc_session_abort_count(&self) {
        if self.enabled {
            self.summary.session_abort_count.increment();
        }
    }

    /// Increment the session timeout count.
    pub fn inc_session_timeout_count(&self) {
        if self.enabled {
            self.summary.session_timeout_count.increment();
        }
    }

    /// Set the number of publishing intervals supported by the server.
    pub fn set_publishing_interval_count(&self, count: u32) {
        if self.enabled {
            self.summary.publishing_interval_count.set(count);
        }
    }
}

/// The server diagnostics summary type. Users with approparite
/// permissions can read these values.
#[derive(Default)]
pub struct ServerDiagnosticsSummary {
    /// The number of sessions that have been created since the server started.
    cumulated_session_count: LocalValue<u32>,
    /// The number of subscriptions that have been created since the server started.
    cumulated_subscription_count: LocalValue<u32>,
    /// The number of sessions that are currently active.
    current_session_count: LocalValue<u32>,
    /// The number of subscriptions that are currently active.
    current_subscription_count: LocalValue<u32>,
    /// The number of publishing intervals that have been created since the server started.
    publishing_interval_count: LocalValue<u32>,
    /// The number of rejected requests since the server started.
    rejected_requests_count: LocalValue<u32>,
    /// The number of rejected sessions since the server started.
    rejected_session_count: LocalValue<u32>,
    /// The number of security rejected requests since the server started.
    security_rejected_requests_count: LocalValue<u32>,
    /// The number of security rejected sessions since the server started.
    security_rejected_session_count: LocalValue<u32>,
    /// The number of server-created views in the server.
    server_view_count: LocalValue<u32>,
    /// The number of sessions that were closed due to errors since the server started.
    session_abort_count: LocalValue<u32>,
    /// The number of sessions that timed out since the server started.
    session_timeout_count: LocalValue<u32>,
}

impl ServerDiagnosticsSummary {
    /// Check if the given variable ID is managed by this object.
    pub fn is_mapped(&self, variable_id: VariableId) -> bool {
        matches!(variable_id,
            VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_ServerViewCount
            | VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSessionCount
            | VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSessionCount
            | VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_SecurityRejectedSessionCount
            | VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_RejectedSessionCount
            | VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_SessionTimeoutCount
            | VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_SessionAbortCount
            | VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSubscriptionCount
            | VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSubscriptionCount
            | VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_PublishingIntervalCount
            | VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_SecurityRejectedRequestsCount
            | VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_RejectedRequestsCount
            | VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary
        )
    }

    /// Get the value of a variable by its ID.
    pub fn get(&self, variable_id: VariableId) -> Option<DataValue> {
        match variable_id {
            VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_ServerViewCount => Some(self.server_view_count.sample()),
            VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSessionCount => Some(self.current_session_count.sample()),
            VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSessionCount => Some(self.cumulated_session_count.sample()),
            VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_SecurityRejectedSessionCount => Some(self.security_rejected_session_count.sample()),
            VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_RejectedSessionCount => Some(self.rejected_session_count.sample()),
            VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_SessionTimeoutCount => Some(self.session_timeout_count.sample()),
            VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_SessionAbortCount => Some(self.session_abort_count.sample()),
            VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSubscriptionCount => Some(self.current_subscription_count.sample()),
            VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSubscriptionCount => Some(self.cumulated_subscription_count.sample()),
            VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_PublishingIntervalCount => Some(self.publishing_interval_count.sample()),
            VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_SecurityRejectedRequestsCount => Some(self.security_rejected_requests_count.sample()),
            VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_RejectedRequestsCount => Some(self.rejected_requests_count.sample()),
            VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary => Some(self.sample()),
            _ => None,
        }
    }

    /// Get the current value of the server diagnostics summary.
    pub fn sample(&self) -> DataValue {
        let values = [
            self.server_view_count.get_with_time(),
            self.current_session_count.get_with_time(),
            self.cumulated_session_count.get_with_time(),
            self.security_rejected_session_count.get_with_time(),
            self.rejected_session_count.get_with_time(),
            self.session_timeout_count.get_with_time(),
            self.session_abort_count.get_with_time(),
            self.current_subscription_count.get_with_time(),
            self.cumulated_subscription_count.get_with_time(),
            self.publishing_interval_count.get_with_time(),
            self.security_rejected_requests_count.get_with_time(),
            self.rejected_requests_count.get_with_time(),
        ];
        let ts = values.iter().map(|v| v.1).max().unwrap();

        DataValue::new_at(
            ServerDiagnosticsSummaryDataType {
                server_view_count: values[0].0,
                current_session_count: values[1].0,
                cumulated_session_count: values[2].0,
                security_rejected_session_count: values[3].0,
                rejected_session_count: values[4].0,
                session_timeout_count: values[5].0,
                session_abort_count: values[6].0,
                current_subscription_count: values[7].0,
                cumulated_subscription_count: values[8].0,
                publishing_interval_count: values[9].0,
                security_rejected_requests_count: values[10].0,
                rejected_requests_count: values[11].0,
            },
            ts,
        )
    }
}
