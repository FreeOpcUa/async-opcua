//! PubSub security key service contracts.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration as StdDuration, Instant},
};

use opcua_core::sync::RwLock;
use opcua_types::{ByteString, Duration, IntegerId, StatusCode, UAString};

/// `StartingTokenId` value that requests the current security token and key.
pub const CURRENT_SECURITY_TOKEN_ID: IntegerId = 0;

/// Ordered key material for one PubSub security group.
#[derive(Debug, Clone)]
pub struct SecurityGroupKeys {
    security_policy_uri: UAString,
    first_token_id: IntegerId,
    keys: Vec<ByteString>,
    key_lifetime: StdDuration,
    current_key_started_at: Instant,
}

impl SecurityGroupKeys {
    /// Creates security group key material beginning at the current instant.
    pub fn new(
        security_policy_uri: impl Into<UAString>,
        first_token_id: IntegerId,
        keys: Vec<ByteString>,
        key_lifetime: StdDuration,
    ) -> Result<Self, StatusCode> {
        Self::with_current_key_started_at(
            security_policy_uri,
            first_token_id,
            keys,
            key_lifetime,
            Instant::now(),
        )
    }

    /// Creates security group key material with an explicit current-key start instant.
    pub fn with_current_key_started_at(
        security_policy_uri: impl Into<UAString>,
        first_token_id: IntegerId,
        keys: Vec<ByteString>,
        key_lifetime: StdDuration,
        current_key_started_at: Instant,
    ) -> Result<Self, StatusCode> {
        let security_policy_uri = security_policy_uri.into();
        if security_policy_uri.as_ref().trim().is_empty()
            || keys.is_empty()
            || key_lifetime.is_zero()
        {
            return Err(StatusCode::BadInvalidArgument);
        }

        Ok(Self {
            security_policy_uri,
            first_token_id,
            keys,
            key_lifetime,
            current_key_started_at,
        })
    }

    fn get_security_keys(
        &self,
        request: &GetSecurityKeysRequest,
    ) -> Result<GetSecurityKeysResponse, StatusCode> {
        if request.requested_key_count == 0 {
            return Err(StatusCode::BadInvalidArgument);
        }

        let first_token_id = if request.starting_token_id == CURRENT_SECURITY_TOKEN_ID {
            self.first_token_id
        } else {
            request.starting_token_id
        };
        let offset = first_token_id
            .checked_sub(self.first_token_id)
            .ok_or(StatusCode::BadNotFound)? as usize;

        if offset >= self.keys.len() {
            return Err(StatusCode::BadNotFound);
        }

        let available_key_count = self.keys.len() - offset;
        let requested_key_count = request.requested_key_count as usize;
        let returned_key_count = requested_key_count.min(available_key_count);
        let keys = self.keys[offset..offset + returned_key_count].to_vec();

        Ok(GetSecurityKeysResponse::new(
            self.security_policy_uri.clone(),
            first_token_id,
            keys,
            self.time_to_next_key_ms(),
            duration_ms(self.key_lifetime),
        ))
    }

    fn time_to_next_key_ms(&self) -> Duration {
        (duration_ms(self.key_lifetime) - duration_ms(self.current_key_started_at.elapsed()))
            .max(0.0)
    }
}

/// In-memory handler for OPC UA Part 14 `GetSecurityKeys` requests.
#[derive(Debug, Clone, Default)]
pub struct SecurityKeyService {
    groups: Arc<RwLock<HashMap<String, SecurityGroupKeys>>>,
}

impl SecurityKeyService {
    /// Creates an empty security key service.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers or replaces key material for a PubSub security group.
    pub fn register_security_group(
        &self,
        security_group_id: impl Into<String>,
        group_keys: SecurityGroupKeys,
    ) -> Result<(), StatusCode> {
        let security_group_id = security_group_id.into();
        validate_security_group_id(&security_group_id)?;
        self.groups.write().insert(security_group_id, group_keys);
        Ok(())
    }

    /// Handles a `GetSecurityKeys` request against registered key material.
    pub fn get_security_keys(
        &self,
        request: GetSecurityKeysRequest,
    ) -> Result<GetSecurityKeysResponse, StatusCode> {
        validate_security_group_id(request.security_group_id.as_ref())?;

        self.groups
            .read()
            .get(request.security_group_id.as_ref())
            .ok_or(StatusCode::BadNotFound)?
            .get_security_keys(&request)
    }
}

fn validate_security_group_id(security_group_id: &str) -> Result<(), StatusCode> {
    if security_group_id.trim().is_empty() {
        Err(StatusCode::BadInvalidArgument)
    } else {
        Ok(())
    }
}

fn duration_ms(duration: StdDuration) -> Duration {
    duration.as_secs_f64() * 1_000.0
}

/// Request contract for the OPC UA Part 14 `GetSecurityKeys` method.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct GetSecurityKeysRequest {
    /// Identifier of the SecurityGroup within the Security Key Service.
    pub security_group_id: UAString,
    /// First requested security token id, or [`CURRENT_SECURITY_TOKEN_ID`] for the current key.
    pub starting_token_id: IntegerId,
    /// Number of keys requested from the Security Key Service.
    pub requested_key_count: u32,
}

impl GetSecurityKeysRequest {
    /// Creates a `GetSecurityKeys` request.
    #[must_use]
    pub fn new(
        security_group_id: impl Into<UAString>,
        starting_token_id: IntegerId,
        requested_key_count: u32,
    ) -> Self {
        Self {
            security_group_id: security_group_id.into(),
            starting_token_id,
            requested_key_count,
        }
    }
}

/// Response contract for the OPC UA Part 14 `GetSecurityKeys` method.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct GetSecurityKeysResponse {
    /// URI of the security policy used by the returned key material.
    pub security_policy_uri: UAString,
    /// Security token id associated with the first returned key.
    pub first_token_id: IntegerId,
    /// Ordered PubSub security keys, beginning at [`first_token_id`](Self::first_token_id).
    pub keys: Vec<ByteString>,
    /// Milliseconds until the current key is expected to expire.
    pub time_to_next_key: Duration,
    /// Milliseconds each key is valid.
    pub key_lifetime: Duration,
}

impl GetSecurityKeysResponse {
    /// Creates a `GetSecurityKeys` response.
    #[must_use]
    pub fn new(
        security_policy_uri: impl Into<UAString>,
        first_token_id: IntegerId,
        keys: Vec<ByteString>,
        time_to_next_key: Duration,
        key_lifetime: Duration,
    ) -> Self {
        Self {
            security_policy_uri: security_policy_uri.into(),
            first_token_id,
            keys,
            time_to_next_key,
            key_lifetime,
        }
    }
}
