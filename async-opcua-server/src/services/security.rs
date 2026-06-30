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
    current_token_id: IntegerId,
    keys: Vec<ByteString>,
    key_lifetime: StdDuration,
    current_key_started_at: Instant,
}

impl SecurityGroupKeys {
    /// Creates current and future key material beginning at the current instant.
    pub fn new(
        security_policy_uri: impl Into<UAString>,
        current_token_id: IntegerId,
        keys: Vec<ByteString>,
        key_lifetime: StdDuration,
    ) -> Result<Self, StatusCode> {
        Self::with_current_key_started_at(
            security_policy_uri,
            current_token_id,
            keys,
            key_lifetime,
            Instant::now(),
        )
    }

    /// Creates current and future key material with an explicit current-key start instant.
    pub fn with_current_key_started_at(
        security_policy_uri: impl Into<UAString>,
        current_token_id: IntegerId,
        keys: Vec<ByteString>,
        key_lifetime: StdDuration,
        current_key_started_at: Instant,
    ) -> Result<Self, StatusCode> {
        Self::with_retained_keys_current_key_started_at(
            security_policy_uri,
            current_token_id,
            current_token_id,
            keys,
            key_lifetime,
            current_key_started_at,
        )
    }

    /// Creates key material that includes retained historical keys.
    ///
    /// The `keys` vector is ordered from `first_token_id`; `current_token_id`
    /// must identify one of those retained keys.
    pub fn with_retained_keys_current_key_started_at(
        security_policy_uri: impl Into<UAString>,
        first_token_id: IntegerId,
        current_token_id: IntegerId,
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
        token_offset(first_token_id, keys.len(), current_token_id)?;

        Ok(Self {
            security_policy_uri,
            first_token_id,
            current_token_id,
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
            self.current_token_id
        } else {
            request.starting_token_id
        };
        let offset = token_offset(self.first_token_id, self.keys.len(), first_token_id)?;

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

/// In-memory handler for OPC UA Part 14 security key requests.
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

    /// Handles a `SetSecurityKeys` push by replacing registered key material.
    pub fn set_security_keys(&self, request: SetSecurityKeysRequest) -> Result<(), StatusCode> {
        validate_security_group_id(request.security_group_id.as_ref())?;

        if request.security_policy_uri.as_ref().trim().is_empty()
            || request.current_key.is_null_or_empty()
            || request.key_lifetime <= 0.0
        {
            return Err(StatusCode::BadInvalidArgument);
        }

        let security_group_id = request.security_group_id.as_ref().to_owned();
        let key_lifetime = duration_from_ms(request.key_lifetime)?;
        let elapsed = duration_from_ms((request.key_lifetime - request.time_to_next_key).max(0.0))?;
        let now = Instant::now();
        let current_key_started_at = now.checked_sub(elapsed).unwrap_or(now);

        let mut keys = Vec::with_capacity(1 + request.future_keys.len());
        keys.push(request.current_key);
        keys.extend(request.future_keys);

        let group_keys = SecurityGroupKeys::with_current_key_started_at(
            request.security_policy_uri,
            request.current_token_id,
            keys,
            key_lifetime,
            current_key_started_at,
        )?;

        self.groups.write().insert(security_group_id, group_keys);
        Ok(())
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

fn duration_from_ms(duration_ms: Duration) -> Result<StdDuration, StatusCode> {
    if duration_ms.is_finite() && duration_ms >= 0.0 {
        Ok(StdDuration::from_secs_f64(duration_ms / 1_000.0))
    } else {
        Err(StatusCode::BadInvalidArgument)
    }
}

fn token_offset(
    first_token_id: IntegerId,
    key_count: usize,
    token_id: IntegerId,
) -> Result<usize, StatusCode> {
    let offset = token_id
        .checked_sub(first_token_id)
        .ok_or(StatusCode::BadNotFound)? as usize;

    if offset < key_count {
        Ok(offset)
    } else {
        Err(StatusCode::BadNotFound)
    }
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

/// Request contract for the OPC UA Part 14 `SetSecurityKeys` method.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SetSecurityKeysRequest {
    /// Identifier of the SecurityGroup receiving pushed key material.
    pub security_group_id: UAString,
    /// URI of the security policy used by the pushed key material.
    pub security_policy_uri: UAString,
    /// Security token id associated with [`current_key`](Self::current_key).
    pub current_token_id: IntegerId,
    /// Current PubSub security key.
    pub current_key: ByteString,
    /// Ordered future PubSub security keys following [`current_key`](Self::current_key).
    pub future_keys: Vec<ByteString>,
    /// Milliseconds remaining on the current key.
    pub time_to_next_key: Duration,
    /// Milliseconds each key is valid.
    pub key_lifetime: Duration,
}

impl SetSecurityKeysRequest {
    /// Creates a `SetSecurityKeys` request.
    #[must_use]
    pub fn new(
        security_group_id: impl Into<UAString>,
        security_policy_uri: impl Into<UAString>,
        current_token_id: IntegerId,
        current_key: ByteString,
        future_keys: Vec<ByteString>,
        time_to_next_key: Duration,
        key_lifetime: Duration,
    ) -> Self {
        Self {
            security_group_id: security_group_id.into(),
            security_policy_uri: security_policy_uri.into(),
            current_token_id,
            current_key,
            future_keys,
            time_to_next_key,
            key_lifetime,
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
