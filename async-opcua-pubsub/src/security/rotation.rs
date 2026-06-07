//! Time-based PubSub security key rotation.

use std::sync::Arc;

use opcua_core::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::SecurityGroup;

/// Shared mutable security group state used by publishers and subscribers.
pub type SharedSecurityGroup = Arc<RwLock<SecurityGroup>>;

/// Rotates a PubSub security group's staged key material on a fixed lifetime.
#[derive(Debug, Clone)]
pub struct TimeBasedKeyRotator {
    group: SharedSecurityGroup,
}

impl TimeBasedKeyRotator {
    /// Creates a rotator for a shared security group.
    pub fn new(group: SharedSecurityGroup) -> Self {
        Self { group }
    }

    /// Returns the shared security group state.
    pub fn group(&self) -> SharedSecurityGroup {
        self.group.clone()
    }

    /// Promotes the staged key immediately.
    pub fn rotate_once(&self) {
        self.group.write().rotate_key_sets();
    }

    /// Starts a background task that rotates keys after each configured lifetime.
    pub fn start(&self, cancel_token: CancellationToken) -> JoinHandle<()> {
        let group = self.group.clone();

        tokio::spawn(async move {
            run_rotation_loop(group, cancel_token).await;
        })
    }
}

async fn run_rotation_loop(group: SharedSecurityGroup, cancel_token: CancellationToken) {
    loop {
        let key_lifetime = group.read().key_lifetime();

        tokio::select! {
            () = cancel_token.cancelled() => break,
            () = tokio::time::sleep(key_lifetime) => {
                group.write().rotate_key_sets();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio_util::sync::CancellationToken;

    use super::super::SecurityKeySet;
    use super::*;

    fn key_set(seed: u8) -> SecurityKeySet {
        SecurityKeySet::from_parts(vec![seed; 32], vec![seed + 1; 32], vec![seed + 2; 32]).unwrap()
    }

    fn test_group(lifetime: Duration) -> (SecurityGroup, SecurityKeySet, SecurityKeySet) {
        let current_key = key_set(1);
        let next_key = key_set(11);
        let group = SecurityGroup::with_key_sets(
            "group-1",
            current_key.clone(),
            next_key.clone(),
            lifetime,
        )
        .unwrap();

        (group, current_key, next_key)
    }

    #[test]
    fn rotate_once_promotes_staged_key() {
        let (group, current_key, next_key) = test_group(Duration::from_secs(60));
        let shared_group = SharedSecurityGroup::new(RwLock::new(group));
        let rotator = TimeBasedKeyRotator::new(shared_group.clone());

        rotator.rotate_once();

        let group = shared_group.read();
        assert_eq!(group.current_key_set(), &next_key);
        assert_ne!(group.current_key_set(), &current_key);
        assert_ne!(group.next_key_set(), &next_key);
    }

    #[tokio::test]
    async fn start_rotates_after_key_lifetime() {
        let (group, _current_key, next_key) = test_group(Duration::from_millis(10));
        let shared_group = SharedSecurityGroup::new(RwLock::new(group));
        let cancel_token = CancellationToken::new();
        let handle = TimeBasedKeyRotator::new(shared_group.clone()).start(cancel_token.clone());

        let rotated = tokio::time::timeout(Duration::from_millis(250), async {
            loop {
                if shared_group.read().current_key_set() == &next_key {
                    break;
                }

                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await;

        cancel_token.cancel();
        handle.await.unwrap();
        assert!(rotated.is_ok());
    }
}
