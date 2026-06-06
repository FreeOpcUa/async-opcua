mod comms;

pub use comms::*;
use tokio::task::AbortHandle;

pub struct JoinHandleAbortGuard(AbortHandle);

impl JoinHandleAbortGuard {
    pub fn new(handle: AbortHandle) -> Self {
        Self(handle)
    }
}

impl Drop for JoinHandleAbortGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}
