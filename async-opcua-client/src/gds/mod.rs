// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2026 Adam Lock

//! GDS Client modules for application registration and CSR exchange.

pub mod csr;
pub mod gds_client;
/// GDS enrollment and credential cache state types.
pub mod gds_state;
pub mod registration;

pub use csr::GdsCsrClient;
pub use gds_client::GdsClient;
pub use gds_state::{CachedCredentials, GdsEnrollment, RegistrationState};
pub use registration::GdsRegistrationClient;
