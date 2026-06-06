// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2026 Adam Lock

//! GDS Client modules for application registration and CSR exchange.

pub mod csr;
pub mod registration;

pub use csr::GdsCsrClient;
pub use registration::GdsRegistrationClient;
