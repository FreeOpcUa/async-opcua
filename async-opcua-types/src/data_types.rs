// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Certain aliases for OPC-UA data types.

use crate::{date_time::DateTime, ByteString, NodeId, UAString};

/// This primitive data type is a UInt32 that is used as an identifier, such as a handle.
/// All values, except for 0, are valid. IntegerId = 288,
pub type IntegerId = u32;

/// This Simple DataType is a Double that defines an interval of time in milliseconds (fractions can
/// be used to define sub-millisecond values). Negative values are generally invalid but may have
/// special meanings where the Duration is used. Duration = 290,
pub type Duration = f64;

/// UtcTime = 294,
pub type UtcTime = DateTime;

/// OPC-UA UriString, represented as just a string.
pub type UriString = UAString;

/// OPC-UA AudiDataType, represented as just a ByteString.
pub type AudioDataType = ByteString;

/// OPC-UA LocaleId.
pub type LocaleId = UAString;

/// OPC-UA raw continuation point, alias for ByteString.
pub type ContinuationPoint = ByteString;

/// OPC-UA Index, alias for u32.
pub type Index = u32;

/// OPC-UA Counter, alias for u32.
pub type Counter = u32;

/// OPC-UA VersionTime, alias for u32.
pub type VersionTime = u32;

/// OPC-UA application instance certificate, alias for ByteString.
pub type ApplicationInstanceCertificate = ByteString;

/// OPC-UA SessionAuthenticationToken, alias for NodeId.
pub type SessionAuthenticationToken = NodeId;
