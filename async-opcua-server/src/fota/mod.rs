//! Firmware-over-the-air file transfer helpers.

/// Session lifecycle cleanup for temporary FOTA resources.
pub mod cleanup;
/// Session-bound temporary FileType node creation.
pub mod file_node;
