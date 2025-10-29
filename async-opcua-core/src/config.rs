// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Common utilities for configuration files in both the server and client.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::result::Result;

use serde;
use serde_yaml;

use opcua_types::{ApplicationDescription, ApplicationType, LocalizedText, UAString};

/// Error returned from saving or loading config objects.
#[derive(Debug)]
pub enum ConfigError {
    /// Configuration is invalid, with a list of validation errors.
    ConfigInvalid(Vec<String>),
    /// Reading or writing file failed.
    IO(std::io::Error),
    /// Failed to serialize or deserialize config object.
    Yaml(serde_yaml::Error),
}

impl From<std::io::Error> for ConfigError {
    fn from(value: std::io::Error) -> Self {
        Self::IO(value)
    }
}

impl From<serde_yaml::Error> for ConfigError {
    fn from(value: serde_yaml::Error) -> Self {
        Self::Yaml(value)
    }
}

/// A trait that handles the loading / saving and validity of configuration information for a
/// client and/or server.
pub trait Config: serde::Serialize {
    /// Save the configuration object to a file.
    fn save(&self, path: &Path) -> Result<(), ConfigError> {
        if let Err(e) = self.validate() {
            return Err(ConfigError::ConfigInvalid(e));
        }
        let s = serde_yaml::to_string(&self)?;
        let mut f = File::create(path)?;
        f.write_all(s.as_bytes())?;
        Ok(())
    }

    /// Load the configuration object from the given path.
    #[cfg(feature = "env_expansion")]
    fn load<A>(path: &Path) -> Result<A, ConfigError>
    where
        for<'de> A: Config + serde::Deserialize<'de>,
    {
        let mut f = File::open(path)?;
        let mut s = String::new();
        f.read_to_string(&mut s)?;
        let mut value: serde_yaml::Value = serde_yaml::from_str(&s)?;
        expand_env_in_value(&mut value);
        return Ok(serde_yaml::from_value(value)?);
    }

    /// Load the configuration object from the given path.
    #[cfg(not(feature = "env_expansion"))]
    fn load<A>(path: &Path) -> Result<A, ConfigError>
    where
        for<'de> A: Config + serde::Deserialize<'de>,
    {
        let mut f = File::open(path)?;
        let mut s = String::new();
        f.read_to_string(&mut s)?;
        Ok(serde_yaml::from_str(&s)?)
    }

    /// Validate the config struct, returning a list of validation errors if it fails.
    fn validate(&self) -> Result<(), Vec<String>>;

    /// Get the application name.
    fn application_name(&self) -> UAString;

    /// Get the application URI.
    fn application_uri(&self) -> UAString;

    /// Get the configured product URI.
    fn product_uri(&self) -> UAString;

    /// Get the application type.
    fn application_type(&self) -> ApplicationType;

    /// Get the registered discovery URLs for this application.
    fn discovery_urls(&self) -> Option<Vec<UAString>> {
        None
    }

    /// Create an application description for the configured application.
    fn application_description(&self) -> ApplicationDescription {
        ApplicationDescription {
            application_uri: self.application_uri(),
            application_name: LocalizedText::new("", self.application_name().as_ref()),
            application_type: self.application_type(),
            product_uri: self.product_uri(),
            gateway_server_uri: UAString::null(),
            discovery_profile_uri: UAString::null(),
            discovery_urls: self.discovery_urls(),
        }
    }
}

#[cfg(feature = "env_expansion")]
fn expand_env_in_value(value: &mut serde_yaml::Value) {
    use serde_yaml::Value;
    match value {
        Value::String(s) => {
            *value = match shellexpand::env(s) {
                Ok(expanded) => match expanded.as_ref() {
                    "null" | "~" => Value::Null,
                    expanded_str => expanded_str
                        .parse::<bool>()
                        .map(Value::Bool)
                        .or_else(|_| expanded_str.parse::<i64>().map(|i| Value::Number(i.into())))
                        .or_else(|_| expanded_str.parse::<u64>().map(|u| Value::Number(u.into())))
                        .or_else(|_| expanded_str.parse::<f64>().map(|f| Value::Number(f.into())))
                        .unwrap_or_else(|_| Value::String(expanded.to_string())),
                },
                Err(_) => Value::Null,
            }
        }
        Value::Sequence(seq) => {
            for v in seq {
                expand_env_in_value(v);
            }
        }
        Value::Mapping(map) => {
            for (_k, v) in map.iter_mut() {
                expand_env_in_value(v);
            }
        }
        _ => (),
    }
}
