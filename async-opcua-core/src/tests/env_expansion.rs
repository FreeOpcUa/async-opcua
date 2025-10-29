#[cfg(feature = "env_expansion")]
mod tests {
    use serde::Serialize;

    use crate::config::Config;

    #[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
    struct DummyConfig<T: Serialize> {
        pub value: T,
    }

    impl<T: Serialize> Config for DummyConfig<T> {
        fn validate(&self) -> Result<(), Vec<String>> {
            Ok(())
        }
        fn application_name(&self) -> opcua_types::UAString {
            opcua_types::UAString::null()
        }
        fn application_uri(&self) -> opcua_types::UAString {
            opcua_types::UAString::null()
        }
        fn product_uri(&self) -> opcua_types::UAString {
            opcua_types::UAString::null()
        }
        fn application_type(&self) -> opcua_types::ApplicationType {
            opcua_types::ApplicationType::Server
        }
    }

    struct EnvTestFixture {
        temp_file: tempfile::NamedTempFile,
        vars_to_remove: Vec<String>,
    }

    impl EnvTestFixture {
        fn new() -> Self {
            Self {
                temp_file: tempfile::NamedTempFile::new().expect("Failed to create temp file"),
                vars_to_remove: Vec::new(),
            }
        }
        fn set_var(&mut self, key: &str, value: &str) {
            std::env::set_var(key, value);
            self.vars_to_remove.push(key.to_string());
        }
        fn remove_var(&mut self, key: &str) {
            std::env::remove_var(key);
            self.vars_to_remove.push(key.to_string());
        }
        fn write_yaml(&self, yaml: &str) {
            std::fs::write(self.temp_file.path(), yaml).expect("Failed to write to temp file");
        }
        fn path(&self) -> &std::path::Path {
            self.temp_file.path()
        }
    }

    impl Drop for EnvTestFixture {
        fn drop(&mut self) {
            for var in &self.vars_to_remove {
                std::env::remove_var(var);
            }
        }
    }

    #[test]
    fn test_env_expansion() {
        let mut fixture = EnvTestFixture::new();
        fixture.write_yaml("value: ${TEST_ENV_VAR}");
        fixture.set_var("TEST_ENV_VAR", "interpolated_value");
        let config: DummyConfig<String> = DummyConfig::<String>::load(fixture.path()).unwrap();
        assert_eq!(config.value, "interpolated_value");
    }

    #[test]
    fn test_env_expansion_without_braces() {
        let mut fixture = EnvTestFixture::new();
        fixture.write_yaml("value: $TEST_ENV_VAR_2");
        fixture.set_var("TEST_ENV_VAR_2", "interpolated_value");
        let config: DummyConfig<String> = DummyConfig::<String>::load(fixture.path()).unwrap();
        assert_eq!(config.value, "interpolated_value");
    }

    #[test]
    fn test_env_expansion_with_default_fallback() {
        let mut fixture = EnvTestFixture::new();
        fixture.write_yaml("value: ${UNSET_ENV_VAR:-default_value}");
        fixture.remove_var("UNSET_ENV_VAR");
        let config: DummyConfig<String> = DummyConfig::<String>::load(fixture.path()).unwrap();
        assert_eq!(config.value, "default_value");
    }

    #[test]
    fn test_fallback_is_not_expanded() {
        let mut fixture = EnvTestFixture::new();
        fixture.write_yaml("value: ${VARIABLE:-${FOO}}");
        fixture.remove_var("VARIABLE");
        fixture.remove_var("FOO");
        let config: DummyConfig<String> = DummyConfig::<String>::load(fixture.path()).unwrap();
        assert_eq!(config.value, "${FOO}");
    }

    #[test]
    fn test_env_expansion_double_dollar_escapes() {
        let mut fixture = EnvTestFixture::new();
        fixture.write_yaml("value: $$TEST_ENV_VAR_ESCAPED");
        fixture.remove_var("TEST_ENV_VAR_ESCAPED");
        let config: DummyConfig<String> = DummyConfig::<String>::load(fixture.path()).unwrap();
        assert_eq!(config.value, "$TEST_ENV_VAR_ESCAPED");
    }

    #[test]
    fn test_env_expansion_ignores_env_vars_in_comments() {
        let mut fixture = EnvTestFixture::new();
        fixture.write_yaml(
            r#"
    value: ${TEST_ENV_VAR_3}
    # This is a comment with an env variable: ${COMMENT_ENV_VAR}
    "#,
        );
        fixture.set_var("TEST_ENV_VAR_3", "interpolated_value");
        fixture.remove_var("COMMENT_ENV_VAR");
        let config: Result<DummyConfig<String>, _> = DummyConfig::<String>::load(fixture.path());
        assert!(config.is_ok());
    }

    #[test]
    fn test_env_expansion_for_null() {
        let mut fixture = EnvTestFixture::new();
        fixture.write_yaml("value: $NULL_ENV_VAR");

        fixture.set_var("NULL_ENV_VAR", "");
        let config: DummyConfig<Option<String>> =
            DummyConfig::<Option<String>>::load(fixture.path()).unwrap();
        assert_eq!(config.value, Some("".to_string()));

        fixture.set_var("NULL_ENV_VAR", "null");
        let config: DummyConfig<Option<String>> =
            DummyConfig::<Option<String>>::load(fixture.path()).unwrap();
        assert_eq!(config.value, None);
        fixture.set_var("NULL_ENV_VAR", "~");
        let config: DummyConfig<Option<String>> =
            DummyConfig::<Option<String>>::load(fixture.path()).unwrap();
        assert_eq!(config.value, None);
        fixture.remove_var("NULL_ENV_VAR");
        let config: DummyConfig<Option<bool>> =
            DummyConfig::<Option<bool>>::load(fixture.path()).unwrap();
        assert_eq!(config.value, None);
    }

    #[test]
    fn test_env_expansion_for_null_errors_for_non_option_type() {
        let mut fixture = EnvTestFixture::new();
        fixture.write_yaml("value: $NULL_ENV_VAR_2");
        fixture.set_var("NULL_ENV_VAR_2", "null");
        let result: Result<DummyConfig<bool>, _> = DummyConfig::<bool>::load(fixture.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_env_expansion_for_boolean() {
        let mut fixture = EnvTestFixture::new();
        fixture.write_yaml("value: $BOOLEAN_ENV_VAR");
        fixture.set_var("BOOLEAN_ENV_VAR", "true");
        let config: DummyConfig<bool> = DummyConfig::<bool>::load(fixture.path()).unwrap();
        assert_eq!(config.value, true);
        fixture.set_var("BOOLEAN_ENV_VAR", "false");
        let config: DummyConfig<bool> = DummyConfig::<bool>::load(fixture.path()).unwrap();
        assert_eq!(config.value, false);
    }

    // Only lowercase "true" and "false" are parsed as booleans
    #[should_panic]
    #[test]
    fn test_env_expansion_for_boolean_should_fail() {
        let mut fixture = EnvTestFixture::new();
        fixture.write_yaml("value: $BOOLEAN_ENV_VAR_2");
        fixture.set_var("BOOLEAN_ENV_VAR_2", "True");
        let config: DummyConfig<bool> = DummyConfig::<bool>::load(fixture.path()).unwrap();
        assert_eq!(config.value, true);
        fixture.set_var("BOOLEAN_ENV_VAR_2", "TRUE");
        let config: DummyConfig<bool> = DummyConfig::<bool>::load(fixture.path()).unwrap();
        assert_eq!(config.value, true);
        fixture.set_var("BOOLEAN_ENV_VAR_2", "False");
        let config: DummyConfig<bool> = DummyConfig::<bool>::load(fixture.path()).unwrap();
        assert_eq!(config.value, false);
        fixture.set_var("BOOLEAN_ENV_VAR_2", "FALSE");
        let config: DummyConfig<bool> = DummyConfig::<bool>::load(fixture.path()).unwrap();
        assert_eq!(config.value, false);
    }

    #[test]
    fn test_env_expansion_for_integer() {
        let mut fixture = EnvTestFixture::new();
        fixture.write_yaml("value: $INTEGER_ENV_VAR");

        fixture.set_var("INTEGER_ENV_VAR", format!("{}", 0).as_str());
        let config: DummyConfig<i64> = DummyConfig::<i64>::load(fixture.path()).unwrap();
        assert_eq!(config.value, 0);

        fixture.set_var("INTEGER_ENV_VAR", format!("{}", i64::MIN).as_str());
        let config: DummyConfig<i64> = DummyConfig::<i64>::load(fixture.path()).unwrap();
        assert_eq!(config.value, i64::MIN);
        fixture.set_var("INTEGER_ENV_VAR", format!("{}", i64::MAX).as_str());
        let config: DummyConfig<i64> = DummyConfig::<i64>::load(fixture.path()).unwrap();
        assert_eq!(config.value, i64::MAX);

        fixture.set_var("INTEGER_ENV_VAR", format!("{}", u64::MAX).as_str());
        let config: DummyConfig<u64> = DummyConfig::<u64>::load(fixture.path()).unwrap();
        assert_eq!(config.value, u64::MAX);
    }

    #[test]
    fn test_env_expansion_for_floats() {
        let mut fixture = EnvTestFixture::new();
        fixture.write_yaml("value: $FLOAT_ENV_VAR");

        fixture.set_var("FLOAT_ENV_VAR", format!("{}", 0).as_str());
        let config: DummyConfig<f64> = DummyConfig::<f64>::load(fixture.path()).unwrap();
        assert_eq!(config.value, 0.0);
        fixture.set_var("FLOAT_ENV_VAR", format!("{}", f64::MIN).as_str());
        let config: DummyConfig<f64> = DummyConfig::<f64>::load(fixture.path()).unwrap();
        assert_eq!(config.value, f64::MIN);
        fixture.set_var("FLOAT_ENV_VAR", format!("{}", f64::MAX).as_str());
        let config: DummyConfig<f64> = DummyConfig::<f64>::load(fixture.path()).unwrap();
        assert_eq!(config.value, f64::MAX);
    }

    // The following tests are expected to panic because `shellexpand` does not support
    // certain bash-like syntax for environment variable interpolation.
    // The tests are here to document that behavior.

    #[should_panic]
    #[test]
    fn test_env_expansion_with_empty_var_and_default_fallback() {
        let mut fixture = EnvTestFixture::new();
        fixture.write_yaml("value: ${EMPTY_ENV_VAR:-default_value}");
        fixture.set_var("EMPTY_ENV_VAR", "");
        let config: DummyConfig<String> = DummyConfig::<String>::load(fixture.path()).unwrap();
        assert_eq!(config.value, "default_value");
    }

    #[should_panic]
    #[test]
    fn test_env_expansion_with_default_if_unset() {
        let mut fixture = EnvTestFixture::new();
        fixture.write_yaml("value: ${UNSET_ENV_VAR-default_value}");
        fixture.remove_var("UNSET_ENV_VAR");
        let config: DummyConfig<String> = DummyConfig::<String>::load(fixture.path()).unwrap();
        assert_eq!(config.value, "default_value");
        fixture.set_var("UNSET_ENV_VAR", "actual_value");
        let config: DummyConfig<String> = DummyConfig::<String>::load(fixture.path()).unwrap();
        assert_eq!(config.value, "actual_value");
        fixture.set_var("UNSET_ENV_VAR", "");
        let config: DummyConfig<String> = DummyConfig::<String>::load(fixture.path()).unwrap();
        assert_eq!(config.value, "");
    }

    #[should_panic]
    #[test]
    fn test_env_expansion_with_required_var() {
        let mut fixture = EnvTestFixture::new();
        fixture.write_yaml("value: ${REQUIRED_ENV_VAR:?must be set}");
        fixture.remove_var("REQUIRED_ENV_VAR");
        let result: Result<DummyConfig<String>, crate::config::ConfigError> =
            DummyConfig::<String>::load(fixture.path());
        assert!(result.is_err(), "Should error if var is unset");
        fixture.set_var("REQUIRED_ENV_VAR", "");
        let result: Result<DummyConfig<String>, crate::config::ConfigError> =
            DummyConfig::<String>::load(fixture.path());
        assert!(result.is_err(), "Should error if var is empty");
        fixture.set_var("REQUIRED_ENV_VAR", "present");
        let config: DummyConfig<String> = DummyConfig::<String>::load(fixture.path()).unwrap();
        assert_eq!(config.value, "present");
    }

    #[should_panic]
    #[test]
    fn test_env_expansion_with_required_var_unset_only() {
        let mut fixture = EnvTestFixture::new();
        fixture.write_yaml("value: ${REQUIRED_UNSET_ENV_VAR?must be set}");
        fixture.remove_var("REQUIRED_UNSET_ENV_VAR");
        let result: Result<DummyConfig<String>, crate::config::ConfigError> =
            DummyConfig::<String>::load(fixture.path());
        assert!(result.is_err(), "Should error if var is unset");
        fixture.set_var("REQUIRED_UNSET_ENV_VAR", "present");
        let config: DummyConfig<String> = DummyConfig::<String>::load(fixture.path()).unwrap();
        assert_eq!(config.value, "present");
        fixture.set_var("REQUIRED_UNSET_ENV_VAR", "");
        let result: Result<DummyConfig<String>, crate::config::ConfigError> =
            DummyConfig::<String>::load(fixture.path());
        assert!(
            result.is_err(),
            "Should error if PLUS_IF_SET_ENV_VAR is empty"
        );
    }

    #[should_panic]
    #[test]
    fn test_env_expansion_with_plus_replacement() {
        let mut fixture = EnvTestFixture::new();
        fixture.write_yaml("value: ${PLUS_ENV_VAR:+replacement_value}");
        fixture.remove_var("PLUS_ENV_VAR");
        let result: Result<DummyConfig<String>, crate::config::ConfigError> =
            DummyConfig::<String>::load(fixture.path());
        assert!(result.is_err(), "Should error if PLUS_ENV_VAR is unset");
        fixture.set_var("PLUS_ENV_VAR", "");
        let result: Result<DummyConfig<String>, crate::config::ConfigError> =
            DummyConfig::<String>::load(fixture.path());
        assert!(result.is_err(), "Should error if PLUS_ENV_VAR is empty");
        fixture.set_var("PLUS_ENV_VAR", "present");
        let config: DummyConfig<String> = DummyConfig::<String>::load(fixture.path()).unwrap();
        assert_eq!(config.value, "replacement_value");
    }

    #[should_panic]
    #[test]
    fn test_env_expansion_with_plus_replacement_if_set() {
        let mut fixture = EnvTestFixture::new();
        fixture.write_yaml("value: ${PLUS_IF_SET_ENV_VAR+replacement_value}");
        fixture.remove_var("PLUS_IF_SET_ENV_VAR");
        let config: DummyConfig<String> = DummyConfig::<String>::load(fixture.path()).unwrap();
        assert_eq!(config.value, "");
        fixture.set_var("PLUS_IF_SET_ENV_VAR", "");
        let config: DummyConfig<String> = DummyConfig::<String>::load(fixture.path()).unwrap();
        assert_eq!(config.value, "replacement_value");
        fixture.set_var("PLUS_IF_SET_ENV_VAR", "present");
        let config: DummyConfig<String> = DummyConfig::<String>::load(fixture.path()).unwrap();
        assert_eq!(config.value, "replacement_value");
    }
}
