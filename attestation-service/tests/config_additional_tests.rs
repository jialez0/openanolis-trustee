// Additional tests for config modules

use attestation_service::config::Config;
use std::path::PathBuf;

#[test]
fn test_config_partial_eq() {
    let config1 = Config::default();
    let config2 = Config::default();
    assert_eq!(config1, config2);
}

#[test]
fn test_config_clone() {
    let config = Config::default();
    let cloned = config.clone();
    assert_eq!(config, cloned);
}

#[test]
fn test_config_debug() {
    let config = Config::default();
    let debug_str = format!("{:?}", config);
    assert!(debug_str.contains("Config"));
}