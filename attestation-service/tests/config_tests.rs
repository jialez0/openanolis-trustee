// Tests for config modules to improve coverage

use attestation_service::config::{Config, DEFAULT_WORK_DIR};
use std::path::PathBuf;

#[test]
fn test_config_default() {
    let config = Config::default();
    assert_eq!(config.work_dir, PathBuf::from(DEFAULT_WORK_DIR));
}

#[test]
fn test_config_try_from_nonexistent_file() {
    let result = Config::try_from(PathBuf::from("/non/existent/file.json").as_path());
    assert!(result.is_err());
}