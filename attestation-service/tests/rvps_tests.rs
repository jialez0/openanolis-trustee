// Tests for RVPS module to improve coverage

use attestation_service::rvps::RvpsConfig;

#[test]
fn test_rvps_config_default() {
    let config = RvpsConfig::default();
    // Just testing that we can create a default config
    assert!(matches!(config, RvpsConfig::BuiltIn(_)));
}