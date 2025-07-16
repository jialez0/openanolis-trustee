// Additional tests for token modules to improve coverage

use attestation_service::token::ear_broker::Configuration as EarConfiguration;
use attestation_service::token::simple::Configuration as SimpleConfiguration;

#[test]
fn test_ear_configuration_default() {
    let config = EarConfiguration::default();
    // Just testing that we can create a default config
    assert_eq!(config.duration_min, attestation_service::token::DEFAULT_TOKEN_DURATION);
}

#[test]
fn test_simple_configuration_default() {
    let config = SimpleConfiguration::default();
    // Just testing that we can create a default config
    assert_eq!(config.duration_min, attestation_service::token::DEFAULT_TOKEN_DURATION);
}