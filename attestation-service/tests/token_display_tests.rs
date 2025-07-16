// Additional tests for token modules

use attestation_service::token::{
    AttestationTokenBroker, AttestationTokenConfig, ear_broker, simple
};

#[test]
fn test_token_config_display() {
    let config = AttestationTokenConfig::Ear(ear_broker::Configuration::default());
    let display = format!("{}", config);
    assert!(!display.is_empty());
}

#[test]
fn test_token_config_partial_eq() {
    let config1 = AttestationTokenConfig::Ear(ear_broker::Configuration::default());
    let config2 = AttestationTokenConfig::Ear(ear_broker::Configuration::default());
    assert_eq!(config1, config2);
    
    let config3 = AttestationTokenConfig::Simple(simple::Configuration::default());
    assert_ne!(config1, config3);
}