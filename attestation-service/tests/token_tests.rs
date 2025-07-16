// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use attestation_service::token::{
    ear_broker, simple, AttestationTokenBroker, AttestationTokenConfig, COCO_AS_ISSUER_NAME,
    DEFAULT_TOKEN_DURATION,
};

#[tokio::test]
async fn test_attestation_token_config_default() {
    let config = AttestationTokenConfig::default();
    assert!(matches!(config, AttestationTokenConfig::Ear(_)));
}

#[tokio::test]
async fn test_attestation_token_config_to_token_broker_simple() {
    let config = AttestationTokenConfig::Simple(simple::Configuration::default());
    let broker = config.to_token_broker().unwrap();
    assert!(broker.list_policies().await.is_ok());
}

#[tokio::test]
async fn test_attestation_token_config_to_token_broker_ear() {
    let config = AttestationTokenConfig::Ear(ear_broker::Configuration::default());
    let broker = config.to_token_broker().unwrap();
    assert!(broker.list_policies().await.is_ok());
}

#[tokio::test]
async fn test_simple_token_broker_default_config() {
    let config = simple::Configuration::default();
    assert_eq!(config.duration_min, DEFAULT_TOKEN_DURATION);
    assert_eq!(config.issuer_name, COCO_AS_ISSUER_NAME);
    assert!(config.signer.is_none());
}

#[tokio::test]
async fn test_simple_token_broker_new_with_default_config() {
    let config = simple::Configuration::default();
    let broker = simple::SimpleAttestationTokenBroker::new(config);
    assert!(broker.is_ok());
}

#[tokio::test]
async fn test_simple_token_broker_policy_operations() {
    let config = simple::Configuration::default();
    let broker = simple::SimpleAttestationTokenBroker::new(config).unwrap();
    
    // Test set_policy (should fail as it's not supported by default)
    let result = broker.set_policy("test-policy".to_string(), "test-content".to_string()).await;
    assert!(result.is_err());
    
    // Test list_policies (should fail as it's not supported by default)
    let result = broker.list_policies().await;
    assert!(result.is_err());
    
    // Test get_policy (should fail as it's not supported by default)
    let result = broker.get_policy("test-policy".to_string()).await;
    assert!(result.is_err());
    
    // Test delete_policy (should fail as it's not supported by default)
    let result = broker.delete_policy("test-policy".to_string()).await;
    assert!(result.is_err());
}