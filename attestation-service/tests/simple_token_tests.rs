// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use attestation_service::token::simple::{Configuration, SimpleAttestationTokenBroker};
use attestation_service::token::AttestationTokenBroker;
use kbs_types::Tee;
use std::collections::HashMap;
use tempfile::TempDir;

#[tokio::test]
async fn test_simple_token_broker_with_custom_config() {
    let temp_dir = TempDir::new().unwrap();
    let policy_dir = temp_dir.path().join("policies");
    std::fs::create_dir_all(&policy_dir).unwrap();
    
    let config = Configuration {
        duration_min: 10,
        issuer_name: "test-issuer".to_string(),
        signer: None,
        policy_dir: policy_dir.to_string_lossy().to_string(),
    };
    
    let broker = SimpleAttestationTokenBroker::new(config).unwrap();
    
    // Test issuing a token
    let token = broker
        .issue(
            serde_json::json!({
                "claim": "test-claim"
            }),
            vec!["default".into()],
            serde_json::json!({
                "initdata": "test-init"
            }),
            serde_json::json!({
                "runtime_data": "test-runtime"
            }),
            HashMap::new(),
            Tee::Sample,
        )
        .await
        .unwrap();
        
    // Basic validation that we got a token
    assert!(!token.is_empty());
    assert!(token.contains("."));
}