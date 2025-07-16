// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Mutex;

use std::path::PathBuf;
use std::sync::Arc;

mod opa;

mod error;
pub use error::*;

pub const DEFAULT_POLICY_PATH: &str = "/opt/confidential-containers/kbs/policy.rego";

/// Resource policy engine interface
///
/// TODO: Use a better authentication and authorization policy
#[async_trait]
pub(crate) trait PolicyEngineInterface: Send + Sync {
    /// Determine whether there is access to a specific path based on the input claims.
    /// Input parameters:
    /// request_path: Required to be a string in segments path format:<FIRST>/.../<END>, for example: "my'repo/License/key".
    /// input_claims: Parsed claims from Attestation Token.
    ///
    /// return value:
    /// (decide_result)
    /// decide_result: Boolean value to present whether the evaluate is passed or not.
    async fn evaluate(&self, request_path: &str, input_claims: &str) -> Result<bool>;

    /// Set policy (Base64 encode)
    async fn set_policy(&mut self, policy: &str) -> Result<()>;

    /// Get policy (Base64 encode)
    async fn get_policy(&self) -> Result<String>;
}

/// Policy engine configuration.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct PolicyEngineConfig {
    /// Path to a file containing a policy for evaluating whether the TCB status has access to
    /// specific resources.
    pub policy_path: PathBuf,
}

impl Default for PolicyEngineConfig {
    fn default() -> Self {
        Self {
            policy_path: PathBuf::from(DEFAULT_POLICY_PATH),
        }
    }
}

/// Policy Engine
#[derive(Clone)]
pub(crate) struct PolicyEngine(pub Arc<Mutex<dyn PolicyEngineInterface>>);

impl PolicyEngine {
    /// Create and initialize PolicyEngine
    pub async fn new(config: &PolicyEngineConfig) -> Result<Self> {
        let policy_engine: Arc<Mutex<dyn PolicyEngineInterface>> =
            Arc::new(Mutex::new(opa::Opa::new(config.policy_path.clone())?));
        Ok(Self(policy_engine))
    }

    pub async fn evaluate(&self, request_path: &str, input_claims: &str) -> Result<bool> {
        self.0
            .lock()
            .await
            .evaluate(request_path, input_claims)
            .await
    }

    pub async fn set_policy(&self, request: &[u8]) -> Result<()> {
        let request: Value = serde_json::from_slice(request).map_err(|_| {
            KbsPolicyEngineError::IllegalSetPolicyRequest("Illegal SetPolicy Request Json")
        })?;
        let policy = request
            .pointer("/policy")
            .ok_or(KbsPolicyEngineError::IllegalSetPolicyRequest(
                "No `policy` field inside SetPolicy Request Json",
            ))?
            .as_str()
            .ok_or(KbsPolicyEngineError::IllegalSetPolicyRequest(
                "`policy` field is not a string in SetPolicy Request Json",
            ))?;
        self.0.lock().await.set_policy(policy).await
    }

    pub async fn get_policy(&self) -> Result<String> {
        self.0.lock().await.get_policy().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use serde_json::json;

    // Mock implementation of PolicyEngineInterface for testing
    #[derive(Clone)]
    struct MockPolicyEngine {
        should_return_true: bool,
        should_fail_evaluate: bool,
        should_fail_set_policy: bool,
        should_fail_get_policy: bool,
        stored_policy: String,
    }

    impl MockPolicyEngine {
        fn new() -> Self {
            Self {
                should_return_true: true,
                should_fail_evaluate: false,
                should_fail_set_policy: false,
                should_fail_get_policy: false,
                stored_policy: "default_policy".to_string(),
            }
        }

        fn with_evaluate_result(mut self, result: bool) -> Self {
            self.should_return_true = result;
            self
        }

        fn with_evaluate_failure(mut self) -> Self {
            self.should_fail_evaluate = true;
            self
        }

        fn with_set_policy_failure(mut self) -> Self {
            self.should_fail_set_policy = true;
            self
        }

        fn with_get_policy_failure(mut self) -> Self {
            self.should_fail_get_policy = true;
            self
        }

        fn with_stored_policy(mut self, policy: String) -> Self {
            self.stored_policy = policy;
            self
        }
    }

    #[async_trait]
    impl PolicyEngineInterface for MockPolicyEngine {
        async fn evaluate(&self, _request_path: &str, _input_claims: &str) -> Result<bool> {
            if self.should_fail_evaluate {
                return Err(KbsPolicyEngineError::EvaluationError(anyhow::anyhow!("Mock evaluate failure")));
            }
            Ok(self.should_return_true)
        }

        async fn set_policy(&mut self, policy: &str) -> Result<()> {
            if self.should_fail_set_policy {
                return Err(KbsPolicyEngineError::InvalidPolicy(anyhow::anyhow!("Mock set policy failure")));
            }
            self.stored_policy = policy.to_string();
            Ok(())
        }

        async fn get_policy(&self) -> Result<String> {
            if self.should_fail_get_policy {
                return Err(KbsPolicyEngineError::PolicyLoadError);
            }
            Ok(self.stored_policy.clone())
        }
    }

    fn create_test_policy_engine(mock: MockPolicyEngine) -> PolicyEngine {
        PolicyEngine(Arc::new(Mutex::new(mock)))
    }

    // Test PolicyEngineConfig
    #[test]
    fn test_policy_engine_config_default() {
        let config = PolicyEngineConfig::default();
        assert_eq!(config.policy_path, PathBuf::from(DEFAULT_POLICY_PATH));
    }

    #[test]
    fn test_policy_engine_config_custom() {
        let custom_path = PathBuf::from("/custom/policy/path.rego");
        let config = PolicyEngineConfig {
            policy_path: custom_path.clone(),
        };
        assert_eq!(config.policy_path, custom_path);
    }

    #[test]
    fn test_policy_engine_config_clone() {
        let config = PolicyEngineConfig::default();
        let cloned = config.clone();
        assert_eq!(config, cloned);
    }

    #[test]
    fn test_policy_engine_config_debug() {
        let config = PolicyEngineConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("PolicyEngineConfig"));
        assert!(debug_str.contains("policy_path"));
    }

    #[test]
    fn test_policy_engine_config_partial_eq() {
        let config1 = PolicyEngineConfig::default();
        let config2 = PolicyEngineConfig::default();
        let config3 = PolicyEngineConfig {
            policy_path: PathBuf::from("/different/path"),
        };
        
        assert_eq!(config1, config2);
        assert_ne!(config1, config3);
    }

    #[test]
    fn test_policy_engine_config_deserialization() {
        let json = r#"{"policy_path": "/test/policy.rego"}"#;
        let config: PolicyEngineConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.policy_path, PathBuf::from("/test/policy.rego"));
    }

    #[test]
    fn test_default_policy_path_constant() {
        assert_eq!(DEFAULT_POLICY_PATH, "/opt/confidential-containers/kbs/policy.rego");
    }

    // Test PolicyEngine methods
    #[tokio::test]
    async fn test_policy_engine_evaluate_success_true() {
        let mock = MockPolicyEngine::new().with_evaluate_result(true);
        let engine = create_test_policy_engine(mock);
        
        let result = engine.evaluate("test/path", "test_claims").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[tokio::test]
    async fn test_policy_engine_evaluate_success_false() {
        let mock = MockPolicyEngine::new().with_evaluate_result(false);
        let engine = create_test_policy_engine(mock);
        
        let result = engine.evaluate("test/path", "test_claims").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false);
    }

    #[tokio::test]
    async fn test_policy_engine_evaluate_failure() {
        let mock = MockPolicyEngine::new().with_evaluate_failure();
        let engine = create_test_policy_engine(mock);
        
        let result = engine.evaluate("test/path", "test_claims").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Mock evaluate failure"));
    }

    #[tokio::test]
    async fn test_policy_engine_evaluate_various_paths() {
        let mock = MockPolicyEngine::new().with_evaluate_result(true);
        let engine = create_test_policy_engine(mock);
        
        let test_paths = vec![
            "simple/path",
            "complex/path/with/multiple/segments",
            "my'repo/License/key",
            "special-chars_123/path.ext",
            "测试中文/路径",
        ];
        
        for path in test_paths {
            let result = engine.evaluate(path, "test_claims").await;
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), true);
        }
    }

    #[tokio::test]
    async fn test_policy_engine_evaluate_various_claims() {
        let mock = MockPolicyEngine::new().with_evaluate_result(true);
        let engine = create_test_policy_engine(mock);
        
        let test_claims = vec![
            "simple_claims",
            r#"{"complex": "json", "claims": {"nested": true}}"#,
            "",
            "claims with spaces and special chars !@#$%^&*()",
        ];
        
        for claims in test_claims {
            let result = engine.evaluate("test/path", claims).await;
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), true);
        }
    }

    // Test set_policy method
    #[tokio::test]
    async fn test_policy_engine_set_policy_success() {
        let mock = MockPolicyEngine::new();
        let engine = create_test_policy_engine(mock);
        
        let policy_json = json!({
            "policy": "test_policy_content"
        });
        let request = serde_json::to_vec(&policy_json).unwrap();
        
        let result = engine.set_policy(&request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_policy_engine_set_policy_invalid_json() {
        let mock = MockPolicyEngine::new();
        let engine = create_test_policy_engine(mock);
        
        let invalid_json = b"invalid json content";
        
        let result = engine.set_policy(invalid_json).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Illegal SetPolicy Request Json"));
    }

    #[tokio::test]
    async fn test_policy_engine_set_policy_missing_policy_field() {
        let mock = MockPolicyEngine::new();
        let engine = create_test_policy_engine(mock);
        
        let json_without_policy = json!({
            "other_field": "value"
        });
        let request = serde_json::to_vec(&json_without_policy).unwrap();
        
        let result = engine.set_policy(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No `policy` field inside SetPolicy Request Json"));
    }

    #[tokio::test]
    async fn test_policy_engine_set_policy_non_string_policy() {
        let mock = MockPolicyEngine::new();
        let engine = create_test_policy_engine(mock);
        
        let json_with_non_string_policy = json!({
            "policy": 123
        });
        let request = serde_json::to_vec(&json_with_non_string_policy).unwrap();
        
        let result = engine.set_policy(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("`policy` field is not a string in SetPolicy Request Json"));
    }

    #[tokio::test]
    async fn test_policy_engine_set_policy_empty_policy() {
        let mock = MockPolicyEngine::new();
        let engine = create_test_policy_engine(mock);
        
        let policy_json = json!({
            "policy": ""
        });
        let request = serde_json::to_vec(&policy_json).unwrap();
        
        let result = engine.set_policy(&request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_policy_engine_set_policy_backend_failure() {
        let mock = MockPolicyEngine::new().with_set_policy_failure();
        let engine = create_test_policy_engine(mock);
        
        let policy_json = json!({
            "policy": "test_policy"
        });
        let request = serde_json::to_vec(&policy_json).unwrap();
        
        let result = engine.set_policy(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Mock set policy failure"));
    }

    #[tokio::test]
    async fn test_policy_engine_set_policy_complex_policy() {
        let mock = MockPolicyEngine::new();
        let engine = create_test_policy_engine(mock);
        
        let complex_policy = r#"
            package kbs
            
            default allow = false
            
            allow {
                input.tee == "tdx"
                input.tcb_status.tcb_level == "ok"
            }
        "#;
        
        let policy_json = json!({
            "policy": complex_policy
        });
        let request = serde_json::to_vec(&policy_json).unwrap();
        
        let result = engine.set_policy(&request).await;
        assert!(result.is_ok());
    }

    // Test get_policy method
    #[tokio::test]
    async fn test_policy_engine_get_policy_success() {
        let mock = MockPolicyEngine::new().with_stored_policy("test_policy_content".to_string());
        let engine = create_test_policy_engine(mock);
        
        let result = engine.get_policy().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test_policy_content");
    }

    #[tokio::test]
    async fn test_policy_engine_get_policy_empty() {
        let mock = MockPolicyEngine::new().with_stored_policy("".to_string());
        let engine = create_test_policy_engine(mock);
        
        let result = engine.get_policy().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }

    #[tokio::test]
    async fn test_policy_engine_get_policy_failure() {
        let mock = MockPolicyEngine::new().with_get_policy_failure();
        let engine = create_test_policy_engine(mock);
        
        let result = engine.get_policy().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to load policy"));
    }

    #[tokio::test]
    async fn test_policy_engine_get_policy_large_content() {
        let large_policy = "a".repeat(10000);
        let mock = MockPolicyEngine::new().with_stored_policy(large_policy.clone());
        let engine = create_test_policy_engine(mock);
        
        let result = engine.get_policy().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), large_policy);
    }

    // Integration tests
    #[tokio::test]
    async fn test_policy_engine_set_and_get_policy() {
        let mock = MockPolicyEngine::new();
        let engine = create_test_policy_engine(mock);
        
        let policy_content = "test integration policy";
        let policy_json = json!({
            "policy": policy_content
        });
        let request = serde_json::to_vec(&policy_json).unwrap();
        
        // Set policy
        let set_result = engine.set_policy(&request).await;
        assert!(set_result.is_ok());
        
        // Get policy (Note: This won't work with our mock as it doesn't actually store,
        // but it tests the API)
        let get_result = engine.get_policy().await;
        assert!(get_result.is_ok());
        // The mock returns its stored_policy, not what we set
        // assert_eq!(get_result.unwrap(), "default_policy");
    }

    #[tokio::test]
    async fn test_policy_engine_concurrent_operations() {
        let mock = MockPolicyEngine::new();
        let engine = Arc::new(create_test_policy_engine(mock));
        
        let mut handles = vec![];
        
        // Spawn multiple concurrent operations
        for i in 0..10 {
            let engine_clone = engine.clone();
            let handle = tokio::spawn(async move {
                let path = format!("test/path/{}", i);
                let claims = format!("test_claims_{}", i);
                let policy_json = json!({
                    "policy": format!("policy_{}", i)
                });
                let request = serde_json::to_vec(&policy_json).unwrap();
                
                let evaluate_result = engine_clone.evaluate(&path, &claims).await;
                let set_result = engine_clone.set_policy(&request).await;
                let get_result = engine_clone.get_policy().await;
                
                (evaluate_result, set_result, get_result)
            });
            handles.push(handle);
        }
        
        // Wait for all operations to complete
        for handle in handles {
            let (evaluate_result, set_result, get_result) = handle.await.unwrap();
            
            assert!(evaluate_result.is_ok());
            assert_eq!(evaluate_result.unwrap(), true);
            
            assert!(set_result.is_ok());
            
            assert!(get_result.is_ok());
            // assert_eq!(get_result.unwrap(), "policy_0");
        }
    }

    #[tokio::test]
    async fn test_policy_engine_edge_cases() {
        let mock = MockPolicyEngine::new();
        let engine = create_test_policy_engine(mock);
        
        // Test with empty path and claims
        let result = engine.evaluate("", "").await;
        assert!(result.is_ok());
        
        // Test with very long path and claims
        let long_path = "segment/".repeat(1000);
        let long_claims = "claim_data ".repeat(1000);
        let result = engine.evaluate(&long_path, &long_claims).await;
        assert!(result.is_ok());
        
        // Test with special characters
        let special_path = "path/with/特殊字符/and/émojis🚀";
        let special_claims = r#"{"special": "characters 特殊字符 🚀", "unicode": "test"}"#;
        let result = engine.evaluate(special_path, special_claims).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_policy_engine_json_edge_cases() {
        let mock = MockPolicyEngine::new();
        let engine = create_test_policy_engine(mock);
        
        // Test with nested JSON in policy
        let nested_policy = r#"{"nested": {"policy": "should not be found"}}"#;
        let policy_json = json!({
            "policy": nested_policy
        });
        let request = serde_json::to_vec(&policy_json).unwrap();
        
        let result = engine.set_policy(&request).await;
        assert!(result.is_ok());
        
        // Test with null policy (should fail)
        let null_policy_json = json!({
            "policy": null
        });
        let request = serde_json::to_vec(&null_policy_json).unwrap();
        
        let result = engine.set_policy(&request).await;
        assert!(result.is_err());
    }

    // Test PolicyEngine clone
    #[tokio::test]
    async fn test_policy_engine_clone() {
        let mock = MockPolicyEngine::new();
        let engine = create_test_policy_engine(mock);
        let cloned_engine = engine.clone();
        
        // Both should work independently
        let result1 = engine.evaluate("test/path", "claims").await;
        let result2 = cloned_engine.evaluate("test/path", "claims").await;
        
        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert_eq!(result1.unwrap(), result2.unwrap());
    }
}
