// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! This is a sample to implement a client plugin

use actix_web::http::Method;
use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::super::plugin_manager::ClientPlugin;

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Default)]
pub struct SampleConfig {
    #[serde(default = "default_item")]
    pub item: String,
}

fn default_item() -> String {
    "default".to_string()
}

pub struct Sample {
    _item: String,
}

impl TryFrom<SampleConfig> for Sample {
    type Error = anyhow::Error;

    fn try_from(value: SampleConfig) -> anyhow::Result<Self> {
        Ok(Self { _item: value.item })
    }
}

#[async_trait::async_trait]
impl ClientPlugin for Sample {
    async fn handle(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        _method: &Method,
    ) -> Result<Vec<u8>> {
        Ok("sample plugin response".as_bytes().to_vec())
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        _method: &Method,
    ) -> Result<bool> {
        Ok(true)
    }

    /// Whether the body needs to be encrypted via TEE key pair.
    /// If returns `Ok(true)`, the KBS server will encrypt the whole body
    /// with TEE key pair and use KBS protocol's Response format.
    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        _method: &Method,
    ) -> Result<bool> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::Method;
    use serde_json;

    #[test]
    fn test_sample_config_default() {
        let config = SampleConfig::default();
        assert_eq!(config.item, ""); // Default trait uses String::default() which is empty string
    }

    #[test]
    fn test_sample_config_clone() {
        let config = SampleConfig {
            item: "test_item".to_string(),
        };
        let cloned = config.clone();
        assert_eq!(config, cloned);
        assert_eq!(cloned.item, "test_item");
    }

    #[test]
    fn test_sample_config_debug() {
        let config = SampleConfig {
            item: "debug_test".to_string(),
        };
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("SampleConfig"));
        assert!(debug_str.contains("debug_test"));
    }

    #[test]
    fn test_sample_config_partial_eq() {
        let config1 = SampleConfig {
            item: "same".to_string(),
        };
        let config2 = SampleConfig {
            item: "same".to_string(),
        };
        let config3 = SampleConfig {
            item: "different".to_string(),
        };
        
        assert_eq!(config1, config2);
        assert_ne!(config1, config3);
    }

    #[test]
    fn test_sample_config_serialization() {
        let config = SampleConfig {
            item: "serialize_test".to_string(),
        };
        
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("serialize_test"));
        
        let deserialized: SampleConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);
    }

    #[test]
    fn test_sample_config_deserialization_with_defaults() {
        // Test deserialization when item field is missing (should use default)
        let json = "{}";
        let config: SampleConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.item, "default");
    }

    #[test]
    fn test_sample_config_deserialization_with_custom_item() {
        let json = r#"{"item": "custom_value"}"#;
        let config: SampleConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.item, "custom_value");
    }

    #[test]
    fn test_sample_config_deserialization_with_extra_fields() {
        // Test that extra fields are ignored
        let json = r#"{"item": "test", "extra_field": "ignored"}"#;
        let config: SampleConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.item, "test");
    }

    #[test]
    fn test_default_item_function() {
        let result = default_item();
        assert_eq!(result, "default");
    }

    #[test]
    fn test_sample_try_from_sample_config() {
        let config = SampleConfig {
            item: "try_from_test".to_string(),
        };
        
        let sample = Sample::try_from(config).unwrap();
        assert_eq!(sample._item, "try_from_test");
    }

    #[test]
    fn test_sample_try_from_default_config() {
        let config = SampleConfig::default();
        let sample = Sample::try_from(config).unwrap();
        assert_eq!(sample._item, ""); // Default creates empty string
    }

    #[test]
    fn test_sample_try_from_empty_item() {
        let config = SampleConfig {
            item: String::new(),
        };
        let sample = Sample::try_from(config).unwrap();
        assert_eq!(sample._item, "");
    }

    #[tokio::test]
    async fn test_sample_handle_method() {
        let config = SampleConfig::default();
        let sample = Sample::try_from(config).unwrap();
        
        let result = sample.handle(b"test body", "query", "/path", &Method::GET).await;
        assert!(result.is_ok());
        
        let response = result.unwrap();
        let response_str = String::from_utf8(response).unwrap();
        assert_eq!(response_str, "sample plugin response");
    }

    #[tokio::test]
    async fn test_sample_handle_different_methods() {
        let config = SampleConfig::default();
        let sample = Sample::try_from(config).unwrap();
        
        let methods = vec![Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::PATCH];
        
        for method in methods {
            let result = sample.handle(b"body", "query", "/path", &method).await;
            assert!(result.is_ok());
            
            let response = result.unwrap();
            let response_str = String::from_utf8(response).unwrap();
            assert_eq!(response_str, "sample plugin response");
        }
    }

    #[tokio::test]
    async fn test_sample_handle_various_inputs() {
        let config = SampleConfig::default();
        let sample = Sample::try_from(config).unwrap();
        
        // Test with different body contents
        let bodies = vec![
            b"".to_vec(),
            b"simple body".to_vec(),
            b"complex body with special chars !@#$%^&*()".to_vec(),
            vec![0u8; 1000], // Large body
        ];
        
        for body in bodies {
            let result = sample.handle(&body, "query", "/path", &Method::POST).await;
            assert!(result.is_ok());
            
            let response = result.unwrap();
            assert_eq!(response, b"sample plugin response");
        }
    }

    #[tokio::test]
    async fn test_sample_handle_various_paths() {
        let config = SampleConfig::default();
        let sample = Sample::try_from(config).unwrap();
        
        let paths = vec![
            "/",
            "/simple",
            "/complex/path/with/multiple/segments",
            "/path?query=value",
            "/path-with-special-chars_123",
        ];
        
        for path in paths {
            let result = sample.handle(b"body", "query", path, &Method::GET).await;
            assert!(result.is_ok());
            
            let response = result.unwrap();
            let response_str = String::from_utf8(response).unwrap();
            assert_eq!(response_str, "sample plugin response");
        }
    }

    #[tokio::test]
    async fn test_sample_handle_various_queries() {
        let config = SampleConfig::default();
        let sample = Sample::try_from(config).unwrap();
        
        let queries = vec![
            "",
            "simple=value",
            "key1=value1&key2=value2",
            "complex=value%20with%20encoding",
            "special=!@#$%^&*()",
        ];
        
        for query in queries {
            let result = sample.handle(b"body", query, "/path", &Method::GET).await;
            assert!(result.is_ok());
            
            let response = result.unwrap();
            let response_str = String::from_utf8(response).unwrap();
            assert_eq!(response_str, "sample plugin response");
        }
    }

    #[tokio::test]
    async fn test_sample_validate_auth_method() {
        let config = SampleConfig::default();
        let sample = Sample::try_from(config).unwrap();
        
        let result = sample.validate_auth(b"body", "query", "/path", &Method::GET).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[tokio::test]
    async fn test_sample_validate_auth_different_methods() {
        let config = SampleConfig::default();
        let sample = Sample::try_from(config).unwrap();
        
        let methods = vec![Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::PATCH, Method::HEAD, Method::OPTIONS];
        
        for method in methods {
            let result = sample.validate_auth(b"body", "query", "/path", &method).await;
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), true);
        }
    }

    #[tokio::test]
    async fn test_sample_validate_auth_various_inputs() {
        let config = SampleConfig::default();
        let sample = Sample::try_from(config).unwrap();
        
        // Test with different input combinations
        let test_cases = vec![
            (b"".as_slice(), "", ""),
            (b"body".as_slice(), "query", "/path"),
            (b"large body content".as_slice(), "key=value", "/complex/path"),
        ];
        
        for (body, query, path) in test_cases {
            let result = sample.validate_auth(body, query, path, &Method::POST).await;
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), true);
        }
    }

    #[tokio::test]
    async fn test_sample_encrypted_method() {
        let config = SampleConfig::default();
        let sample = Sample::try_from(config).unwrap();
        
        let result = sample.encrypted(b"body", "query", "/path", &Method::GET).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false);
    }

    #[tokio::test]
    async fn test_sample_encrypted_different_methods() {
        let config = SampleConfig::default();
        let sample = Sample::try_from(config).unwrap();
        
        let methods = vec![Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::PATCH, Method::HEAD, Method::OPTIONS];
        
        for method in methods {
            let result = sample.encrypted(b"body", "query", "/path", &method).await;
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), false);
        }
    }

    #[tokio::test]
    async fn test_sample_encrypted_various_inputs() {
        let config = SampleConfig::default();
        let sample = Sample::try_from(config).unwrap();
        
        // Test with different input combinations
        let test_cases = vec![
            (b"".as_slice(), "", ""),
            (b"sensitive data".as_slice(), "auth=token", "/secure/path"),
            (b"large content".as_slice(), "complex=query&other=param", "/api/v1/resource"),
        ];
        
        for (body, query, path) in test_cases {
            let result = sample.encrypted(body, query, path, &Method::POST).await;
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), false);
        }
    }

    #[tokio::test]
    async fn test_sample_all_methods_together() {
        let config = SampleConfig {
            item: "integration_test".to_string(),
        };
        let sample = Sample::try_from(config).unwrap();
        
        // Test all ClientPlugin methods work together
        let body = b"integration test body";
        let query = "test=integration";
        let path = "/integration/test";
        let method = Method::POST;
        
        // Test handle
        let handle_result = sample.handle(body, query, path, &method).await;
        assert!(handle_result.is_ok());
        assert_eq!(handle_result.unwrap(), b"sample plugin response");
        
        // Test validate_auth
        let auth_result = sample.validate_auth(body, query, path, &method).await;
        assert!(auth_result.is_ok());
        assert_eq!(auth_result.unwrap(), true);
        
        // Test encrypted
        let encrypted_result = sample.encrypted(body, query, path, &method).await;
        assert!(encrypted_result.is_ok());
        assert_eq!(encrypted_result.unwrap(), false);
    }

    #[test]
    fn test_sample_config_edge_cases() {
        // Test with very long item string
        let long_item = "a".repeat(10000);
        let config = SampleConfig {
            item: long_item.clone(),
        };
        
        let sample = Sample::try_from(config).unwrap();
        assert_eq!(sample._item, long_item);
    }

    #[test]
    fn test_sample_config_special_characters() {
        let special_item = "!@#$%^&*()_+-={}[]|;':\",./<>?`~测试中文🚀";
        let config = SampleConfig {
            item: special_item.to_string(),
        };
        
        let sample = Sample::try_from(config).unwrap();
        assert_eq!(sample._item, special_item);
    }

    #[test]
    fn test_sample_config_json_round_trip() {
        let original = SampleConfig {
            item: "round_trip_test".to_string(),
        };
        
        // Serialize to JSON
        let json = serde_json::to_string(&original).unwrap();
        
        // Deserialize back
        let deserialized: SampleConfig = serde_json::from_str(&json).unwrap();
        
        // Should be equal
        assert_eq!(original, deserialized);
    }

    #[tokio::test]
    async fn test_sample_concurrent_operations() {
        let config = SampleConfig::default();
        let sample = std::sync::Arc::new(Sample::try_from(config).unwrap());
        
        let mut handles = vec![];
        
        // Spawn multiple concurrent operations
        for i in 0..10 {
            let sample_clone = sample.clone();
            let handle = tokio::spawn(async move {
                let body = format!("concurrent body {}", i).into_bytes();
                let query = format!("concurrent_query={}", i);
                let path = format!("/concurrent/{}", i);
                
                let handle_result = sample_clone.handle(&body, &query, &path, &Method::GET).await;
                let auth_result = sample_clone.validate_auth(&body, &query, &path, &Method::GET).await;
                let encrypted_result = sample_clone.encrypted(&body, &query, &path, &Method::GET).await;
                
                (handle_result, auth_result, encrypted_result)
            });
            handles.push(handle);
        }
        
        // Wait for all operations to complete
        for handle in handles {
            let (handle_result, auth_result, encrypted_result) = handle.await.unwrap();
            
            assert!(handle_result.is_ok());
            assert_eq!(handle_result.unwrap(), b"sample plugin response");
            
            assert!(auth_result.is_ok());
            assert_eq!(auth_result.unwrap(), true);
            
            assert!(encrypted_result.is_ok());
            assert_eq!(encrypted_result.unwrap(), false);
        }
    }

    #[test]
    fn test_sample_memory_efficiency() {
        // Test that Sample doesn't consume excessive memory
        let config = SampleConfig {
            item: "memory_test".to_string(),
        };
        
        let sample = Sample::try_from(config).unwrap();
        
        // The Sample struct should be relatively small
        let size = std::mem::size_of_val(&sample);
        assert!(size < 1000); // Should be much smaller than 1KB
    }
}
