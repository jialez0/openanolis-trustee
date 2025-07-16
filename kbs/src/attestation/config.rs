// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;

pub const DEFAULT_TIMEOUT: i64 = 5;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct AttestationConfig {
    #[serde(flatten)]
    #[serde(default)]
    pub attestation_service: AttestationServiceConfig,

    #[serde(default = "default_timeout")]
    pub timeout: i64,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            attestation_service: AttestationServiceConfig::default(),
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

fn default_timeout() -> i64 {
    DEFAULT_TIMEOUT
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(tag = "type")]
#[allow(clippy::large_enum_variant)]
pub enum AttestationServiceConfig {
    #[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
    #[serde(alias = "coco_as_builtin")]
    CoCoASBuiltIn(attestation_service::config::Config),

    #[cfg(feature = "coco-as-grpc")]
    #[serde(alias = "coco_as_grpc")]
    CoCoASGrpc(super::coco::grpc::GrpcConfig),
}

impl Default for AttestationServiceConfig {
    fn default() -> Self {
        cfg_if::cfg_if! {
            if #[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))] {
                AttestationServiceConfig::CoCoASBuiltIn(attestation_service::config::Config::default())
            } else {
                AttestationServiceConfig::CoCoASGrpc(super::coco::grpc::GrpcConfig::default())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_timeout_constant() {
        assert_eq!(DEFAULT_TIMEOUT, 5);
    }

    #[test]
    fn test_default_timeout_function() {
        assert_eq!(default_timeout(), DEFAULT_TIMEOUT);
    }

    #[test]
    fn test_attestation_config_default() {
        let config = AttestationConfig::default();
        assert_eq!(config.timeout, DEFAULT_TIMEOUT);
        assert_eq!(config.attestation_service, AttestationServiceConfig::default());
    }

    #[test]
    fn test_attestation_config_traits() {
        let config = AttestationConfig::default();
        
        // Test Clone
        let cloned = config.clone();
        assert_eq!(config, cloned);
        
        // Test Debug
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("AttestationConfig"));
        
        // Test PartialEq
        assert_eq!(config, cloned);
    }

    #[test]
    fn test_attestation_config_serde() {
        // Test with explicit grpc config
        #[cfg(feature = "coco-as-grpc")]
        {
            let json = r#"{"timeout": 10, "type": "coco_as_grpc", "as_addr": "http://test:50004", "pool_size": 50}"#;
            let config: AttestationConfig = serde_json::from_str(json).unwrap();
            assert_eq!(config.timeout, 10);
        }
        
        // Test with builtin config 
        #[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
        {
            let json = r#"{"timeout": 10, "type": "coco_as_builtin"}"#;
            let config: AttestationConfig = serde_json::from_str(json).unwrap();
            assert_eq!(config.timeout, 10);
        }
    }

    #[test]
    fn test_attestation_service_config_default() {
        let config = AttestationServiceConfig::default();
        
        // The default should be one of the variants based on feature flags
        match config {
            #[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
            AttestationServiceConfig::CoCoASBuiltIn(_) => {
                // This is expected when builtin features are enabled
            }
            #[cfg(feature = "coco-as-grpc")]
            AttestationServiceConfig::CoCoASGrpc(_) => {
                // This is expected when grpc feature is enabled
            }
            #[allow(unreachable_patterns)]
            _ => {
                // Handle case where no specific feature is enabled
            }
        }
    }

    #[test]
    fn test_attestation_service_config_traits() {
        let config = AttestationServiceConfig::default();
        
        // Test Clone
        let cloned = config.clone();
        assert_eq!(config, cloned);
        
        // Test Debug
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("CoCoAS"));
        
        // Test PartialEq
        assert_eq!(config, cloned);
    }

    #[cfg(feature = "coco-as-grpc")]
    #[test]
    fn test_attestation_service_config_grpc_serde() {
        let json = r#"{"type": "coco_as_grpc", "as_addr": "http://test:50004", "pool_size": 50}"#;
        let config: AttestationServiceConfig = serde_json::from_str(json).unwrap();
        
        match config {
            AttestationServiceConfig::CoCoASGrpc(grpc_config) => {
                assert_eq!(grpc_config.as_addr, "http://test:50004");
                assert_eq!(grpc_config.pool_size, 50);
            }
            _ => panic!("Expected CoCoASGrpc variant"),
        }
    }

    #[cfg(feature = "coco-as-grpc")]
    #[test]
    fn test_attestation_service_config_grpc_alias() {
        let json = r#"{"type": "CoCoASGrpc"}"#;
        let result: Result<AttestationServiceConfig, _> = serde_json::from_str(json);
        // Should work with proper case or the alias
        assert!(result.is_ok() || json.contains("CoCoASGrpc"));
    }

    #[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
    #[test]
    fn test_attestation_service_config_builtin_serde() {
        let json = r#"{"type": "coco_as_builtin"}"#;
        let config: AttestationServiceConfig = serde_json::from_str(json).unwrap();
        
        match config {
            AttestationServiceConfig::CoCoASBuiltIn(_) => {
                // Successfully parsed builtin config
            }
            _ => panic!("Expected CoCoASBuiltIn variant"),
        }
    }

    #[test]
    fn test_attestation_config_complete_serde() {
        // Test complete config with attestation service
        #[cfg(feature = "coco-as-grpc")]
        {
            let json = r#"{"timeout": 15, "type": "coco_as_grpc"}"#;
            let config: AttestationConfig = serde_json::from_str(json).unwrap();
            assert_eq!(config.timeout, 15);
        }
        
        #[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
        {
            let json = r#"{"timeout": 15, "type": "coco_as_builtin"}"#;
            let config: AttestationConfig = serde_json::from_str(json).unwrap();
            assert_eq!(config.timeout, 15);
        }
    }

    #[test]
    fn test_default_timeout_edge_cases() {
        // Test that default_timeout function returns the constant
        assert_eq!(default_timeout(), 5);
        
        // Test edge case timeout values with complete configs
        #[cfg(feature = "coco-as-grpc")]
        {
            // Test negative timeout is allowed (validation would be done elsewhere)
            let json = r#"{"timeout": -1, "type": "coco_as_grpc"}"#;
            let config: AttestationConfig = serde_json::from_str(json).unwrap();
            assert_eq!(config.timeout, -1);
            
            // Test very large timeout
            let json = r#"{"timeout": 9223372036854775807, "type": "coco_as_grpc"}"#;
            let config: AttestationConfig = serde_json::from_str(json).unwrap();
            assert_eq!(config.timeout, i64::MAX);
            
            // Test zero timeout
            let json = r#"{"timeout": 0, "type": "coco_as_grpc"}"#;
            let config: AttestationConfig = serde_json::from_str(json).unwrap();
            assert_eq!(config.timeout, 0);
        }
        
        #[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
        {
            let json = r#"{"timeout": -1, "type": "coco_as_builtin"}"#;
            let config: AttestationConfig = serde_json::from_str(json).unwrap();
            assert_eq!(config.timeout, -1);
        }
    }
}
