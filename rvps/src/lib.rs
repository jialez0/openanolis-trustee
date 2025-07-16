// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod client;
pub mod config;
pub mod extractors;
pub mod pre_processor;
pub mod reference_value;
pub mod rvps_api;
pub mod server;
pub mod storage;

pub use config::Config;
pub use reference_value::{ReferenceValue, TrustedDigest};
pub use storage::ReferenceValueStorage;

use extractors::Extractors;
use pre_processor::{PreProcessor, PreProcessorAPI};

use anyhow::{bail, Context, Result};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Default version of Message
static MESSAGE_VERSION: &str = "0.1.0";

/// Message is an overall packet that Reference Value Provider Service
/// receives. It will contain payload (content of different provenance,
/// JSON format), provenance type (indicates the type of the payload)
/// and a version number (use to distinguish different version of
/// message, for extendability).
/// * `version`: version of this message.
/// * `payload`: content of the provenance, JSON encoded.
/// * `type`: provenance type of the payload.
#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    #[serde(default = "default_version")]
    version: String,
    payload: String,
    r#type: String,
}

/// Set the default version for Message
fn default_version() -> String {
    MESSAGE_VERSION.into()
}

/// The core of the RVPS, s.t. componants except communication componants.
pub struct Rvps {
    pre_processor: PreProcessor,
    extractors: Extractors,
    storage: Box<dyn ReferenceValueStorage + Send + Sync>,
}

impl Rvps {
    /// Instantiate a new RVPS
    pub fn new(config: Config) -> Result<Self> {
        let pre_processor = PreProcessor::default();
        let extractors = Extractors::default();
        let storage = config.storage.to_storage()?;

        Ok(Rvps {
            pre_processor,
            extractors,
            storage,
        })
    }

    /// Add Ware to the Core's Pre-Processor
    pub fn with_ware(&mut self, _ware: &str) -> &Self {
        // TODO: no wares implemented now.
        self
    }

    pub async fn verify_and_extract(&mut self, message: &str) -> Result<()> {
        let mut message: Message = serde_json::from_str(message).context("parse message")?;

        // Judge the version field
        if message.version != MESSAGE_VERSION {
            bail!(
                "Version unmatched! Need {}, given {}.",
                MESSAGE_VERSION,
                message.version
            );
        }

        self.pre_processor.process(&mut message)?;

        let rv = self.extractors.process(message)?;
        for v in rv.iter() {
            let old = self.storage.set(v.name().to_string(), v.clone()).await?;
            if let Some(old) = old {
                info!("Old Reference value of {} is replaced.", old.name());
            }
        }

        Ok(())
    }

    pub async fn get_digests(&self) -> Result<HashMap<String, Vec<String>>> {
        let mut rv_map = HashMap::new();
        let reference_values = self.storage.get_values().await?;

        for rv in reference_values {
            if rv.expired() {
                warn!("Reference value of {} is expired.", rv.name());
                continue;
            }

            let hash_values = rv
                .hash_values()
                .iter()
                .map(|pair| pair.value().to_owned())
                .collect();

            rv_map.insert(rv.name().to_string(), hash_values);
        }
        Ok(rv_map)
    }

    pub async fn delete_reference_value(&mut self, name: &str) -> Result<bool> {
        match self.storage.delete(name).await? {
            Some(deleted_rv) => {
                info!(
                    "Reference value {} deleted successfully.",
                    deleted_rv.name()
                );
                Ok(true)
            }
            None => {
                warn!("Reference value {} not found for deletion.", name);
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use chrono::{Utc, TimeZone};
    use tempfile::NamedTempFile;
    use base64::{Engine, engine::general_purpose};

    // Test default_version function
    #[test]
    fn test_default_version() {
        assert_eq!(default_version(), MESSAGE_VERSION);
        assert_eq!(default_version(), "0.1.0");
    }

    // Test MESSAGE_VERSION constant
    #[test]
    fn test_message_version_constant() {
        assert_eq!(MESSAGE_VERSION, "0.1.0");
    }

    // Test Message struct
    #[test]
    fn test_message_creation() {
        let message = Message {
            version: "1.0.0".to_string(),
            payload: "test payload".to_string(),
            r#type: "sample".to_string(),
        };
        
        assert_eq!(message.version, "1.0.0");
        assert_eq!(message.payload, "test payload");
        assert_eq!(message.r#type, "sample");
    }

    #[test]
    fn test_message_serialization() {
        let message = Message {
            version: "1.0.0".to_string(),
            payload: "test payload".to_string(),
            r#type: "sample".to_string(),
        };
        
        let serialized = serde_json::to_value(&message).unwrap();
        let expected = json!({
            "version": "1.0.0",
            "payload": "test payload",
            "type": "sample"
        });
        
        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_message_deserialization() {
        let json_str = r#"{
            "version": "2.0.0",
            "payload": "test data",
            "type": "provenance"
        }"#;
        
        let message: Message = serde_json::from_str(json_str).unwrap();
        
        assert_eq!(message.version, "2.0.0");
        assert_eq!(message.payload, "test data");
        assert_eq!(message.r#type, "provenance");
    }

    #[test]
    fn test_message_deserialization_with_default_version() {
        let json_str = r#"{
            "payload": "test data",
            "type": "provenance"
        }"#;
        
        let message: Message = serde_json::from_str(json_str).unwrap();
        
        // Should use default version
        assert_eq!(message.version, MESSAGE_VERSION);
        assert_eq!(message.payload, "test data");
        assert_eq!(message.r#type, "provenance");
    }

    #[test]
    fn test_message_debug_format() {
        let message = Message {
            version: "1.0.0".to_string(),
            payload: "test".to_string(),
            r#type: "sample".to_string(),
        };
        
        let debug_str = format!("{:?}", message);
        assert!(debug_str.contains("Message"));
        assert!(debug_str.contains("1.0.0"));
        assert!(debug_str.contains("test"));
        assert!(debug_str.contains("sample"));
    }

    // Helper function to create a test config
    fn create_test_config() -> Config {
        let temp_file = NamedTempFile::new().unwrap();
        let file_path = temp_file.path().to_str().unwrap().to_string();
        
        Config {
            storage: storage::ReferenceValueStorageConfig::LocalJson(
                storage::local_json::Config {
                    file_path,
                }
            ),
        }
    }

    // Test Rvps struct creation
    #[test]
    fn test_rvps_new() {
        let config = create_test_config();
        let rvps = Rvps::new(config);
        
        assert!(rvps.is_ok());
    }

    #[test]
    fn test_rvps_with_ware() {
        let config = create_test_config();
        let mut rvps = Rvps::new(config).unwrap();
        
        // Test with_ware method (currently a no-op)
        let result = rvps.with_ware("test-ware");
        
        // Should return self reference
        assert!(std::ptr::eq(result, &rvps));
    }

    #[tokio::test]
    async fn test_rvps_verify_and_extract_valid_message() {
        let config = create_test_config();
        let mut rvps = Rvps::new(config).unwrap();
        
        // Create a valid message with proper base64 encoded payload
        let payload_data = json!({
            "test-artifact": ["hash1", "hash2"]
        });
        let payload_base64 = general_purpose::STANDARD.encode(payload_data.to_string());
        
        let message = json!({
            "version": "0.1.0",
            "type": "sample",
            "payload": payload_base64
        });
        
        let result = rvps.verify_and_extract(&message.to_string()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_rvps_verify_and_extract_invalid_json() {
        let config = create_test_config();
        let mut rvps = Rvps::new(config).unwrap();
        
        let invalid_json = "invalid json string";
        
        let result = rvps.verify_and_extract(invalid_json).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("parse message"));
    }

    #[tokio::test]
    async fn test_rvps_verify_and_extract_version_mismatch() {
        let config = create_test_config();
        let mut rvps = Rvps::new(config).unwrap();
        
        let message = json!({
            "version": "999.0.0",
            "type": "sample",
            "payload": "dGVzdA=="
        });
        
        let result = rvps.verify_and_extract(&message.to_string()).await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Version unmatched"));
        assert!(error_msg.contains("0.1.0"));
        assert!(error_msg.contains("999.0.0"));
    }

    #[tokio::test]
    async fn test_rvps_verify_and_extract_with_replacement() {
        let config = create_test_config();
        let mut rvps = Rvps::new(config).unwrap();
        
        // Create a message that will result in reference values
        let payload_data = json!({
            "test-artifact": ["hash1"]
        });
        let payload_base64 = general_purpose::STANDARD.encode(payload_data.to_string());
        
        let message = json!({
            "version": "0.1.0",
            "type": "sample",
            "payload": payload_base64
        });
        
        // First insertion
        let result1 = rvps.verify_and_extract(&message.to_string()).await;
        assert!(result1.is_ok());
        
        // Second insertion (should replace the old one)
        let payload_data2 = json!({
            "test-artifact": ["hash2"]
        });
        let payload_base64_2 = general_purpose::STANDARD.encode(payload_data2.to_string());
        
        let message2 = json!({
            "version": "0.1.0",
            "type": "sample",
            "payload": payload_base64_2
        });
        
        let result2 = rvps.verify_and_extract(&message2.to_string()).await;
        assert!(result2.is_ok());
    }

    #[tokio::test]
    async fn test_rvps_get_digests_empty() {
        let config = create_test_config();
        let rvps = Rvps::new(config).unwrap();
        
        let result = rvps.get_digests().await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_rvps_get_digests_with_data() {
        let config = create_test_config();
        let mut rvps = Rvps::new(config).unwrap();
        
        // Add some reference values first
        let payload_data = json!({
            "artifact1": ["hash1", "hash2"],
            "artifact2": ["hash3"]
        });
        let payload_base64 = general_purpose::STANDARD.encode(payload_data.to_string());
        
        let message = json!({
            "version": "0.1.0",
            "type": "sample",
            "payload": payload_base64
        });
        
        rvps.verify_and_extract(&message.to_string()).await.unwrap();
        
        let result = rvps.get_digests().await;
        assert!(result.is_ok());
        
        let digests = result.unwrap();
        assert!(!digests.is_empty());
        assert!(digests.contains_key("artifact1"));
        assert!(digests.contains_key("artifact2"));
        
        let artifact1_hashes = &digests["artifact1"];
        assert_eq!(artifact1_hashes.len(), 2);
        assert!(artifact1_hashes.contains(&"hash1".to_string()));
        assert!(artifact1_hashes.contains(&"hash2".to_string()));
        
        let artifact2_hashes = &digests["artifact2"];
        assert_eq!(artifact2_hashes.len(), 1);
        assert!(artifact2_hashes.contains(&"hash3".to_string()));
    }

    #[tokio::test]
    async fn test_rvps_get_digests_with_expired_values() {
        let config = create_test_config();
        let rvps = Rvps::new(config).unwrap();
        
        // Manually create an expired reference value
        let past_time = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        let expired_rv = ReferenceValue::new()
            .unwrap()
            .set_name("expired-artifact")
            .set_expiration(past_time)
            .add_hash_value("sha256".to_string(), "expiredhash".to_string());
        
        // Set the expired reference value
        rvps.storage.set("expired-artifact".to_string(), expired_rv).await.unwrap();
        
        let result = rvps.get_digests().await;
        assert!(result.is_ok());
        
        let digests = result.unwrap();
        // Should not contain expired values
        assert!(!digests.contains_key("expired-artifact"));
    }

    #[tokio::test]
    async fn test_rvps_delete_reference_value_existing() {
        let config = create_test_config();
        let mut rvps = Rvps::new(config).unwrap();
        
        // First add a reference value
        let payload_data = json!({
            "test-artifact": ["hash1"]
        });
        let payload_base64 = general_purpose::STANDARD.encode(payload_data.to_string());
        
        let message = json!({
            "version": "0.1.0",
            "type": "sample",
            "payload": payload_base64
        });
        
        rvps.verify_and_extract(&message.to_string()).await.unwrap();
        
        // Now delete it
        let result = rvps.delete_reference_value("test-artifact").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[tokio::test]
    async fn test_rvps_delete_reference_value_non_existing() {
        let config = create_test_config();
        let mut rvps = Rvps::new(config).unwrap();
        
        let result = rvps.delete_reference_value("non-existing").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false);
    }

    // Test error conditions for get_digests
    #[tokio::test]
    async fn test_rvps_get_digests_hash_value_mapping() {
        let config = create_test_config();
        let rvps = Rvps::new(config).unwrap();
        
        // Manually create a reference value with multiple hash algorithms
        let future_time = Utc::now() + chrono::Duration::days(1);
        let rv = ReferenceValue::new()
            .unwrap()
            .set_name("multi-hash-artifact")
            .set_expiration(future_time)
            .add_hash_value("sha256".to_string(), "sha256hash".to_string())
            .add_hash_value("sha512".to_string(), "sha512hash".to_string());
        
        rvps.storage.set("multi-hash-artifact".to_string(), rv).await.unwrap();
        
        let result = rvps.get_digests().await;
        assert!(result.is_ok());
        
        let digests = result.unwrap();
        assert!(digests.contains_key("multi-hash-artifact"));
        
        let hashes = &digests["multi-hash-artifact"];
        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains(&"sha256hash".to_string()));
        assert!(hashes.contains(&"sha512hash".to_string()));
    }

    // Test the complete flow from message to storage
    #[tokio::test]
    async fn test_rvps_complete_flow() {
        let config = create_test_config();
        let mut rvps = Rvps::new(config).unwrap();
        
        // Step 1: Add reference values
        let payload_data = json!({
            "app1": ["hash1", "hash2"],
            "app2": ["hash3"]
        });
        let payload_base64 = general_purpose::STANDARD.encode(payload_data.to_string());
        
        let message = json!({
            "version": "0.1.0",
            "type": "sample",
            "payload": payload_base64
        });
        
        // Verify and extract
        rvps.verify_and_extract(&message.to_string()).await.unwrap();
        
        // Step 2: Get digests
        let digests = rvps.get_digests().await.unwrap();
        assert_eq!(digests.len(), 2);
        assert!(digests.contains_key("app1"));
        assert!(digests.contains_key("app2"));
        
        // Step 3: Delete one reference value
        let deleted = rvps.delete_reference_value("app1").await.unwrap();
        assert!(deleted);
        
        // Step 4: Verify deletion
        let digests_after_delete = rvps.get_digests().await.unwrap();
        assert_eq!(digests_after_delete.len(), 1);
        assert!(!digests_after_delete.contains_key("app1"));
        assert!(digests_after_delete.contains_key("app2"));
        
        // Step 5: Try to delete non-existing
        let not_deleted = rvps.delete_reference_value("app1").await.unwrap();
        assert!(!not_deleted);
    }

    // Test edge cases
    #[tokio::test]
    async fn test_rvps_multiple_extractions() {
        let config = create_test_config();
        let mut rvps = Rvps::new(config).unwrap();
        
        // Create multiple messages
        for i in 1..=3 {
            let payload_data = json!({
                format!("artifact{}", i): [format!("hash{}", i)]
            });
            let payload_base64 = general_purpose::STANDARD.encode(payload_data.to_string());
            
            let message = json!({
                "version": "0.1.0",
                "type": "sample",
                "payload": payload_base64
            });
            
            rvps.verify_and_extract(&message.to_string()).await.unwrap();
        }
        
        let digests = rvps.get_digests().await.unwrap();
        assert_eq!(digests.len(), 3);
        
        for i in 1..=3 {
            let key = format!("artifact{}", i);
            assert!(digests.contains_key(&key));
            assert_eq!(digests[&key].len(), 1);
            assert_eq!(digests[&key][0], format!("hash{}", i));
        }
    }

    // Test with_ware multiple calls
    #[test]
    fn test_rvps_with_ware_chaining() {
        let config = create_test_config();
        let mut rvps = Rvps::new(config).unwrap();
        
        // Test chaining with_ware calls
        rvps.with_ware("ware1");
        rvps.with_ware("ware2");
        let result = rvps.with_ware("ware3");
        
        // Should return self reference
        assert!(std::ptr::eq(result, &rvps));
    }

    // Test empty hash values scenario
    #[tokio::test]
    async fn test_rvps_get_digests_empty_hash_values() {
        let config = create_test_config();
        let rvps = Rvps::new(config).unwrap();
        
        // Create a reference value with no hash values
        let future_time = Utc::now() + chrono::Duration::days(1);
        let rv = ReferenceValue::new()
            .unwrap()
            .set_name("no-hash-artifact")
            .set_expiration(future_time);
        
        rvps.storage.set("no-hash-artifact".to_string(), rv).await.unwrap();
        
        let result = rvps.get_digests().await;
        assert!(result.is_ok());
        
        let digests = result.unwrap();
        assert!(digests.contains_key("no-hash-artifact"));
        assert!(digests["no-hash-artifact"].is_empty());
    }
}
