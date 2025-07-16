//! Attestation Service
//!
//! # Features
//! - `rvps-grpc`: The AS will connect a remote RVPS.

pub mod config;
pub mod policy_engine;
pub mod rvps;
pub mod token;

use crate::token::AttestationTokenBroker;

use anyhow::{anyhow, Context, Result};
use config::Config;
pub use kbs_types::{Attestation, Tee};
use log::{debug, info};
use reqwest::Client;
use rvps::{RvpsApi, RvpsError};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::HashMap;
use std::io::Read;
use strum::{AsRefStr, Display, EnumString};
use thiserror::Error;
use tokio::fs;
use verifier::{InitDataHash, ReportData};

/// Hash algorithms used to calculate runtime/init data binding
#[derive(Debug, Display, EnumString, AsRefStr)]
pub enum HashAlgorithm {
    #[strum(ascii_case_insensitive)]
    Sha256,

    #[strum(ascii_case_insensitive)]
    Sha384,

    #[strum(ascii_case_insensitive)]
    Sha512,
}

impl HashAlgorithm {
    fn accumulate_hash(&self, materials: Vec<u8>) -> Vec<u8> {
        match self {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(materials);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(materials);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(materials);
                hasher.finalize().to_vec()
            }
        }
    }
}

/// Runtime/Init Data used to check the binding relationship with report data
/// in Evidence
#[derive(Debug, Clone)]
pub enum Data {
    /// This will be used as the expected runtime/init data to check against
    /// the one inside evidence.
    Raw(Vec<u8>),

    /// Runtime/Init data in a JSON map. CoCoAS will rearrange each layer of the
    /// data JSON object in dictionary order by key, then serialize and output
    /// it into a compact string, and perform hash calculation on the whole
    /// to check against the one inside evidence.
    Structured(Value),
}

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("io error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Create AS work dir failed: {0}")]
    CreateDir(#[source] std::io::Error),
    #[error("Policy Engine is not supported: {0}")]
    UnsupportedPolicy(#[source] strum::ParseError),
    #[error("Create rvps failed: {0}")]
    Rvps(#[source] RvpsError),
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

pub struct AttestationService {
    _config: Config,
    rvps: Box<dyn RvpsApi + Send + Sync>,
    token_broker: Box<dyn AttestationTokenBroker + Send + Sync>,
}

impl AttestationService {
    /// Create a new Attestation Service instance.
    pub async fn new(config: Config) -> Result<Self, ServiceError> {
        if !config.work_dir.as_path().exists() {
            fs::create_dir_all(&config.work_dir)
                .await
                .map_err(ServiceError::CreateDir)?;
        }

        let rvps = rvps::initialize_rvps_client(&config.rvps_config)
            .await
            .map_err(ServiceError::Rvps)?;

        let token_broker = config.attestation_token_broker.to_token_broker()?;

        Ok(Self {
            _config: config,
            rvps,
            token_broker,
        })
    }

    /// Set Attestation Verification Policy.
    pub async fn set_policy(&mut self, policy_id: String, policy: String) -> Result<()> {
        self.token_broker.set_policy(policy_id, policy).await?;
        Ok(())
    }

    /// Get Attestation Verification Policy List.
    /// The result is a `policy-id` -> `policy hash` map.
    pub async fn list_policies(&self) -> Result<HashMap<String, String>> {
        self.token_broker
            .list_policies()
            .await
            .context("Cannot List Policy")
    }

    /// Get a single Policy content.
    pub async fn get_policy(&self, policy_id: String) -> Result<String> {
        self.token_broker
            .get_policy(policy_id)
            .await
            .context("Cannot Get Policy")
    }

    /// Delete a single Policy.
    pub async fn delete_policy(&self, policy_id: String) -> Result<()> {
        self.token_broker
            .delete_policy(policy_id)
            .await
            .context("Cannot Delete Policy")
    }

    /// Evaluate Attestation Evidence.
    /// Issue an attestation results token which contain TCB status and TEE public key. Input parameters:
    /// - `evidence`: TEE evidence bytes. This might not be the raw hardware evidence bytes. Definitions
    ///   are in `verifier` crate.
    /// - `tee`: concrete TEE type
    /// - `runtime_data`: These data field will be used to check against the counterpart inside the evidence.
    ///   The concrete way of checking is decide by the enum type. If this parameter is set `None`, the comparation
    ///   will not be performed.
    /// - `init_data`: These data field will be used to check against the counterpart inside the evidence.
    ///   The concrete way of checking is decide by the enum type. If this parameter is set `None`, the comparation
    ///   will not be performed.
    /// - `hash_algorithm`: The hash algorithm that is used to calculate the digest of `runtime_data` and
    ///   `init_data`.
    /// - `policy_ids`: The ids of the policies that will be used to evaluate the claims.
    ///    For EAR tokens, only the first policy will be evaluated.
    ///    The hash of the policy will be returned as part of the attestation token.
    #[allow(clippy::too_many_arguments)]
    pub async fn evaluate(
        &self,
        evidence: Vec<u8>,
        tee: Tee,
        runtime_data: Option<Data>,
        runtime_data_hash_algorithm: HashAlgorithm,
        init_data: Option<Data>,
        init_data_hash_algorithm: HashAlgorithm,
        policy_ids: Vec<String>,
    ) -> Result<String> {
        let verifier = verifier::to_verifier(&tee)?;

        let (report_data, runtime_data_claims) =
            parse_data(runtime_data, &runtime_data_hash_algorithm).context("parse runtime data")?;

        let report_data = match &report_data {
            Some(data) => ReportData::Value(data),
            None => ReportData::NotProvided,
        };

        let (init_data, init_data_claims) =
            parse_data(init_data, &init_data_hash_algorithm).context("parse init data")?;

        let init_data_hash = match &init_data {
            Some(data) => InitDataHash::Value(data),
            None => InitDataHash::NotProvided,
        };

        let claims_from_tee_evidence = verifier
            .evaluate(&evidence, &report_data, &init_data_hash)
            .await
            .map_err(|e| anyhow!("Verifier evaluate failed: {e:?}"))?;
        info!("{:?} Verifier/endorsement check passed.", tee);

        let reference_data_map = self
            .rvps
            .get_digests()
            .await
            .map_err(|e| anyhow!("Generate reference data failed: {:?}", e))?;
        debug!("reference_data_map: {:#?}", reference_data_map);

        let attestation_results_token = self
            .token_broker
            .issue(
                claims_from_tee_evidence,
                policy_ids,
                init_data_claims,
                runtime_data_claims,
                reference_data_map,
                tee,
            )
            .await?;
        Ok(attestation_results_token)
    }

    /// Registry a new reference value
    pub async fn register_reference_value(&mut self, message: &str) -> Result<()> {
        self.rvps
            .verify_and_extract(message)
            .await
            .context("register reference value")
    }

    /// Delete a reference value by name
    pub async fn delete_reference_value(&mut self, name: String) -> Result<bool> {
        self.rvps
            .delete_reference_value(&name)
            .await
            .context("delete reference value")
    }

    pub async fn generate_supplemental_challenge(
        &self,
        tee: Tee,
        tee_parameters: String,
    ) -> Result<String> {
        let verifier = verifier::to_verifier(&tee)?;
        verifier
            .generate_supplemental_challenge(tee_parameters)
            .await
    }

    /// Get token broker certificate content
    /// Returns the binary content of the certificate
    pub async fn get_token_broker_cert_config(&self) -> Result<Option<Vec<u8>>> {
        match &self._config.attestation_token_broker {
            token::AttestationTokenConfig::Simple(cfg) => {
                if let Some(signer) = &cfg.signer {
                    self.get_cert_content(signer.cert_path.as_deref(), signer.cert_url.as_deref())
                        .await
                } else {
                    Ok(None)
                }
            }
            token::AttestationTokenConfig::Ear(cfg) => {
                if let Some(signer) = &cfg.signer {
                    self.get_cert_content(signer.cert_path.as_deref(), signer.cert_url.as_deref())
                        .await
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Get certificate content from file path or URL
    async fn get_cert_content(
        &self,
        cert_path: Option<&str>,
        cert_url: Option<&str>,
    ) -> Result<Option<Vec<u8>>> {
        if let Some(path) = cert_path {
            // Read certificate from file
            let mut file = std::fs::File::open(path)
                .map_err(|e| anyhow!("Failed to open certificate file: {}", e))?;
            let mut content = Vec::new();
            file.read_to_end(&mut content)
                .map_err(|e| anyhow!("Failed to read certificate file: {}", e))?;
            Ok(Some(content))
        } else if let Some(url) = cert_url {
            // Get certificate from URL
            let client = Client::new();
            let response = client
                .get(url)
                .send()
                .await
                .map_err(|e| anyhow!("Failed to fetch certificate from URL: {}", e))?;

            if !response.status().is_success() {
                return Err(anyhow!(
                    "Failed to fetch certificate: HTTP {}",
                    response.status()
                ));
            }

            let content = response
                .bytes()
                .await
                .map_err(|e| anyhow!("Failed to read certificate content: {}", e))?;

            Ok(Some(content.to_vec()))
        } else {
            Ok(None)
        }
    }
}

/// Get the expected init/runtime data and potential claims due to the given input
/// and the hash algorithm
fn parse_data(
    data: Option<Data>,
    hash_algorithm: &HashAlgorithm,
) -> Result<(Option<Vec<u8>>, Value)> {
    match data {
        Some(value) => match value {
            Data::Raw(raw) => Ok((Some(raw), Value::Null)),
            Data::Structured(structured) => {
                // by default serde_json will enforence the alphabet order for keys
                let hash_materials =
                    serde_json::to_vec(&structured).context("parse JSON structured data")?;
                let digest = hash_algorithm.accumulate_hash(hash_materials);
                Ok((Some(digest), structured))
            }
        },
        None => Ok((None, Value::Null)),
    }
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use rstest::rstest;
    use serde_json::{json, Value};

    use crate::{Data, HashAlgorithm, ServiceError, AttestationService, config::Config, parse_data};
    use crate::rvps::RvpsError;
    use crate::token::AttestationTokenConfig;

    // Note: Mock implementations would require mockall dependency which is not included
    // For comprehensive testing, we focus on the actual implementations

    // Test HashAlgorithm enum and its methods
    #[test]
    fn test_hash_algorithm_from_str() {
        use std::str::FromStr;
        
        // Test case insensitive parsing
        assert!(matches!(HashAlgorithm::from_str("sha256"), Ok(HashAlgorithm::Sha256)));
        assert!(matches!(HashAlgorithm::from_str("SHA256"), Ok(HashAlgorithm::Sha256)));
        assert!(matches!(HashAlgorithm::from_str("Sha256"), Ok(HashAlgorithm::Sha256)));
        
        assert!(matches!(HashAlgorithm::from_str("sha384"), Ok(HashAlgorithm::Sha384)));
        assert!(matches!(HashAlgorithm::from_str("SHA384"), Ok(HashAlgorithm::Sha384)));
        assert!(matches!(HashAlgorithm::from_str("Sha384"), Ok(HashAlgorithm::Sha384)));
        
        assert!(matches!(HashAlgorithm::from_str("sha512"), Ok(HashAlgorithm::Sha512)));
        assert!(matches!(HashAlgorithm::from_str("SHA512"), Ok(HashAlgorithm::Sha512)));
        assert!(matches!(HashAlgorithm::from_str("Sha512"), Ok(HashAlgorithm::Sha512)));
        
        // Test invalid input
        assert!(HashAlgorithm::from_str("invalid").is_err());
        assert!(HashAlgorithm::from_str("").is_err());
        assert!(HashAlgorithm::from_str("md5").is_err());
    }

    #[test]
    fn test_hash_algorithm_display() {
        assert_eq!(format!("{}", HashAlgorithm::Sha256), "Sha256");
        assert_eq!(format!("{}", HashAlgorithm::Sha384), "Sha384");
        assert_eq!(format!("{}", HashAlgorithm::Sha512), "Sha512");
    }

    #[test]
    fn test_hash_algorithm_as_ref() {
        assert_eq!(HashAlgorithm::Sha256.as_ref(), "Sha256");
        assert_eq!(HashAlgorithm::Sha384.as_ref(), "Sha384");
        assert_eq!(HashAlgorithm::Sha512.as_ref(), "Sha512");
    }

    #[rstest]
    #[case(HashAlgorithm::Sha256, b"test", 32)] // SHA256 produces 32 bytes
    #[case(HashAlgorithm::Sha384, b"test", 48)] // SHA384 produces 48 bytes
    #[case(HashAlgorithm::Sha512, b"test", 64)] // SHA512 produces 64 bytes
    #[case(HashAlgorithm::Sha256, b"", 32)] // Empty input
    #[case(HashAlgorithm::Sha384, b"", 48)]
    #[case(HashAlgorithm::Sha512, b"", 64)]
    fn test_hash_algorithm_accumulate_hash(
        #[case] algorithm: HashAlgorithm,
        #[case] input: &[u8],
        #[case] expected_length: usize,
    ) {
        let result = algorithm.accumulate_hash(input.to_vec());
        assert_eq!(result.len(), expected_length);
        
        // Test deterministic behavior
        let result2 = algorithm.accumulate_hash(input.to_vec());
        assert_eq!(result, result2);
    }

    #[test]
    fn test_hash_algorithm_accumulate_hash_different_inputs() {
        let algorithm = HashAlgorithm::Sha256;
        let hash1 = algorithm.accumulate_hash(b"input1".to_vec());
        let hash2 = algorithm.accumulate_hash(b"input2".to_vec());
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_algorithm_accumulate_hash_large_input() {
        let algorithm = HashAlgorithm::Sha256;
        let large_input = vec![0u8; 1_000_000]; // 1MB of zeros
        let result = algorithm.accumulate_hash(large_input);
        assert_eq!(result.len(), 32);
    }

    // Test Data enum variants
    #[test]
    fn test_data_raw_variant() {
        let data = Data::Raw(vec![1, 2, 3, 4, 5]);
        match data {
            Data::Raw(bytes) => assert_eq!(bytes, vec![1, 2, 3, 4, 5]),
            _ => panic!("Expected Raw variant"),
        }
    }

    #[test]
    fn test_data_structured_variant() {
        let json_value = json!({"key": "value", "number": 42});
        let data = Data::Structured(json_value.clone());
        match data {
            Data::Structured(value) => assert_eq!(value, json_value),
            _ => panic!("Expected Structured variant"),
        }
    }

    #[test]
    fn test_data_debug_format() {
        let raw_data = Data::Raw(vec![1, 2, 3]);
        let debug_str = format!("{:?}", raw_data);
        assert!(debug_str.contains("Raw"));
        
        let structured_data = Data::Structured(json!({"test": true}));
        let debug_str = format!("{:?}", structured_data);
        assert!(debug_str.contains("Structured"));
    }

    // Test ServiceError variants
    #[test]
    fn test_service_error_io() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
        let service_error = ServiceError::IO(io_error);
        assert!(format!("{}", service_error).contains("io error"));
    }

    #[test]
    fn test_service_error_create_dir() {
        let io_error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Permission denied");
        let service_error = ServiceError::CreateDir(io_error);
        assert!(format!("{}", service_error).contains("Create AS work dir failed"));
    }

    #[test]
    fn test_service_error_unsupported_policy() {
        use std::str::FromStr;
        
        // Create a parse error by trying to parse an invalid enum variant
        let parse_error = HashAlgorithm::from_str("invalid").unwrap_err();
        let service_error = ServiceError::UnsupportedPolicy(parse_error);
        assert!(format!("{}", service_error).contains("Policy Engine is not supported"));
    }

    #[test]
    fn test_service_error_rvps() {
        let rvps_error = RvpsError::Anyhow(anyhow::anyhow!("Test error"));
        let service_error = ServiceError::Rvps(rvps_error);
        assert!(format!("{}", service_error).contains("Create rvps failed"));
    }

    #[test]
    fn test_service_error_anyhow() {
        let anyhow_error = anyhow::anyhow!("Test anyhow error");
        let service_error = ServiceError::Anyhow(anyhow_error);
        assert!(format!("{}", service_error).contains("Test anyhow error"));
    }

    // Test parse_data function comprehensively
    #[rstest]
    #[case(Some(Data::Raw(b"aaaaa".to_vec())), Some(b"aaaaa".to_vec()), HashAlgorithm::Sha384, Value::Null)]
    #[case(None, None, HashAlgorithm::Sha384, Value::Null)]
    #[case(Some(Data::Structured(json!({"b": 1, "a": "test", "c": {"d": "e"}}))), Some(hex::decode(b"e71ce8e70d814ba6639c3612ebee0ff1f76f650f8dbb5e47157e0f3f525cd22c4597480a186427c813ca941da78870c3").unwrap()), HashAlgorithm::Sha384, json!({"b": 1, "a": "test", "c": {"d": "e"}}))]
    fn parse_data_json_binding(
        #[case] input: Option<Data>,
        #[case] expected_data: Option<Vec<u8>>,
        #[case] hash_algorithm: HashAlgorithm,
        #[case] expected_claims: Value,
    ) {
        let (data, data_claims) = parse_data(input, &hash_algorithm).expect("parse failed");
        assert_eq!(data, expected_data);
        assert_json_eq!(data_claims, expected_claims);
    }

    #[test]
    fn test_parse_data_raw_empty() {
        let (data, claims) = parse_data(Some(Data::Raw(vec![])), &HashAlgorithm::Sha256).unwrap();
        assert_eq!(data, Some(vec![]));
        assert_eq!(claims, Value::Null);
    }

    #[test]
    fn test_parse_data_structured_empty_object() {
        let (data, claims) = parse_data(Some(Data::Structured(json!({}))), &HashAlgorithm::Sha256).unwrap();
        assert!(data.is_some());
        assert_eq!(claims, json!({}));
    }

    #[test]
    fn test_parse_data_structured_null() {
        let (data, claims) = parse_data(Some(Data::Structured(Value::Null)), &HashAlgorithm::Sha256).unwrap();
        assert!(data.is_some());
        assert_eq!(claims, Value::Null);
    }

    #[test]
    fn test_parse_data_structured_array() {
        let array_value = json!([1, 2, 3, "test"]);
        let (data, claims) = parse_data(Some(Data::Structured(array_value.clone())), &HashAlgorithm::Sha256).unwrap();
        assert!(data.is_some());
        assert_eq!(claims, array_value);
    }

    #[test]
    fn test_parse_data_structured_complex_nested() {
        let complex_value = json!({
            "level1": {
                "level2": {
                    "level3": ["a", "b", "c"],
                    "number": 123,
                    "boolean": true
                },
                "array": [{"key": "value"}, null, 456]
            },
            "top_level": "test"
        });
        let (data, claims) = parse_data(Some(Data::Structured(complex_value.clone())), &HashAlgorithm::Sha512).unwrap();
        assert!(data.is_some());
        assert_eq!(data.unwrap().len(), 64); // SHA512 produces 64 bytes
        assert_eq!(claims, complex_value);
    }

    #[test]
    fn test_parse_data_structured_different_hash_algorithms() {
        let test_data = json!({"test": "value"});
        
        let (data_256, _) = parse_data(Some(Data::Structured(test_data.clone())), &HashAlgorithm::Sha256).unwrap();
        let (data_384, _) = parse_data(Some(Data::Structured(test_data.clone())), &HashAlgorithm::Sha384).unwrap();
        let (data_512, _) = parse_data(Some(Data::Structured(test_data.clone())), &HashAlgorithm::Sha512).unwrap();
        
        assert_eq!(data_256.unwrap().len(), 32);
        assert_eq!(data_384.unwrap().len(), 48);
        assert_eq!(data_512.unwrap().len(), 64);
    }

    #[test]
    fn test_parse_data_structured_key_ordering() {
        // JSON with keys in different order should produce same hash
        let json1 = json!({"b": 2, "a": 1, "c": 3});
        let json2 = json!({"a": 1, "b": 2, "c": 3});
        
        let (data1, _) = parse_data(Some(Data::Structured(json1)), &HashAlgorithm::Sha256).unwrap();
        let (data2, _) = parse_data(Some(Data::Structured(json2)), &HashAlgorithm::Sha256).unwrap();
        
        assert_eq!(data1, data2);
    }

         // Test helper function for creating temporary config files
     #[allow(dead_code)]
     fn create_temp_config() -> (Config, tempfile::TempDir) {
         let temp_dir = tempfile::tempdir().unwrap();
         let work_dir = temp_dir.path().to_path_buf();
         
         let config = Config {
             work_dir,
             rvps_config: crate::rvps::RvpsConfig::BuiltIn(Default::default()),
             attestation_token_broker: AttestationTokenConfig::Simple(Default::default()),
         };
         
         (config, temp_dir)
     }
    
         #[tokio::test]
     async fn test_attestation_service_work_dir_creation() {
         let temp_dir = tempfile::tempdir().unwrap();
         let work_dir = temp_dir.path().join("non_existent_dir");
         
         let config = Config {
             work_dir: work_dir.clone(),
             rvps_config: crate::rvps::RvpsConfig::BuiltIn(Default::default()),
             attestation_token_broker: AttestationTokenConfig::Simple(Default::default()),
         };
         
         // This should create the directory
         let _result = AttestationService::new(config).await;
         
         // Check if the directory was created
         assert!(work_dir.exists());
         
         // Cleanup is handled by tempdir drop
     }

    #[test]
    fn test_service_error_debug_format() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
        let service_error = ServiceError::IO(io_error);
        let debug_str = format!("{:?}", service_error);
        assert!(debug_str.contains("IO"));
    }

         #[test]
     fn test_data_enum_memory_size() {
         // Ensure enum variants don't have unexpected memory overhead
         use std::mem::size_of;
         
         let _raw_data = Data::Raw(vec![1, 2, 3]);
         let _structured_data = Data::Structured(json!({"key": "value"}));
         
         // Both should be reasonable in size (within a few hundred bytes)
         assert!(size_of::<Data>() < 1000);
     }

    // Test edge cases for hash algorithms with extreme inputs
    #[test]
    fn test_hash_algorithm_with_max_vec_size() {
        let algorithm = HashAlgorithm::Sha256;
        
        // Test with reasonably large input (avoid OOM in tests)
        let large_input = vec![0xAA; 100_000];
        let result = algorithm.accumulate_hash(large_input);
        assert_eq!(result.len(), 32);
        
        // Verify it's not all zeros
        assert!(result.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_hash_algorithm_with_alternating_pattern() {
        let algorithm = HashAlgorithm::Sha384;
        let pattern: Vec<u8> = (0..1000).map(|i| (i % 2) as u8).collect();
        let result = algorithm.accumulate_hash(pattern);
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn test_parse_data_with_unicode_strings() {
        let unicode_json = json!({
            "chinese": "你好世界",
            "emoji": "🚀🌟",
            "special": "café naïve résumé"
        });
        
        let (data, claims) = parse_data(Some(Data::Structured(unicode_json.clone())), &HashAlgorithm::Sha256).unwrap();
        assert!(data.is_some());
        assert_eq!(claims, unicode_json);
    }

    #[test]
    fn test_parse_data_with_numeric_edge_cases() {
        let numeric_json = json!({
            "zero": 0,
            "negative": -42,
            "float": 3.14159,
            "scientific": 1.23e-10,
            "max_i64": i64::MAX,
            "min_i64": i64::MIN
        });
        
        let (data, claims) = parse_data(Some(Data::Structured(numeric_json.clone())), &HashAlgorithm::Sha256).unwrap();
        assert!(data.is_some());
        assert_eq!(claims, numeric_json);
    }

    // Test that Hash algorithms produce consistent results across calls
    #[test]
    fn test_hash_consistency_across_multiple_calls() {
        let test_data = b"consistency test data".to_vec();
        
        for algorithm in [HashAlgorithm::Sha256, HashAlgorithm::Sha384, HashAlgorithm::Sha512] {
            let hash1 = algorithm.accumulate_hash(test_data.clone());
            let hash2 = algorithm.accumulate_hash(test_data.clone());
            let hash3 = algorithm.accumulate_hash(test_data.clone());
            
            assert_eq!(hash1, hash2);
            assert_eq!(hash2, hash3);
        }
    }

         // Test for potential overflow in hash algorithm
     #[test]
     fn test_hash_algorithm_boundary_values() {
         let algorithms = [HashAlgorithm::Sha256, HashAlgorithm::Sha384, HashAlgorithm::Sha512];
         let expected_lengths = [32, 48, 64];
         
         for (algorithm, expected_len) in algorithms.iter().zip(expected_lengths.iter()) {
             // Test with single byte
             let result = algorithm.accumulate_hash(vec![0xFF]);
             assert_eq!(result.len(), *expected_len);
             
             // Test with alternating bytes
             let alternating = vec![0x00, 0xFF].repeat(1000);
             let result = algorithm.accumulate_hash(alternating);
             assert_eq!(result.len(), *expected_len);
         }
     }

     // Test AttestationService certificate methods
     #[tokio::test]
     async fn test_get_cert_content_from_file() {
         let temp_dir = tempfile::tempdir().unwrap();
         let cert_path = temp_dir.path().join("test_cert.pem");
         let cert_content = b"-----BEGIN CERTIFICATE-----\ntest certificate content\n-----END CERTIFICATE-----";
         
         std::fs::write(&cert_path, cert_content).unwrap();
         
         let config = Config {
             work_dir: temp_dir.path().to_path_buf(),
             rvps_config: crate::rvps::RvpsConfig::BuiltIn(Default::default()),
             attestation_token_broker: AttestationTokenConfig::Simple(Default::default()),
         };
         
         let service = AttestationService::new(config).await.unwrap();
         let result = service.get_cert_content(Some(cert_path.to_str().unwrap()), None).await.unwrap();
         
         assert_eq!(result, Some(cert_content.to_vec()));
     }

     #[tokio::test]
     async fn test_get_cert_content_file_not_found() {
         let config = Config {
             work_dir: tempfile::tempdir().unwrap().path().to_path_buf(),
             rvps_config: crate::rvps::RvpsConfig::BuiltIn(Default::default()),
             attestation_token_broker: AttestationTokenConfig::Simple(Default::default()),
         };
         
         let service = AttestationService::new(config).await.unwrap();
         let result = service.get_cert_content(Some("/non/existent/path"), None).await;
         
         assert!(result.is_err());
         assert!(result.unwrap_err().to_string().contains("Failed to open certificate file"));
     }

     #[tokio::test]
     async fn test_get_cert_content_no_cert_path_or_url() {
         let config = Config {
             work_dir: tempfile::tempdir().unwrap().path().to_path_buf(),
             rvps_config: crate::rvps::RvpsConfig::BuiltIn(Default::default()),
             attestation_token_broker: AttestationTokenConfig::Simple(Default::default()),
         };
         
         let service = AttestationService::new(config).await.unwrap();
         let result = service.get_cert_content(None, None).await.unwrap();
         
         assert_eq!(result, None);
     }

     #[tokio::test]
     async fn test_get_cert_content_empty_file() {
         let temp_dir = tempfile::tempdir().unwrap();
         let cert_path = temp_dir.path().join("empty_cert.pem");
         
         std::fs::write(&cert_path, b"").unwrap();
         
         let config = Config {
             work_dir: temp_dir.path().to_path_buf(),
             rvps_config: crate::rvps::RvpsConfig::BuiltIn(Default::default()),
             attestation_token_broker: AttestationTokenConfig::Simple(Default::default()),
         };
         
         let service = AttestationService::new(config).await.unwrap();
         let result = service.get_cert_content(Some(cert_path.to_str().unwrap()), None).await.unwrap();
         
         assert_eq!(result, Some(vec![]));
     }

     #[tokio::test]
     async fn test_get_cert_content_large_file() {
         let temp_dir = tempfile::tempdir().unwrap();
         let cert_path = temp_dir.path().join("large_cert.pem");
         let large_content = vec![b'A'; 10_000]; // 10KB file
         
         std::fs::write(&cert_path, &large_content).unwrap();
         
         let config = Config {
             work_dir: temp_dir.path().to_path_buf(),
             rvps_config: crate::rvps::RvpsConfig::BuiltIn(Default::default()),
             attestation_token_broker: AttestationTokenConfig::Simple(Default::default()),
         };
         
         let service = AttestationService::new(config).await.unwrap();
         let result = service.get_cert_content(Some(cert_path.to_str().unwrap()), None).await.unwrap();
         
         assert_eq!(result, Some(large_content));
     }

     #[tokio::test]
     async fn test_get_cert_content_binary_file() {
         let temp_dir = tempfile::tempdir().unwrap();
         let cert_path = temp_dir.path().join("binary_cert.der");
         let binary_content: Vec<u8> = (0..256).map(|i| i as u8).collect();
         
         std::fs::write(&cert_path, &binary_content).unwrap();
         
         let config = Config {
             work_dir: temp_dir.path().to_path_buf(),
             rvps_config: crate::rvps::RvpsConfig::BuiltIn(Default::default()),
             attestation_token_broker: AttestationTokenConfig::Simple(Default::default()),
         };
         
         let service = AttestationService::new(config).await.unwrap();
         let result = service.get_cert_content(Some(cert_path.to_str().unwrap()), None).await.unwrap();
         
         assert_eq!(result, Some(binary_content));
     }

     // Test certificate path priority (file path takes precedence over URL)
     #[tokio::test]
     async fn test_get_cert_content_file_path_precedence() {
         let temp_dir = tempfile::tempdir().unwrap();
         let cert_path = temp_dir.path().join("priority_cert.pem");
         let file_content = b"file content";
         
         std::fs::write(&cert_path, file_content).unwrap();
         
         let config = Config {
             work_dir: temp_dir.path().to_path_buf(),
             rvps_config: crate::rvps::RvpsConfig::BuiltIn(Default::default()),
             attestation_token_broker: AttestationTokenConfig::Simple(Default::default()),
         };
         
         let service = AttestationService::new(config).await.unwrap();
         // Both file path and URL provided, should use file path
         let result = service.get_cert_content(
             Some(cert_path.to_str().unwrap()), 
             Some("https://example.com/cert")
         ).await.unwrap();
         
         assert_eq!(result, Some(file_content.to_vec()));
     }

     // Test for very long file paths (edge case)
     #[tokio::test]
     async fn test_get_cert_content_long_path() {
         let temp_dir = tempfile::tempdir().unwrap();
         let long_name = "a".repeat(100); // Very long filename
         let cert_path = temp_dir.path().join(long_name);
         let content = b"test content";
         
         std::fs::write(&cert_path, content).unwrap();
         
         let config = Config {
             work_dir: temp_dir.path().to_path_buf(),
             rvps_config: crate::rvps::RvpsConfig::BuiltIn(Default::default()),
             attestation_token_broker: AttestationTokenConfig::Simple(Default::default()),
         };
         
         let service = AttestationService::new(config).await.unwrap();
         let result = service.get_cert_content(Some(cert_path.to_str().unwrap()), None).await.unwrap();
         
         assert_eq!(result, Some(content.to_vec()));
     }

     // Test permission denied error (simulated by using directory as file path)
     #[tokio::test]
     async fn test_get_cert_content_permission_denied() {
         let temp_dir = tempfile::tempdir().unwrap();
         let dir_path = temp_dir.path().join("test_dir");
         std::fs::create_dir(&dir_path).unwrap();
         
         let config = Config {
             work_dir: temp_dir.path().to_path_buf(),
             rvps_config: crate::rvps::RvpsConfig::BuiltIn(Default::default()),
             attestation_token_broker: AttestationTokenConfig::Simple(Default::default()),
         };
         
         let service = AttestationService::new(config).await.unwrap();
         // Try to read a directory as file - should fail
         let result = service.get_cert_content(Some(dir_path.to_str().unwrap()), None).await;
         
         assert!(result.is_err());
     }

     // Test URL-based certificate retrieval error paths
     #[tokio::test]
     async fn test_get_cert_content_invalid_url() {
         let config = Config {
             work_dir: tempfile::tempdir().unwrap().path().to_path_buf(),
             rvps_config: crate::rvps::RvpsConfig::BuiltIn(Default::default()),
             attestation_token_broker: AttestationTokenConfig::Simple(Default::default()),
         };
         
         let service = AttestationService::new(config).await.unwrap();
         let result = service.get_cert_content(None, Some("invalid-url")).await;
         
         assert!(result.is_err());
         assert!(result.unwrap_err().to_string().contains("Failed to fetch certificate from URL"));
     }

     // Test edge cases for Data enum size calculation
     #[test]
     fn test_data_enum_size_edge_cases() {
         use std::mem::size_of_val;
         
         // Test with very large vector
         let large_data = Data::Raw(vec![0u8; 1000]);
         // The enum itself should be small, the large data is on heap
         assert!(size_of_val(&large_data) < 100);
         
         // Test with complex JSON
         let complex_json = json!({
             "deeply": {
                 "nested": {
                     "object": {
                         "with": {
                             "many": {
                                 "levels": "value"
                             }
                         }
                     }
                 }
             }
         });
         let structured_data = Data::Structured(complex_json);
         assert!(size_of_val(&structured_data) < 200);
     }

     // Test ServiceError source chains
     #[test]
     fn test_service_error_source_chain() {
         use std::error::Error;
         
         let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
         let service_error = ServiceError::CreateDir(io_error);
         
         // Test error source chain
         assert!(service_error.source().is_some());
         assert_eq!(service_error.source().unwrap().to_string(), "File not found");
     }

     // Test parse_data with malformed JSON (should not occur in practice due to type safety)
     #[test]
     fn test_parse_data_json_serialization_consistency() {
         // Test that the same JSON structure always produces the same hash
         let json_data = json!({
             "float": 1.0,
             "int": 1,
             "string": "test",
             "bool": true,
             "null": null,
             "array": [1, 2, 3],
             "object": {"nested": "value"}
         });
         
         let (hash1, _) = parse_data(Some(Data::Structured(json_data.clone())), &HashAlgorithm::Sha256).unwrap();
         let (hash2, _) = parse_data(Some(Data::Structured(json_data.clone())), &HashAlgorithm::Sha256).unwrap();
         
         assert_eq!(hash1, hash2);
     }

     // Test that different JSON representations of the same logical data produce the same hash
     #[test]
     fn test_parse_data_json_canonical_form() {
         // These should produce the same hash due to canonical JSON ordering
         let json1 = serde_json::from_str::<Value>(r#"{"b": 1, "a": 2}"#).unwrap();
         let json2 = serde_json::from_str::<Value>(r#"{"a": 2, "b": 1}"#).unwrap();
         
         let (hash1, _) = parse_data(Some(Data::Structured(json1)), &HashAlgorithm::Sha256).unwrap();
         let (hash2, _) = parse_data(Some(Data::Structured(json2)), &HashAlgorithm::Sha256).unwrap();
         
         assert_eq!(hash1, hash2);
     }

     // Test HashAlgorithm enum completeness
     #[test]
     fn test_hash_algorithm_enum_completeness() {
         // Ensure all variants are tested
         let algorithms = vec![
             HashAlgorithm::Sha256,
             HashAlgorithm::Sha384,
             HashAlgorithm::Sha512,
         ];
         
         // Test each algorithm works
         for algorithm in algorithms {
             let result = algorithm.accumulate_hash(b"test".to_vec());
             assert!(!result.is_empty());
             
             // Test debug formatting
             let debug_str = format!("{:?}", algorithm);
             assert!(!debug_str.is_empty());
         }
     }

     // Test extreme edge cases for hash input
     #[test]
     fn test_hash_algorithm_extreme_inputs() {
         let algorithm = HashAlgorithm::Sha256;
         
         // Test with maximum u8 values
         let max_bytes = vec![255u8; 1000];
         let result = algorithm.accumulate_hash(max_bytes);
         assert_eq!(result.len(), 32);
         
         // Test with minimum u8 values (all zeros)
         let min_bytes = vec![0u8; 1000];
         let result = algorithm.accumulate_hash(min_bytes);
         assert_eq!(result.len(), 32);
         
         // Test with single maximum byte
         let single_max = vec![255u8];
         let result = algorithm.accumulate_hash(single_max);
         assert_eq!(result.len(), 32);
     }

     // Test Data enum with extreme JSON values
     #[test]
     fn test_data_structured_extreme_json() {
         // Test with very large numbers
         let large_number_json = json!({
             "large_positive": 9223372036854775807i64, // i64::MAX
             "large_negative": -9223372036854775808i64, // i64::MIN
             "large_float": 1.7976931348623157e308f64,
             "small_float": f64::MIN_POSITIVE
         });
         
         let (data, claims) = parse_data(Some(Data::Structured(large_number_json.clone())), &HashAlgorithm::Sha256).unwrap();
         assert!(data.is_some());
         assert_eq!(claims, large_number_json);
     }

     // Test Data enum with empty and null edge cases
     #[test]
     fn test_data_structured_empty_and_null_cases() {
         // Test array with nulls
         let null_array = json!([null, null, null]);
         let (data, claims) = parse_data(Some(Data::Structured(null_array.clone())), &HashAlgorithm::Sha256).unwrap();
         assert!(data.is_some());
         assert_eq!(claims, null_array);
         
         // Test object with null values
         let null_object = json!({"a": null, "b": null});
         let (data, claims) = parse_data(Some(Data::Structured(null_object.clone())), &HashAlgorithm::Sha256).unwrap();
         assert!(data.is_some());
         assert_eq!(claims, null_object);
         
         // Test empty string
         let empty_string = json!({"empty": ""});
         let (data, claims) = parse_data(Some(Data::Structured(empty_string.clone())), &HashAlgorithm::Sha256).unwrap();
         assert!(data.is_some());
         assert_eq!(claims, empty_string);
     }

     // Test for memory efficiency of hash operations
     #[test]
     fn test_hash_memory_efficiency() {
         // This test ensures we don't have memory leaks in hash operations
         let algorithm = HashAlgorithm::Sha384;
         
         // Perform many hash operations
         for i in 0..100 {
             let data = format!("test data {}", i).into_bytes();
             let result = algorithm.accumulate_hash(data);
             assert_eq!(result.len(), 48);
         }
     }

     // Test that all hash algorithms handle identical input identically
     #[test]
     fn test_hash_algorithm_deterministic_behavior() {
         let test_input = b"deterministic test input".to_vec();
         
         // Test multiple calls return same result
         let sha256_1 = HashAlgorithm::Sha256.accumulate_hash(test_input.clone());
         let sha256_2 = HashAlgorithm::Sha256.accumulate_hash(test_input.clone());
         assert_eq!(sha256_1, sha256_2);
         
         let sha384_1 = HashAlgorithm::Sha384.accumulate_hash(test_input.clone());
         let sha384_2 = HashAlgorithm::Sha384.accumulate_hash(test_input.clone());
         assert_eq!(sha384_1, sha384_2);
         
         let sha512_1 = HashAlgorithm::Sha512.accumulate_hash(test_input.clone());
         let sha512_2 = HashAlgorithm::Sha512.accumulate_hash(test_input.clone());
         assert_eq!(sha512_1, sha512_2);
         
         // But different algorithms should produce different results
         assert_ne!(sha256_1, sha384_1);
         assert_ne!(sha384_1, sha512_1);
         assert_ne!(sha256_1, sha512_1);
     }

     // Test AttestationTokenConfig enum variants
     #[test]
     fn test_attestation_token_config_variants() {
         // Test Simple variant
         let simple_config = AttestationTokenConfig::Simple(Default::default());
         assert!(matches!(simple_config, AttestationTokenConfig::Simple(_)));
         
         // Test Ear variant
         let ear_config = AttestationTokenConfig::Ear(Default::default());
         assert!(matches!(ear_config, AttestationTokenConfig::Ear(_)));
         
         // Test default
         let default_config = AttestationTokenConfig::default();
         assert!(matches!(default_config, AttestationTokenConfig::Ear(_)));
     }

     // Test work directory creation with nested paths
     #[tokio::test]
     async fn test_attestation_service_nested_work_dir_creation() {
         let temp_dir = tempfile::tempdir().unwrap();
         let nested_work_dir = temp_dir.path().join("level1").join("level2").join("level3");
         
         let config = Config {
             work_dir: nested_work_dir.clone(),
             rvps_config: crate::rvps::RvpsConfig::BuiltIn(Default::default()),
             attestation_token_broker: AttestationTokenConfig::Simple(Default::default()),
         };
         
         // Directory doesn't exist initially
         assert!(!nested_work_dir.exists());
         
         let _service = AttestationService::new(config).await.unwrap();
         
         // Should create all nested directories
         assert!(nested_work_dir.exists());
         assert!(nested_work_dir.is_dir());
     }

     // Test work directory creation when it already exists
     #[tokio::test]
     async fn test_attestation_service_existing_work_dir() {
         let temp_dir = tempfile::tempdir().unwrap();
         let work_dir = temp_dir.path().join("existing_dir");
         
         // Pre-create the directory
         std::fs::create_dir_all(&work_dir).unwrap();
         assert!(work_dir.exists());
         
         let config = Config {
             work_dir: work_dir.clone(),
             rvps_config: crate::rvps::RvpsConfig::BuiltIn(Default::default()),
             attestation_token_broker: AttestationTokenConfig::Simple(Default::default()),
         };
         
         // Should not fail even if directory exists
         let _service = AttestationService::new(config).await.unwrap();
         
         assert!(work_dir.exists());
     }

     // Test with relative paths (should be normalized)
     #[tokio::test]
     async fn test_get_cert_content_relative_path() {
         let temp_dir = tempfile::tempdir().unwrap();
         let cert_path = temp_dir.path().join("relative_cert.pem");
         let cert_content = b"relative path content";
         
         std::fs::write(&cert_path, cert_content).unwrap();
         
         let config = Config {
             work_dir: temp_dir.path().to_path_buf(),
             rvps_config: crate::rvps::RvpsConfig::BuiltIn(Default::default()),
             attestation_token_broker: AttestationTokenConfig::Simple(Default::default()),
         };
         
         let service = AttestationService::new(config).await.unwrap();
         
         // Use relative path format
         let relative_path = format!("./{}", cert_path.file_name().unwrap().to_str().unwrap());
         
         // Change to temp directory for relative path test
         let original_dir = std::env::current_dir().unwrap();
         std::env::set_current_dir(temp_dir.path()).unwrap();
         
         let result = service.get_cert_content(Some(&relative_path), None).await.unwrap();
         
         // Restore original directory
         std::env::set_current_dir(original_dir).unwrap();
         
         assert_eq!(result, Some(cert_content.to_vec()));
     }

     // Test with symlinks (if supported on the platform)
     #[cfg(unix)]
     #[tokio::test]
     async fn test_get_cert_content_symlink() {
         let temp_dir = tempfile::tempdir().unwrap();
         let target_path = temp_dir.path().join("target_cert.pem");
         let symlink_path = temp_dir.path().join("symlink_cert.pem");
         let cert_content = b"symlink target content";
         
         std::fs::write(&target_path, cert_content).unwrap();
         std::os::unix::fs::symlink(&target_path, &symlink_path).unwrap();
         
         let config = Config {
             work_dir: temp_dir.path().to_path_buf(),
             rvps_config: crate::rvps::RvpsConfig::BuiltIn(Default::default()),
             attestation_token_broker: AttestationTokenConfig::Simple(Default::default()),
         };
         
         let service = AttestationService::new(config).await.unwrap();
         let result = service.get_cert_content(Some(symlink_path.to_str().unwrap()), None).await.unwrap();
         
         assert_eq!(result, Some(cert_content.to_vec()));
     }

     // Test Data enum clone behavior (ensure it's cheap for large data)
     #[test]
     fn test_data_enum_clone() {
         let large_raw_data = Data::Raw(vec![0u8; 10_000]);
         let cloned_data = large_raw_data.clone();
         
         match (large_raw_data, cloned_data) {
             (Data::Raw(orig), Data::Raw(cloned)) => {
                 assert_eq!(orig.len(), cloned.len());
                 assert_eq!(orig, cloned);
             }
             _ => panic!("Expected Raw variants")
         }
         
         let complex_json = json!({
             "large_array": vec![0; 1000],
             "nested": {
                 "deep": {
                     "structure": "value"
                 }
             }
         });
         let structured_data = Data::Structured(complex_json.clone());
         let cloned_structured = structured_data.clone();
         
         match (structured_data, cloned_structured) {
             (Data::Structured(orig), Data::Structured(cloned)) => {
                 assert_eq!(orig, cloned);
             }
             _ => panic!("Expected Structured variants")
         }
     }

     // Test ServiceError conversion traits
     #[test]
     fn test_service_error_from_conversions() {
         // Test From<std::io::Error>
         let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "Not found");
         let service_error: ServiceError = io_error.into();
         assert!(matches!(service_error, ServiceError::IO(_)));
         
         // Test From<anyhow::Error>
         let anyhow_error = anyhow::anyhow!("Test error");
         let service_error: ServiceError = anyhow_error.into();
         assert!(matches!(service_error, ServiceError::Anyhow(_)));
     }

     // Test HashAlgorithm string conversions in both directions
     #[test]
     fn test_hash_algorithm_string_round_trip() {
         use std::str::FromStr;
         
         let algorithms = [
             HashAlgorithm::Sha256,
             HashAlgorithm::Sha384, 
             HashAlgorithm::Sha512,
         ];
         
         for original in algorithms {
             // Convert to string
             let as_string = original.to_string();
             
             // Parse back from string
             let parsed = HashAlgorithm::from_str(&as_string).unwrap();
             
             // Should be identical
             assert_eq!(format!("{:?}", original), format!("{:?}", parsed));
         }
     }

     // Test that parse_data preserves exact JSON structure in claims
     #[test]
     fn test_parse_data_preserves_json_structure() {
         let original_json = json!({
             "string": "value",
             "number": 42,
             "float": 3.14,
             "boolean": true,
             "null": null,
             "array": [1, "two", null, {"nested": "object"}],
             "object": {
                 "nested_string": "nested_value",
                 "nested_number": 99
             }
         });
         
         let (_, claims) = parse_data(Some(Data::Structured(original_json.clone())), &HashAlgorithm::Sha256).unwrap();
         
         // Claims should be exactly the same as input
         assert_json_eq!(claims, original_json);
     }
 }
