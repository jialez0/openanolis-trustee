// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! reference value for RVPS

use anyhow::{anyhow, Result};
use chrono::{DateTime, NaiveDateTime, Timelike, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use std::time::SystemTime;

/// Default version of ReferenceValue
pub const REFERENCE_VALUE_VERSION: &str = "0.1.0";

/// A HashValuePair stores a hash algorithm name
/// and relative artifact's hash value due to
/// the algorithm.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HashValuePair {
    alg: String,
    value: String,
}

impl HashValuePair {
    pub fn new(alg: String, value: String) -> Self {
        Self { alg, value }
    }

    pub fn alg(&self) -> &String {
        &self.alg
    }

    pub fn value(&self) -> &String {
        &self.value
    }
}

/// Helper to deserialize an expired time
fn primitive_date_time_from_str<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<DateTime<Utc>, D::Error> {
    let s = <Option<&str>>::deserialize(d)?
        .ok_or_else(|| serde::de::Error::invalid_length(0, &"<TIME>"))?;

    let ndt = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ")
        .map_err(|err| serde::de::Error::custom::<String>(err.to_string()))?;

    Ok(DateTime::from_naive_utc_and_offset(ndt, Utc))
}

/// Define Reference Value stored inside RVPS.
/// This Reference Value is not the same as that in IETF's RATS.
/// Here, ReferenceValue is stored inside RVPS. Its format MAY be modified.
/// * `version`: version of the reference value format.
/// * `name`: name of the artifact related to this reference value.
/// * `expiration`: Time after which refrence valid is invalid
/// * `hash_value`: A set of key-value pairs, each indicates a hash
///   algorithm and its relative hash value for the artifact.
///   The actual struct deliver from RVPS to AS is
///   [`TrustedDigest`], whose simple structure is easy
///   for AS to handle.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ReferenceValue {
    #[serde(default = "default_version")]
    pub version: String,
    pub name: String,
    #[serde(deserialize_with = "primitive_date_time_from_str")]
    pub expiration: DateTime<Utc>,
    #[serde(rename = "hash-value")]
    pub hash_value: Vec<HashValuePair>,
}

/// Set the default version for ReferenceValue
fn default_version() -> String {
    REFERENCE_VALUE_VERSION.into()
}

impl ReferenceValue {
    /// Create a new `ReferenceValue`, the `expiration`
    /// field's nanosecond will be set to 0. This avoid
    /// a rare bug that when the nanosecond of the time
    /// is not 0, the test case will fail.
    pub fn new() -> Result<Self> {
        Ok(ReferenceValue {
            version: REFERENCE_VALUE_VERSION.into(),
            name: String::new(),
            expiration: Utc::now()
                .with_nanosecond(0)
                .ok_or_else(|| anyhow!("set nanosecond failed."))?,
            hash_value: Vec::new(),
        })
    }

    /// Set version of the ReferenceValue.
    pub fn set_version(mut self, version: &str) -> Self {
        self.version = version.into();
        self
    }

    /// Get version of the ReferenceValue.
    pub fn version(&self) -> &String {
        &self.version
    }

    /// Set expired time of the ReferenceValue.
    pub fn set_expiration(mut self, expiration: DateTime<Utc>) -> Self {
        self.expiration = expiration
            .with_nanosecond(0)
            .expect("Set nanosecond failed.");
        self
    }

    /// Check whether reference value is expired
    pub fn expired(&self) -> bool {
        let now: DateTime<Utc> = DateTime::from(SystemTime::now());

        now > self.expiration
    }

    /// Set hash value of the ReferenceValue.
    pub fn add_hash_value(mut self, alg: String, value: String) -> Self {
        self.hash_value.push(HashValuePair::new(alg, value));
        self
    }

    /// Get hash value of the ReferenceValue.
    pub fn hash_values(&self) -> &Vec<HashValuePair> {
        &self.hash_value
    }

    /// Set artifact name for Reference Value
    pub fn set_name(mut self, name: &str) -> Self {
        self.name = name.into();
        self
    }

    /// Get artifact name of the ReferenceValue.
    pub fn name(&self) -> &String {
        &self.name
    }
}

/// Trusted Digest is what RVPS actually delivered to
/// AS, it will include:
/// * `name`: The name of the artifact, e.g., `linux-1.1.1`
/// * `hash_values`: digests that have been verified and can
///   be trusted, so we can refer them as `trusted digests`.
#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq, Eq)]
pub struct TrustedDigest {
    /// The resource name.
    pub name: String,
    /// The reference hash values, base64 coded.
    pub hash_values: Vec<String>,
}

#[cfg(test)]
mod test {
    use chrono::{TimeZone, Utc, Timelike, Datelike};
    use serde_json::json;

    use super::{ReferenceValue, HashValuePair, TrustedDigest, default_version, REFERENCE_VALUE_VERSION};

    #[test]
    fn reference_value_serialize() {
        let rv = ReferenceValue::new()
            .expect("create ReferenceValue failed.")
            .set_version("1.0.0")
            .set_name("artifact")
            .set_expiration(Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap())
            .add_hash_value("sha512".into(), "123".into());

        assert_eq!(rv.version(), "1.0.0");

        let rv_json = json!({
            "expiration": "1970-01-01T00:00:00Z",
            "name": "artifact",
            "version": "1.0.0",
            "hash-value": [{
                "alg": "sha512",
                "value": "123"
            }]
        });

        let serialized_rf = serde_json::to_value(&rv).unwrap();
        assert_eq!(serialized_rf, rv_json);
    }

    #[test]
    fn reference_value_deserialize() {
        let rv = ReferenceValue::new()
            .expect("create ReferenceValue failed.")
            .set_version("1.0.0")
            .set_name("artifact")
            .set_expiration(Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap())
            .add_hash_value("sha512".into(), "123".into());

        assert_eq!(rv.version(), "1.0.0");
        let rv_json = r#"{
            "expiration": "1970-01-01T00:00:00Z",
            "name": "artifact",
            "version": "1.0.0",
            "hash-value": [{
                "alg": "sha512",
                "value": "123"
            }]
        }"#;
        let deserialized_rf: ReferenceValue = serde_json::from_str(&rv_json).unwrap();
        assert_eq!(deserialized_rf, rv);
    }

    // Test HashValuePair struct
    #[test]
    fn hash_value_pair_creation() {
        let alg = "sha256".to_string();
        let value = "abcdef123456".to_string();
        let pair = HashValuePair::new(alg.clone(), value.clone());
        
        assert_eq!(pair.alg(), &alg);
        assert_eq!(pair.value(), &value);
    }

    #[test]
    fn hash_value_pair_serialization() {
        let pair = HashValuePair::new("sha256".to_string(), "hash123".to_string());
        let serialized = serde_json::to_value(&pair).unwrap();
        
        let expected = json!({
            "alg": "sha256",
            "value": "hash123"
        });
        
        assert_eq!(serialized, expected);
    }

    #[test]
    fn hash_value_pair_deserialization() {
        let json_str = r#"{"alg": "sha384", "value": "fedcba654321"}"#;
        let pair: HashValuePair = serde_json::from_str(json_str).unwrap();
        
        assert_eq!(pair.alg(), "sha384");
        assert_eq!(pair.value(), "fedcba654321");
    }

    #[test]
    fn hash_value_pair_equality() {
        let pair1 = HashValuePair::new("md5".to_string(), "hash1".to_string());
        let pair2 = HashValuePair::new("md5".to_string(), "hash1".to_string());
        let pair3 = HashValuePair::new("sha1".to_string(), "hash1".to_string());
        
        assert_eq!(pair1, pair2);
        assert_ne!(pair1, pair3);
    }

    // Test default_version function
    #[test]
    fn test_default_version() {
        assert_eq!(default_version(), REFERENCE_VALUE_VERSION);
        assert_eq!(default_version(), "0.1.0");
    }

    // Test ReferenceValue creation and methods
    #[test]
    fn reference_value_new() {
        let rv = ReferenceValue::new().expect("Failed to create ReferenceValue");
        
        assert_eq!(rv.version(), REFERENCE_VALUE_VERSION);
        assert_eq!(rv.name(), "");
        assert!(rv.hash_values().is_empty());
        // Check that nanoseconds are set to 0
        assert_eq!(rv.expiration.nanosecond(), 0);
    }

    #[test]
    fn reference_value_set_version() {
        let rv = ReferenceValue::new()
            .unwrap()
            .set_version("2.0.0");
        
        assert_eq!(rv.version(), "2.0.0");
    }

    #[test]
    fn reference_value_set_name() {
        let rv = ReferenceValue::new()
            .unwrap()
            .set_name("test-artifact");
        
        assert_eq!(rv.name(), "test-artifact");
    }

    #[test]
    fn reference_value_set_expiration() {
        let test_time = Utc.with_ymd_and_hms(2025, 6, 15, 12, 30, 45).unwrap();
        let rv = ReferenceValue::new()
            .unwrap()
            .set_expiration(test_time);
        
        // Should set nanoseconds to 0
        let expected_time = test_time.with_nanosecond(0).unwrap();
        assert_eq!(rv.expiration, expected_time);
        assert_eq!(rv.expiration.nanosecond(), 0);
    }

    #[test]
    fn reference_value_add_hash_value() {
        let rv = ReferenceValue::new()
            .unwrap()
            .add_hash_value("sha256".to_string(), "hash1".to_string())
            .add_hash_value("sha512".to_string(), "hash2".to_string());
        
        assert_eq!(rv.hash_values().len(), 2);
        assert_eq!(rv.hash_values()[0].alg(), "sha256");
        assert_eq!(rv.hash_values()[0].value(), "hash1");
        assert_eq!(rv.hash_values()[1].alg(), "sha512");
        assert_eq!(rv.hash_values()[1].value(), "hash2");
    }

    #[test]
    fn reference_value_expired_false() {
        let future_time = Utc::now() + chrono::Duration::days(1);
        let rv = ReferenceValue::new()
            .unwrap()
            .set_expiration(future_time);
        
        assert!(!rv.expired());
    }

    #[test]
    fn reference_value_expired_true() {
        let past_time = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        let rv = ReferenceValue::new()
            .unwrap()
            .set_expiration(past_time);
        
        assert!(rv.expired());
    }

    #[test]
    fn reference_value_method_chaining() {
        let rv = ReferenceValue::new()
            .unwrap()
            .set_version("3.0.0")
            .set_name("chained-artifact")
            .set_expiration(Utc.with_ymd_and_hms(2030, 12, 31, 23, 59, 59).unwrap())
            .add_hash_value("md5".to_string(), "md5hash".to_string())
            .add_hash_value("sha1".to_string(), "sha1hash".to_string());
        
        assert_eq!(rv.version(), "3.0.0");
        assert_eq!(rv.name(), "chained-artifact");
        assert_eq!(rv.hash_values().len(), 2);
        assert_eq!(rv.expiration.nanosecond(), 0);
    }

    // Test TrustedDigest
    #[test]
    fn trusted_digest_creation() {
        let digest = TrustedDigest {
            name: "test-binary".to_string(),
            hash_values: vec!["hash1".to_string(), "hash2".to_string()],
        };
        
        assert_eq!(digest.name, "test-binary");
        assert_eq!(digest.hash_values.len(), 2);
        assert_eq!(digest.hash_values[0], "hash1");
        assert_eq!(digest.hash_values[1], "hash2");
    }

    #[test]
    fn trusted_digest_default() {
        let digest = TrustedDigest::default();
        
        assert_eq!(digest.name, "");
        assert!(digest.hash_values.is_empty());
    }

    #[test]
    fn trusted_digest_serialization() {
        let digest = TrustedDigest {
            name: "artifact".to_string(),
            hash_values: vec!["hash1".to_string(), "hash2".to_string()],
        };
        
        let serialized = serde_json::to_value(&digest).unwrap();
        let expected = json!({
            "name": "artifact",
            "hash_values": ["hash1", "hash2"]
        });
        
        assert_eq!(serialized, expected);
    }

    #[test]
    fn trusted_digest_deserialization() {
        let json_str = r#"{"name": "test-app", "hash_values": ["abc123", "def456"]}"#;
        let digest: TrustedDigest = serde_json::from_str(json_str).unwrap();
        
        assert_eq!(digest.name, "test-app");
        assert_eq!(digest.hash_values.len(), 2);
        assert_eq!(digest.hash_values[0], "abc123");
        assert_eq!(digest.hash_values[1], "def456");
    }

    #[test]
    fn trusted_digest_equality() {
        let digest1 = TrustedDigest {
            name: "app".to_string(),
            hash_values: vec!["hash1".to_string()],
        };
        let digest2 = TrustedDigest {
            name: "app".to_string(),
            hash_values: vec!["hash1".to_string()],
        };
        let digest3 = TrustedDigest {
            name: "app2".to_string(),
            hash_values: vec!["hash1".to_string()],
        };
        
        assert_eq!(digest1, digest2);
        assert_ne!(digest1, digest3);
    }

    // Test deserialization with default version
    #[test]
    fn reference_value_deserialize_without_version() {
        let rv_json = r#"{
            "expiration": "2025-12-31T23:59:59Z",
            "name": "no-version-artifact",
            "hash-value": [{
                "alg": "sha256",
                "value": "noversion123"
            }]
        }"#;
        let rv: ReferenceValue = serde_json::from_str(&rv_json).unwrap();
        
        // Should use default version
        assert_eq!(rv.version(), REFERENCE_VALUE_VERSION);
        assert_eq!(rv.name(), "no-version-artifact");
    }

    // Test primitive_date_time_from_str function indirectly through deserialization
    #[test]
    fn reference_value_deserialize_various_time_formats() {
        let rv_json = r#"{
            "expiration": "2025-01-15T10:30:45Z",
            "name": "time-test",
            "version": "1.0.0",
            "hash-value": []
        }"#;
        let rv: ReferenceValue = serde_json::from_str(&rv_json).unwrap();
        
        let expected_time = Utc.with_ymd_and_hms(2025, 1, 15, 10, 30, 45).unwrap();
        assert_eq!(rv.expiration, expected_time);
    }

    // Test error cases for deserialization
    #[test]
    fn reference_value_deserialize_invalid_time() {
        let rv_json = r#"{
            "expiration": "invalid-time",
            "name": "error-test",
            "version": "1.0.0",
            "hash-value": []
        }"#;
        
        let result: Result<ReferenceValue, _> = serde_json::from_str(&rv_json);
        assert!(result.is_err());
    }

    #[test]
    fn reference_value_deserialize_missing_expiration() {
        let rv_json = r#"{
            "name": "missing-exp",
            "version": "1.0.0",
            "hash-value": []
        }"#;
        
        let result: Result<ReferenceValue, _> = serde_json::from_str(&rv_json);
        assert!(result.is_err());
    }

    // Test complex scenarios
    #[test]
    fn reference_value_complex_scenario() {
        let now = Utc::now();
        let future = now + chrono::Duration::hours(1);
        let past = now - chrono::Duration::hours(1);
        
        // Test not expired
        let rv_future = ReferenceValue::new()
            .unwrap()
            .set_expiration(future)
            .set_name("future-artifact")
            .add_hash_value("sha256".to_string(), "future_hash".to_string());
        
        assert!(!rv_future.expired());
        assert_eq!(rv_future.name(), "future-artifact");
        assert_eq!(rv_future.hash_values().len(), 1);
        
        // Test expired
        let rv_past = ReferenceValue::new()
            .unwrap()
            .set_expiration(past);
        
        assert!(rv_past.expired());
    }

    // Test all struct derive traits (Clone, Debug, PartialEq, Eq)
    #[test]
    fn hash_value_pair_traits() {
        let pair = HashValuePair::new("sha256".to_string(), "hash".to_string());
        
        // Test Clone
        let cloned = pair.clone();
        assert_eq!(pair, cloned);
        
        // Test Debug
        let debug_str = format!("{:?}", pair);
        assert!(debug_str.contains("sha256"));
        assert!(debug_str.contains("hash"));
    }

    #[test]
    fn reference_value_traits() {
        let rv = ReferenceValue::new()
            .unwrap()
            .set_name("trait-test")
            .add_hash_value("sha256".to_string(), "test_hash".to_string());
        
        // Test Clone
        let cloned = rv.clone();
        assert_eq!(rv, cloned);
        
        // Test Debug
        let debug_str = format!("{:?}", rv);
        assert!(debug_str.contains("trait-test"));
    }

    #[test]
    fn trusted_digest_traits() {
        let digest = TrustedDigest {
            name: "test".to_string(),
            hash_values: vec!["hash".to_string()],
        };
        
        // Test Clone
        let cloned = digest.clone();
        assert_eq!(digest, cloned);
        
        // Test Debug
        let debug_str = format!("{:?}", digest);
        assert!(debug_str.contains("test"));
    }

    // Test edge cases
    #[test]
    fn reference_value_empty_values() {
        let rv = ReferenceValue::new()
            .unwrap()
            .set_name("")
            .set_version("");
        
        assert_eq!(rv.name(), "");
        assert_eq!(rv.version(), "");
        assert!(rv.hash_values().is_empty());
    }

    #[test]
    fn reference_value_multiple_same_hash_algorithms() {
        let rv = ReferenceValue::new()
            .unwrap()
            .add_hash_value("sha256".to_string(), "hash1".to_string())
            .add_hash_value("sha256".to_string(), "hash2".to_string());
        
        assert_eq!(rv.hash_values().len(), 2);
        assert_eq!(rv.hash_values()[0].alg(), "sha256");
        assert_eq!(rv.hash_values()[1].alg(), "sha256");
        assert_ne!(rv.hash_values()[0].value(), rv.hash_values()[1].value());
    }

    // Test boundary conditions for time
    #[test]
    fn reference_value_time_boundary() {
        // Test with minimum time
        let min_time = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap();
        let rv_min = ReferenceValue::new()
            .unwrap()
            .set_expiration(min_time);
        
        assert_eq!(rv_min.expiration.year(), 1970);
        assert!(rv_min.expired());
        
        // Test with far future time
        let far_future = Utc.with_ymd_and_hms(2099, 12, 31, 23, 59, 59).unwrap();
        let rv_future = ReferenceValue::new()
            .unwrap()
            .set_expiration(far_future);
        
        assert_eq!(rv_future.expiration.year(), 2099);
        assert!(!rv_future.expired());
    }

    // Test serialization/deserialization roundtrip
    #[test]
    fn reference_value_roundtrip() {
        let original = ReferenceValue::new()
            .unwrap()
            .set_version("2.1.0")
            .set_name("roundtrip-test")
            .set_expiration(Utc.with_ymd_and_hms(2025, 6, 15, 14, 30, 0).unwrap())
            .add_hash_value("sha256".to_string(), "abc123".to_string())
            .add_hash_value("sha512".to_string(), "def456".to_string());
        
        // Serialize
        let json_str = serde_json::to_string(&original).unwrap();
        
        // Deserialize
        let deserialized: ReferenceValue = serde_json::from_str(&json_str).unwrap();
        
        // Should be equal
        assert_eq!(original, deserialized);
    }

    #[test]
    fn trusted_digest_roundtrip() {
        let original = TrustedDigest {
            name: "roundtrip-digest".to_string(),
            hash_values: vec![
                "hash1".to_string(),
                "hash2".to_string(),
                "hash3".to_string(),
            ],
        };
        
        // Serialize
        let json_str = serde_json::to_string(&original).unwrap();
        
        // Deserialize
        let deserialized: TrustedDigest = serde_json::from_str(&json_str).unwrap();
        
        // Should be equal
        assert_eq!(original, deserialized);
    }
}
