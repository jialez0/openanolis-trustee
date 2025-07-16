// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use reference_value_provider_service::storage::{local_fs, local_json, ReferenceValueStorage, ReferenceValueStorageConfig};
use reference_value_provider_service::ReferenceValue;
use tempfile::TempDir;
use chrono::{TimeZone, Utc};

#[tokio::test]
async fn test_local_fs_storage() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("reference_values");
    
    let config = local_fs::Config {
        file_path: file_path.to_string_lossy().to_string(),
    };
    
    let storage_config = ReferenceValueStorageConfig::LocalFs(config);
    let storage = storage_config.to_storage().unwrap();
    
    // Create a test reference value
    let reference_value = ReferenceValue::new()
        .expect("Failed to create ReferenceValue")
        .set_name("test-reference")
        .set_version("1.0")
        .set_expiration(Utc.with_ymd_and_hms(2025, 12, 31, 23, 59, 59).unwrap())
        .add_hash_value("sha256".to_string(), "test-hash-value".to_string());
    
    // Test setting a reference value
    let result = storage.set("test-ref".to_string(), reference_value.clone()).await.unwrap();
    assert!(result.is_none()); // No previous value
    
    // Test getting the reference value
    let retrieved = storage.get("test-ref").await.unwrap().unwrap();
    assert_eq!(retrieved.name(), reference_value.name());
    assert_eq!(retrieved.version(), reference_value.version());
    
    // Test getting all values
    let values = storage.get_values().await.unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].name(), reference_value.name());
    
    // Test deleting the reference value
    let deleted = storage.delete("test-ref").await.unwrap().unwrap();
    assert_eq!(deleted.name(), reference_value.name());
    
    // Verify it's deleted
    let retrieved = storage.get("test-ref").await.unwrap();
    assert!(retrieved.is_none());
}

#[tokio::test]
async fn test_local_json_storage() {
    let temp_dir = TempDir::new().unwrap();
    let json_file = temp_dir.path().join("reference_values.json");
    
    let config = local_json::Config {
        file_path: json_file.to_string_lossy().to_string(),
    };
    
    let storage_config = ReferenceValueStorageConfig::LocalJson(config);
    let storage = storage_config.to_storage().unwrap();
    
    // Create a test reference value
    let reference_value = ReferenceValue::new()
        .expect("Failed to create ReferenceValue")
        .set_name("test-reference-json")
        .set_version("2.0")
        .set_expiration(Utc.with_ymd_and_hms(2025, 12, 31, 23, 59, 59).unwrap())
        .add_hash_value("sha256".to_string(), "json-hash-value".to_string());
    
    // Test setting a reference value
    let result = storage.set("test-ref-json".to_string(), reference_value.clone()).await;
    // Just check that it doesn't panic
    assert!(result.is_ok());
    
    // Test getting all values
    let values = storage.get_values().await;
    // Just check that it doesn't panic
    assert!(values.is_ok());
}