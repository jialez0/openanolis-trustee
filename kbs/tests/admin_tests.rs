// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use kbs::admin::{Admin, config::AdminConfig};
use std::path::PathBuf;
use tempfile::TempDir;

#[actix_web::test]
async fn test_admin_insecure_mode() {
    let config = AdminConfig {
        insecure_api: true,
        auth_public_key: None,
    };
    
    // Should succeed in insecure mode
    assert!(Admin::try_from(config).is_ok());
}

#[actix_web::test]
async fn test_admin_secure_mode_no_key() {
    let config = AdminConfig {
        insecure_api: false,
        auth_public_key: None,
    };
    
    // Should fail when secure mode is enabled but no public key is provided
    assert!(Admin::try_from(config).is_err());
}

#[actix_web::test]
async fn test_admin_creation() {
    // Create a temporary directory for our test key
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("public_key.pem");
    
    // Create a valid test PEM file
    let public_key_pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAduMuZGMbFS0EnHFKE0DvfScp02rJ974xBFsBQ6kX7dc=\n-----END PUBLIC KEY-----\n";
    std::fs::write(&key_path, public_key_pem).unwrap();
    
    let config = AdminConfig {
        insecure_api: false,
        auth_public_key: Some(PathBuf::from(key_path.to_str().unwrap())),
    };
    
    // Should succeed when provided with a valid key path
    assert!(Admin::try_from(config).is_ok());
}