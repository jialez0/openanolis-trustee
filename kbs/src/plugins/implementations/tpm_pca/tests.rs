// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use actix_web::http::Method;
use openssl::rsa::Rsa;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_parse_duration() {
    // Test valid durations
    assert_eq!(parse_duration("1s").unwrap(), 1);
    assert_eq!(parse_duration("2m").unwrap(), 120);
    assert_eq!(parse_duration("3h").unwrap(), 10800);
    assert_eq!(parse_duration("4d").unwrap(), 345600);
    
    // Test invalid format
    assert!(parse_duration("invalid").is_err());
    assert!(parse_duration("1x").is_err());
    assert!(parse_duration("abc").is_err());
}

#[test]
fn test_tpm_ca_config_try_from() {
    let temp_dir = TempDir::new().unwrap();
    let work_dir = temp_dir.path().to_string_lossy().to_string();
    
    let config = TpmCaConfig {
        signing_key_path: None,
        cert_chain_path: None,
        work_dir: Some(work_dir.clone()),
        tpm_self_signed_ca_config: None,
    };
    
    // Test creating plugin from config
    let plugin = TpmCaPlugin::try_from(config);
    assert!(plugin.is_ok());
    
    let plugin = plugin.unwrap();
    assert_eq!(plugin.work_dir.to_string_lossy(), work_dir);
    
    // Check that key and cert files were created
    assert!(plugin.signing_key_path.exists());
    assert!(plugin.cert_chain_path.exists());
}

#[tokio::test]
async fn test_tpm_ca_plugin_handle_certificate() {
    let temp_dir = TempDir::new().unwrap();
    let work_dir = temp_dir.path().to_string_lossy().to_string();
    
    let config = TpmCaConfig {
        signing_key_path: None,
        cert_chain_path: None,
        work_dir: Some(work_dir),
        tpm_self_signed_ca_config: None,
    };
    
    let plugin = TpmCaPlugin::try_from(config).unwrap();
    
    // Test getting certificate
    let result = plugin.handle(&[], "", "/certificate", &Method::GET).await;
    assert!(result.is_ok());
    
    let cert_data = result.unwrap();
    let cert_str = String::from_utf8(cert_data).unwrap();
    assert!(cert_str.contains("-----BEGIN CERTIFICATE-----"));
}

#[tokio::test]
async fn test_tpm_ca_plugin_handle_invalid_method() {
    let temp_dir = TempDir::new().unwrap();
    let work_dir = temp_dir.path().to_string_lossy().to_string();
    
    let config = TpmCaConfig {
        signing_key_path: None,
        cert_chain_path: None,
        work_dir: Some(work_dir),
        tpm_self_signed_ca_config: None,
    };
    
    let plugin = TpmCaPlugin::try_from(config).unwrap();
    
    // Test with invalid HTTP method
    let result = plugin.handle(&[], "", "/certificate", &Method::POST).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Illegal HTTP method"));
}

#[tokio::test]
async fn test_tpm_ca_plugin_handle_invalid_path() {
    let temp_dir = TempDir::new().unwrap();
    let work_dir = temp_dir.path().to_string_lossy().to_string();
    
    let config = TpmCaConfig {
        signing_key_path: None,
        cert_chain_path: None,
        work_dir: Some(work_dir),
        tpm_self_signed_ca_config: None,
    };
    
    let plugin = TpmCaPlugin::try_from(config).unwrap();
    
    // Test with invalid path
    let result = plugin.handle(&[], "", "/invalid", &Method::GET).await;
    assert!(result.is_err());
}

#[test]
fn test_ak_credential_params_try_from() {
    let query = "name=test&ak_pubkey=test_key";
    let params = AkCredentialParams::try_from(query);
    assert!(params.is_ok());
    
    let params = params.unwrap();
    assert_eq!(params.name, "test");
    assert_eq!(params.ak_pubkey, "test_key");
}

#[test]
fn test_ak_credential_params_try_from_invalid() {
    let query = "invalid_query";
    let params = AkCredentialParams::try_from(query);
    assert!(params.is_err());
}