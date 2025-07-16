// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use serde_json::json;

#[tokio::test]
async fn test_csv_verifier_evaluate_invalid_evidence() {
    let verifier = CsvVerifier::default();
    
    // Create invalid evidence (not valid JSON)
    let evidence = b"invalid json";
    
    // Create expected report data
    let expected_report_data = ReportData::Value(b"test_report_data");
    let expected_init_data_hash = InitDataHash::Value(b"");
    
    // Test evaluation with invalid evidence
    let result = verifier.evaluate(evidence, &expected_report_data, &expected_init_data_hash).await;
    assert!(result.is_err());
}

#[test]
fn test_xor_with_anonce() {
    let mut data = [0u8, 1u8, 2u8, 3u8, 4u8];
    let anonce = 0x12345678u32;
    
    // Test the function doesn't panic
    xor_with_anonce(&mut data, &anonce);
    
    // Test with empty data
    let mut empty_data = [];
    xor_with_anonce(&mut empty_data, &anonce);
}

#[tokio::test]
async fn test_csv_verifier_creation() {
    // Just test that we can create a CSV verifier
    let verifier = CsvVerifier::default();
    assert_eq!(format!("{:?}", verifier), "CsvVerifier");
}