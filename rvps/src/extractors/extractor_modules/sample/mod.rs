// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This is a very simple format of provenance

use std::collections::HashMap;

use anyhow::*;
use base64::Engine;
use chrono::{Months, Timelike, Utc};
use log::warn;
use serde::{Deserialize, Serialize};

use crate::{
    reference_value::{HashValuePair, REFERENCE_VALUE_VERSION},
    ReferenceValue,
};

use super::Extractor;

#[derive(Serialize, Deserialize)]
pub struct Provenance {
    #[serde(flatten)]
    rvs: HashMap<String, Vec<String>>,
}

#[derive(Default)]
pub struct SampleExtractor;

/// Default reference value hash algorithm
const DEFAULT_ALG: &str = "sha384";

/// The reference value will be expired in the default time (months)
const MONTHS_BEFORE_EXPIRATION: u32 = 12;

impl Extractor for SampleExtractor {
    fn verify_and_extract(&self, provenance_base64: &str) -> Result<Vec<ReferenceValue>> {
        let provenance = base64::engine::general_purpose::STANDARD
            .decode(provenance_base64)
            .context("base64 decode")?;
        let payload: Provenance =
            serde_json::from_slice(&provenance).context("deseralize sample provenance")?;

        let res = payload
            .rvs
            .iter()
            .filter_map(|(name, rvalues)| {
                let rvs = rvalues
                    .iter()
                    .map(|rv| HashValuePair::new(DEFAULT_ALG.into(), rv.to_string()))
                    .collect();

                let time = Utc::now()
                    .with_nanosecond(0)
                    .and_then(|t| t.checked_add_months(Months::new(MONTHS_BEFORE_EXPIRATION)));

                match time {
                    Some(expiration) => Some(ReferenceValue {
                        version: REFERENCE_VALUE_VERSION.into(),
                        name: name.to_string(),
                        expiration,
                        hash_value: rvs,
                    }),
                    None => {
                        warn!("Expired time calculated overflowed for reference value of {name}.");
                        None
                    }
                }
            })
            .collect();

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use chrono::{Duration, Utc};
    use serde_json::json;
    use std::collections::HashMap;

    // 测试 Provenance 结构体的序列化和反序列化
    #[test]
    fn test_provenance_serialization() {
        let mut rvs = HashMap::new();
        rvs.insert("app1".to_string(), vec!["hash1".to_string(), "hash2".to_string()]);
        rvs.insert("app2".to_string(), vec!["hash3".to_string()]);
        
        let provenance = Provenance { rvs };
        
        // 测试序列化
        let serialized = serde_json::to_value(&provenance).unwrap();
        let expected = json!({
            "app1": ["hash1", "hash2"],
            "app2": ["hash3"]
        });
        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_provenance_deserialization() {
        let json_data = json!({
            "app1": ["hash1", "hash2"],
            "app2": ["hash3"]
        });
        
        let provenance: Provenance = serde_json::from_value(json_data).unwrap();
        
        assert_eq!(provenance.rvs.len(), 2);
        assert!(provenance.rvs.contains_key("app1"));
        assert!(provenance.rvs.contains_key("app2"));
        assert_eq!(provenance.rvs["app1"], vec!["hash1", "hash2"]);
        assert_eq!(provenance.rvs["app2"], vec!["hash3"]);
    }

    #[test]
    fn test_provenance_empty() {
        let empty_json = json!({});
        let provenance: Provenance = serde_json::from_value(empty_json).unwrap();
        assert!(provenance.rvs.is_empty());
    }

    // 测试 SampleExtractor 结构体
    #[test]
    fn test_sample_extractor_default() {
        let extractor = SampleExtractor::default();
        // SampleExtractor 是一个空结构体，主要测试其实例化
        assert_eq!(std::mem::size_of_val(&extractor), 0);
    }

    #[test]
    fn test_sample_extractor_new() {
        let extractor = SampleExtractor;
        // 验证可以创建新实例
        assert_eq!(std::mem::size_of_val(&extractor), 0);
    }

    // 测试常量值
    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_ALG, "sha384");
        assert_eq!(MONTHS_BEFORE_EXPIRATION, 12);
    }

    // 测试 verify_and_extract 方法的成功路径
    #[test]
    fn test_verify_and_extract_success() {
        let extractor = SampleExtractor::default();
        
        // 准备测试数据
        let test_data = json!({
            "app1": ["hash1", "hash2"],
            "app2": ["hash3"]
        });
        
        let json_string = test_data.to_string();
        let base64_payload = STANDARD.encode(&json_string);
        
        // 执行测试
        let result = extractor.verify_and_extract(&base64_payload).unwrap();
        
        // 验证结果
        assert_eq!(result.len(), 2);
        
        // 验证第一个 ReferenceValue
        let rv1 = result.iter().find(|rv| rv.name == "app1").unwrap();
        assert_eq!(rv1.version, REFERENCE_VALUE_VERSION);
        assert_eq!(rv1.name, "app1");
        assert_eq!(rv1.hash_value.len(), 2);
        assert_eq!(rv1.hash_value[0].alg(), DEFAULT_ALG);
        assert_eq!(rv1.hash_value[0].value(), "hash1");
        assert_eq!(rv1.hash_value[1].alg(), DEFAULT_ALG);
        assert_eq!(rv1.hash_value[1].value(), "hash2");
        
        // 验证第二个 ReferenceValue
        let rv2 = result.iter().find(|rv| rv.name == "app2").unwrap();
        assert_eq!(rv2.version, REFERENCE_VALUE_VERSION);
        assert_eq!(rv2.name, "app2");
        assert_eq!(rv2.hash_value.len(), 1);
        assert_eq!(rv2.hash_value[0].alg(), DEFAULT_ALG);
        assert_eq!(rv2.hash_value[0].value(), "hash3");
        
        // 验证过期时间设置正确（应该是12个月后）
        let now = Utc::now().with_nanosecond(0).unwrap();
        let expected_expiration = now.checked_add_months(Months::new(MONTHS_BEFORE_EXPIRATION)).unwrap();
        
        // 允许一定的时间误差（比如1分钟）
        let time_diff = (rv1.expiration - expected_expiration).abs();
        assert!(time_diff < Duration::minutes(1));
        
        let time_diff = (rv2.expiration - expected_expiration).abs();
        assert!(time_diff < Duration::minutes(1));
    }

    #[test]
    fn test_verify_and_extract_single_app() {
        let extractor = SampleExtractor::default();
        
        let test_data = json!({
            "single_app": ["single_hash"]
        });
        
        let json_string = test_data.to_string();
        let base64_payload = STANDARD.encode(&json_string);
        
        let result = extractor.verify_and_extract(&base64_payload).unwrap();
        
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "single_app");
        assert_eq!(result[0].hash_value.len(), 1);
        assert_eq!(result[0].hash_value[0].value(), "single_hash");
    }

    #[test]
    fn test_verify_and_extract_empty_hash_values() {
        let extractor = SampleExtractor::default();
        
        let test_data = json!({
            "app_with_empty_hashes": []
        });
        
        let json_string = test_data.to_string();
        let base64_payload = STANDARD.encode(&json_string);
        
        let result = extractor.verify_and_extract(&base64_payload).unwrap();
        
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "app_with_empty_hashes");
        assert!(result[0].hash_value.is_empty());
    }

    #[test]
    fn test_verify_and_extract_empty_provenance() {
        let extractor = SampleExtractor::default();
        
        let test_data = json!({});
        let json_string = test_data.to_string();
        let base64_payload = STANDARD.encode(&json_string);
        
        let result = extractor.verify_and_extract(&base64_payload).unwrap();
        assert!(result.is_empty());
    }

    // 测试错误路径
    #[test]
    fn test_verify_and_extract_invalid_base64() {
        let extractor = SampleExtractor::default();
        
        // 无效的 base64 字符串
        let invalid_base64 = "这不是有效的base64!@#$%";
        
        let result = extractor.verify_and_extract(invalid_base64);
        assert!(result.is_err());
        
        let error_msg = format!("{}", result.err().unwrap());
        assert!(error_msg.contains("base64 decode"));
    }

    #[test]
    fn test_verify_and_extract_invalid_json() {
        let extractor = SampleExtractor::default();
        
        // 无效的 JSON 数据
        let invalid_json = "这不是有效的JSON数据";
        let base64_payload = STANDARD.encode(invalid_json);
        
        let result = extractor.verify_and_extract(&base64_payload);
        assert!(result.is_err());
        
        let error_msg = format!("{}", result.err().unwrap());
        assert!(error_msg.contains("deseralize sample provenance"));
    }

    #[test]
    fn test_verify_and_extract_malformed_json_structure() {
        let extractor = SampleExtractor::default();
        
        // JSON 格式正确但结构不符合 Provenance 预期
        let malformed_data = json!({
            "wrong_field": "wrong_value"
        });
        
        let json_string = malformed_data.to_string();
        let base64_payload = STANDARD.encode(&json_string);
        
        // 这应该失败，因为 "wrong_value" 不是数组类型，无法反序列化为 Vec<String>
        let result = extractor.verify_and_extract(&base64_payload);
        assert!(result.is_err());
        
        let error_msg = format!("{}", result.err().unwrap());
        assert!(error_msg.contains("deseralize sample provenance"));
    }

    // 测试边界条件
    #[test]
    fn test_verify_and_extract_very_long_names_and_hashes() {
        let extractor = SampleExtractor::default();
        
        let long_name = "a".repeat(1000);
        let long_hash = "b".repeat(1000);
        
        let mut test_data = HashMap::new();
        test_data.insert(long_name.clone(), vec![long_hash.clone()]);
        
        let json_data = serde_json::to_value(&test_data).unwrap();
        let json_string = json_data.to_string();
        let base64_payload = STANDARD.encode(&json_string);
        
        let result = extractor.verify_and_extract(&base64_payload).unwrap();
        
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, long_name);
        assert_eq!(result[0].hash_value[0].value(), &long_hash);
    }

    #[test]
    fn test_verify_and_extract_special_characters() {
        let extractor = SampleExtractor::default();
        
        let special_name = "应用程序-测试_with特殊字符!@#$%^&*()";
        let special_hash = "哈希值-with-中文-and-symbols-123!@#";
        
        let test_data = json!({
            special_name: [special_hash]
        });
        
        let json_string = test_data.to_string();
        let base64_payload = STANDARD.encode(&json_string);
        
        let result = extractor.verify_and_extract(&base64_payload).unwrap();
        
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, special_name);
        assert_eq!(result[0].hash_value[0].value(), special_hash);
    }

    #[test]
    fn test_verify_and_extract_many_apps() {
        let extractor = SampleExtractor::default();
        
        let mut test_data = HashMap::new();
        for i in 0..100 {
            let app_name = format!("app_{}", i);
            let hash_values = vec![
                format!("hash_{}_1", i),
                format!("hash_{}_2", i),
            ];
            test_data.insert(app_name, hash_values);
        }
        
        let json_data = serde_json::to_value(&test_data).unwrap();
        let json_string = json_data.to_string();
        let base64_payload = STANDARD.encode(&json_string);
        
        let result = extractor.verify_and_extract(&base64_payload).unwrap();
        
        assert_eq!(result.len(), 100);
        
        // 验证每个应用都被正确处理
        for i in 0..100 {
            let app_name = format!("app_{}", i);
            let rv = result.iter().find(|rv| rv.name == app_name).unwrap();
            assert_eq!(rv.hash_value.len(), 2);
            assert_eq!(rv.hash_value[0].value(), &format!("hash_{}_1", i));
            assert_eq!(rv.hash_value[1].value(), &format!("hash_{}_2", i));
        }
    }

    // 测试时间溢出场景（模拟时间溢出情况比较困难，但我们可以测试相关逻辑）
    #[test]
    fn test_verify_and_extract_expiration_time_setting() {
        let extractor = SampleExtractor::default();
        
        let test_data = json!({
            "test_app": ["test_hash"]
        });
        
        let json_string = test_data.to_string();
        let base64_payload = STANDARD.encode(&json_string);
        
        let result = extractor.verify_and_extract(&base64_payload).unwrap();
        
        assert_eq!(result.len(), 1);
        let rv = &result[0];
        
        // 验证过期时间是未来的时间
        assert!(rv.expiration > Utc::now());
        
        // 验证纳秒被设置为0
        assert_eq!(rv.expiration.nanosecond(), 0);
        
        // 验证过期时间大约是12个月后（允许一些误差）
        let now = Utc::now();
        let expected_min = now + Duration::days(360); // 约12个月
        let expected_max = now + Duration::days(370); // 约12个月加一些缓冲
        
        assert!(rv.expiration >= expected_min);
        assert!(rv.expiration <= expected_max);
    }

    // 测试 ReferenceValue 字段的正确性
    #[test]
    fn test_reference_value_fields() {
        let extractor = SampleExtractor::default();
        
        let test_data = json!({
            "test_app": ["hash1", "hash2", "hash3"]
        });
        
        let json_string = test_data.to_string();
        let base64_payload = STANDARD.encode(&json_string);
        
        let result = extractor.verify_and_extract(&base64_payload).unwrap();
        
        assert_eq!(result.len(), 1);
        let rv = &result[0];
        
        // 验证版本字段
        assert_eq!(rv.version, REFERENCE_VALUE_VERSION);
        
        // 验证名称字段
        assert_eq!(rv.name, "test_app");
        
        // 验证哈希值字段
        assert_eq!(rv.hash_value.len(), 3);
        for (i, hash_pair) in rv.hash_value.iter().enumerate() {
            assert_eq!(hash_pair.alg(), DEFAULT_ALG);
            assert_eq!(hash_pair.value(), &format!("hash{}", i + 1));
        }
        
        // 验证过期时间字段（应该是未来的时间）
        assert!(rv.expiration > Utc::now());
    }

    // 测试混合场景
    #[test]
    fn test_verify_and_extract_mixed_scenarios() {
        let extractor = SampleExtractor::default();
        
        let test_data = json!({
            "app_with_one_hash": ["single_hash"],
            "app_with_multiple_hashes": ["hash1", "hash2", "hash3"],
            "app_with_empty_hashes": [],
            "app_with_long_name_very_very_very_long": ["hash_for_long_name"]
        });
        
        let json_string = test_data.to_string();
        let base64_payload = STANDARD.encode(&json_string);
        
        let result = extractor.verify_and_extract(&base64_payload).unwrap();
        
        assert_eq!(result.len(), 4);
        
        // 验证每个应用的结果
        for rv in &result {
            assert_eq!(rv.version, REFERENCE_VALUE_VERSION);
            assert!(rv.expiration > Utc::now());
            
            for hash_pair in &rv.hash_value {
                assert_eq!(hash_pair.alg(), DEFAULT_ALG);
            }
        }
        
        // 验证特定应用
        let single_hash_app = result.iter().find(|rv| rv.name == "app_with_one_hash").unwrap();
        assert_eq!(single_hash_app.hash_value.len(), 1);
        
        let multiple_hash_app = result.iter().find(|rv| rv.name == "app_with_multiple_hashes").unwrap();
        assert_eq!(multiple_hash_app.hash_value.len(), 3);
        
        let empty_hash_app = result.iter().find(|rv| rv.name == "app_with_empty_hashes").unwrap();
        assert_eq!(empty_hash_app.hash_value.len(), 0);
    }

    // 测试极端的 base64 编码情况
    #[test]
    fn test_verify_and_extract_edge_base64_cases() {
        let extractor = SampleExtractor::default();
        
        // 测试空的 base64 字符串
        let empty_json = "{}";
        let empty_base64 = STANDARD.encode(empty_json);
        let result = extractor.verify_and_extract(&empty_base64).unwrap();
        assert!(result.is_empty());
        
        // 测试只有空白字符的 JSON
        let whitespace_json = "  {  }  ";
        let whitespace_base64 = STANDARD.encode(whitespace_json);
        let result = extractor.verify_and_extract(&whitespace_base64).unwrap();
        assert!(result.is_empty());
    }

    // 测试所有可能的错误路径以确保完整覆盖
    #[test]
    fn test_all_error_contexts() {
        let extractor = SampleExtractor::default();
        
        // 测试 base64 解码错误
        let result = extractor.verify_and_extract("无效base64");
        assert!(result.is_err());
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(err_str.contains("base64 decode"));
        
        // 测试 JSON 反序列化错误
        let invalid_json_base64 = STANDARD.encode("不是JSON");
        let result = extractor.verify_and_extract(&invalid_json_base64);
        assert!(result.is_err());
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(err_str.contains("deseralize sample provenance"));
    }

    // 性能测试（确保大数据量下也能正常工作）
    #[test]
    fn test_verify_and_extract_performance() {
        let extractor = SampleExtractor::default();
        
        // 创建大量数据
        let mut test_data = HashMap::new();
        for i in 0..1000 {
            let app_name = format!("performance_app_{}", i);
            let mut hash_values = Vec::new();
            for j in 0..10 {
                hash_values.push(format!("hash_{}_{}", i, j));
            }
            test_data.insert(app_name, hash_values);
        }
        
        let json_data = serde_json::to_value(&test_data).unwrap();
        let json_string = json_data.to_string();
        let base64_payload = STANDARD.encode(&json_string);
        
        // 这应该能够快速完成而不出错
        let start = std::time::Instant::now();
        let result = extractor.verify_and_extract(&base64_payload).unwrap();
        let duration = start.elapsed();
        
        assert_eq!(result.len(), 1000);
        assert!(duration.as_secs() < 5); // 应该在5秒内完成
        
        // 验证结果的正确性
        for rv in &result {
            assert_eq!(rv.hash_value.len(), 10);
            assert!(rv.name.starts_with("performance_app_"));
        }
    }
}
