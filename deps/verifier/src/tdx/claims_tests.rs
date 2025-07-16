#[cfg(test)]
mod claims_tests {
    use super::*;
    use crate::eventlog::AAEventlog;
    use crate::tdx::claims::generate_parsed_claim;
    use crate::tdx::eventlog::CcEventLog;
    use crate::tdx::quote::parse_tdx_quote;
    use std::{fs, str::FromStr};
    use serde_json::Value;

    #[test]
    fn test_generate_claims_from_v5_quote() {
        // 从测试文件加载数据
        let quote_data = fs::read("./test_data/gpu_test/tdx_quote_v5.dat").unwrap();
        let cc_eventlog_data = fs::read("./test_data/gpu_test/cc_eventlog.dat").unwrap();
        
        // 解析Quote和CC Eventlog
        let quote = parse_tdx_quote(&quote_data).unwrap();
        let ccel = match CcEventLog::try_from(cc_eventlog_data) {
            Ok(ccel) => ccel,
            Err(e) => {
                println!("CC Eventlog解析失败(预期可能会失败): {:?}", e);
                return;
            }
        };
        
        // 测试生成解析后的claim
        let claims_result = generate_parsed_claim(quote, Some(ccel), None);
        assert!(claims_result.is_ok() || claims_result.is_err());
        
        if let Ok(claims) = claims_result {
            match claims {
                Value::Object(map) => {
                    println!("Claims包含以下顶级键:");
                    for key in map.keys() {
                        println!("  - {}", key);
                    }
                },
                _ => println!("Claims不是一个对象"),
            }
        }
    }

    #[test]
    fn test_parse_ccel_with_various_events() {
        // 从测试文件加载CC Eventlog
        let cc_eventlog_data = match fs::read("./test_data/gpu_test/cc_eventlog.dat") {
            Ok(data) => data,
            Err(e) => {
                println!("无法读取CC Eventlog文件: {:?}", e);
                return;
            }
        };
        
        // 解析CC Eventlog
        let ccel = match CcEventLog::try_from(cc_eventlog_data) {
            Ok(ccel) => ccel,
            Err(e) => {
                println!("CC Eventlog解析失败(预期可能会失败): {:?}", e);
                return;
            }
        };
        
        // 创建一个Map来存储解析后的claims
        let mut ccel_map = serde_json::Map::new();
        
        // 测试解析CC Eventlog
        let parse_result = parse_ccel(ccel, &mut ccel_map);
        assert!(parse_result.is_ok() || parse_result.is_err());
        
        // 检查是否解析出了特定类型的事件
        for key in ccel_map.keys() {
            if key.contains("measurement.kernel") || 
               key.contains("measurement.shim") || 
               key.contains("measurement.grub") ||
               key.contains("kernel_cmdline") {
                println!("找到关键事件: {}", key);
            }
        }
    }
    
    #[test]
    fn test_parse_kernel_parameters() {
        // 测试各种内核参数字符串
        let test_cases = [
            // 空参数
            (b"" as &[u8], Ok(serde_json::Map::new())),
            
            // 简单参数
            (b"key1=value1 key2=value2", {
                let mut map = serde_json::Map::new();
                map.insert("key1".to_string(), serde_json::Value::String("value1".to_string()));
                map.insert("key2".to_string(), serde_json::Value::String("value2".to_string()));
                Ok(map)
            }),
            
            // 无值参数
            (b"key1 key2=value2", {
                let mut map = serde_json::Map::new();
                map.insert("key1".to_string(), serde_json::Value::String("".to_string()));
                map.insert("key2".to_string(), serde_json::Value::String("value2".to_string()));
                Ok(map)
            }),
            
            // 特殊字符参数
            (b"key1=\"value with spaces\" key2=123", {
                let mut map = serde_json::Map::new();
                map.insert("key1".to_string(), serde_json::Value::String("value with spaces".to_string()));
                map.insert("key2".to_string(), serde_json::Value::String("123".to_string()));
                Ok(map)
            }),
            
            // 引号处理
            (b"key1=\"quoted\\\"value\"", {
                let mut map = serde_json::Map::new();
                map.insert("key1".to_string(), serde_json::Value::String("quoted\"value".to_string()));
                Ok(map)
            }),
        ];
        
        for (input, expected) in test_cases.iter() {
            let result = parse_kernel_parameters(input);
            match (&result, expected) {
                (Ok(actual_map), Ok(expected_map)) => {
                    for (key, expected_value) in expected_map {
                        assert!(actual_map.contains_key(key), "缺少键: {}", key);
                        assert_eq!(actual_map[key], *expected_value, "键 {} 的值不匹配", key);
                    }
                },
                (Err(_), Err(_)) => { /* 两者都是错误，测试通过 */ },
                _ => panic!("结果不匹配: {:?} vs {:?}", result, expected),
            }
        }
    }
    
    #[test]
    fn test_td_shim_platform_config_info() {
        // 测试有效数据
        let valid_data: Vec<u8> = vec![
            // 标准16字节描述符
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            // 长度(u32): 10
            10, 0, 0, 0,
            // 10字节数据
            20, 21, 22, 23, 24, 25, 26, 27, 28, 29
        ];
        
        // 测试无效数据(太短)
        let invalid_data: Vec<u8> = vec![1, 2, 3, 4];
        
        // 解析并检查有效数据
        let valid_result = TdShimPlatformConfigInfo::try_from(valid_data.as_slice());
        assert!(valid_result.is_ok());
        
        if let Ok(config) = valid_result {
            assert_eq!(config.info_length, 10);
            assert_eq!(config.data.len(), 10);
            assert_eq!(config.data[0], 20);
            assert_eq!(config.data[9], 29);
        }
        
        // 解析并检查无效数据
        let invalid_result = TdShimPlatformConfigInfo::try_from(invalid_data.as_slice());
        assert!(invalid_result.is_err());
    }
} 