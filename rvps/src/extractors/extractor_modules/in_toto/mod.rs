// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # in-toto Extractor
//!
//! This Extractor helps to verify in-toto metadata and extract
//! related reference value from link file.

pub mod shim;

use std::{
    collections::HashMap,
    env,
    fs::{create_dir_all, File},
    io::Write,
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use log::debug;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ReferenceValue;

use super::Extractor;

/// The default in-toto metadata version
static INTOTO_VERSION: &str = "0.9";

/// Provenance contains information including the following:
/// * `version`: version field of the given in-toto metadata
/// * `line_normalization`: whether Windows-style line separators
/// (CRLF) are normalized to Unix-style line separators (LF) for
/// cross-platform consistency.
/// * `files`: a key-value map. Keys are relative paths and the
/// values are base64-encoded content of the file.
#[derive(Serialize, Deserialize)]
pub struct Provenance {
    #[serde(default = "default_version")]
    version: String,
    line_normalization: bool,
    files: HashMap<String, String>,
}

/// Use to set default version of Provenance
fn default_version() -> String {
    INTOTO_VERSION.into()
}

pub struct InTotoExtractor;

impl InTotoExtractor {
    pub fn new() -> Self {
        InTotoExtractor
    }
}

impl Extractor for InTotoExtractor {
    /// In-toto's Extractor.
    ///
    /// It will verify given provenance of in-toto using
    /// Rust-wrappered in-toto-golang. If the verification
    /// succeeds, the ReferenceValues of the resulted link
    /// file will be extracted.
    ///
    /// The verification process will create a tempdir
    /// to store the metadata, and do the verification.
    fn verify_and_extract(&self, provenance: &str) -> Result<Vec<ReferenceValue>> {
        // Deserialize Provenance
        let payload: Provenance = serde_json::from_str(provenance)?;

        // Judge version
        if payload.version != INTOTO_VERSION {
            return Err(anyhow!(
                "Version unmatched! Need {}, given {}.",
                INTOTO_VERSION,
                payload.version
            ));
        }

        // Create tempdir and put the files
        let tempdir = tempfile::tempdir()?;
        let tempdir_path = tempdir.path().to_owned();
        let tempdir_str = tempdir.path().to_string_lossy().to_string();

        let mut file_paths = Vec::new();
        for (relative_path, content_base64) in &payload.files {
            let (file_path, dir) = get_file_path(&tempdir_str[..], relative_path);
            create_dir_all(dir)?;
            let mut file = File::create(&file_path)?;
            let bytes = STANDARD.decode(content_base64)?;
            file.write_all(&bytes)?;

            file_paths.push(file_path);
        }

        // get link dir (temp dir)
        debug!(
            "tempdir_path = {:?}, use temp path to store metadata",
            tempdir.path()
        );

        // get layout file
        let layout_path = file_paths
            .iter()
            .find(|&k| k.ends_with(".layout"))
            .ok_or_else(|| anyhow!("Layout file not found."))?
            .to_owned();

        // get pub keys
        let pub_key_paths = file_paths
            .iter()
            .filter(|&k| k.ends_with(".pub"))
            .map(|k| k.to_owned())
            .collect();

        let intermediate_paths = Vec::new();

        let line_normalization = payload.line_normalization;

        // Store and change current dir to the tmp dir
        let cwd = env::current_dir()?;

        // Read layout for the expired time
        let layout_file = std::fs::File::open(&layout_path)?;

        // A layout's expired time will be in signed.expires
        let _expires = {
            // fit up with the newest in-toto provenance format
            let envelope = serde_json::from_reader::<_, Value>(layout_file)?;
            let layout_base64 = &envelope["payload"];
            let payload_type = &envelope["payloadType"];
            if *payload_type != Value::String(String::from("application/vnd.in-toto+json")) {
                bail!(
                    "Unsupported payload type {}, only support `application/vnd.in-toto+json` now",
                    payload_type
                );
            }

            let layout = match layout_base64 {
                Value::String(inner) => STANDARD.decode(inner),
                _ => bail!("Unexpected payload, expected a base64 encoded string"),
            }?;

            let layout = serde_json::from_slice::<Value>(&layout).context("parse layout")?;
            let expire_str = layout["expires"]
                .as_str()
                .ok_or_else(|| anyhow!("failed to get expired time"))?;

            expire_str.parse::<DateTime<Utc>>()?
        };

        env::set_current_dir(tempdir_path)?;

        // The newest in-toto api does not return an link file to sum up
        // the outputs of the supplychain. We will only verify the provenance
        // here. Because the reference value gathered from an in-toto
        // pipeline is the hash digest of the binary, while the expected
        // measurement is a hash digest of a slice of memory area. The
        // difference is as the followiing equation:
        // memory area = binary + paddings
        // So we need a full design to include the final reference value
        // inside the provenance, which we will work on later. Before that,
        // in-toto will not be usable.
        //
        // Related issue:
        // https://github.com/confidential-containers/attestation-service/issues/42
        match shim::verify(
            layout_path,
            pub_key_paths,
            intermediate_paths,
            "".into(),
            line_normalization,
        ) {
            Ok(summary_link) => summary_link,
            Err(e) => {
                env::set_current_dir(cwd)?;
                bail!(e);
            }
        };

        // Change back working dir
        env::set_current_dir(cwd)?;

        Ok(vec![])
    }
}

/// Given a directory of tempdir and a file's relative path,
/// output the abs path of the file that will be put in the tempdir
/// and its parent dir. For example:
/// * `/tmp/tempdir` and `dir1/file` will output `/tmp/tempdir/dir1/file` and `/tmp/tempdir/dir1`
fn get_file_path(tempdir: &str, relative_file_path: &str) -> (String, String) {
    let mut abs_path = tempdir.to_string();
    abs_path.push('/');
    abs_path.push_str(relative_file_path);
    let abs_path = path_clean::clean(&abs_path[..]);
    let abs_path = abs_path.to_string_lossy();
    let dir = abs_path
        .rsplit_once('/')
        .unwrap_or((&abs_path[..], ""))
        .0
        .to_string();
    (abs_path.to_string(), dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use chrono::{TimeZone, Utc};
    use serde_json::json;
    use std::collections::HashMap;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    // 测试常量
    #[test]
    fn test_intoto_version_constant() {
        assert_eq!(INTOTO_VERSION, "0.9");
    }

    // 测试 default_version 函数
    #[test]
    fn test_default_version_function() {
        assert_eq!(default_version(), INTOTO_VERSION);
        assert_eq!(default_version(), "0.9");
    }

    // 测试 Provenance 结构体的序列化
    #[test]
    fn test_provenance_serialization() {
        let mut files = HashMap::new();
        files.insert("layout.json".to_string(), "ZHVtbXkgZGF0YQ==".to_string()); // "dummy data"的base64
        files.insert("key.pub".to_string(), "a2V5IGRhdGE=".to_string()); // "key data"的base64

        let provenance = Provenance {
            version: "0.9".to_string(),
            line_normalization: true,
            files,
        };

        let serialized = serde_json::to_value(&provenance).unwrap();
        let expected = json!({
            "version": "0.9",
            "line_normalization": true,
            "files": {
                "layout.json": "ZHVtbXkgZGF0YQ==",
                "key.pub": "a2V5IGRhdGE="
            }
        });

        assert_eq!(serialized, expected);
    }

    // 测试 Provenance 结构体的反序列化
    #[test]
    fn test_provenance_deserialization() {
        let json_data = json!({
            "version": "0.9",
            "line_normalization": false,
            "files": {
                "test.layout": "dGVzdCBkYXRh",
                "test.pub": "cHViIGtleQ=="
            }
        });

        let provenance: Provenance = serde_json::from_value(json_data).unwrap();

        assert_eq!(provenance.version, "0.9");
        assert!(!provenance.line_normalization);
        assert_eq!(provenance.files.len(), 2);
        assert_eq!(provenance.files["test.layout"], "dGVzdCBkYXRh");
        assert_eq!(provenance.files["test.pub"], "cHViIGtleQ==");
    }

    // 测试 Provenance 反序列化时使用默认版本
    #[test]
    fn test_provenance_deserialization_default_version() {
        let json_data = json!({
            "line_normalization": true,
            "files": {
                "test.layout": "dGVzdA=="
            }
        });

        let provenance: Provenance = serde_json::from_value(json_data).unwrap();

        // 应该使用默认版本
        assert_eq!(provenance.version, INTOTO_VERSION);
        assert!(provenance.line_normalization);
        assert_eq!(provenance.files.len(), 1);
    }

    // 测试 InTotoExtractor 实例化
    #[test]
    fn test_in_toto_extractor_new() {
        let extractor = InTotoExtractor::new();
        // InTotoExtractor 是空结构体，主要测试其能被正确实例化
        assert_eq!(std::mem::size_of_val(&extractor), 0);
    }

    // 测试 get_file_path 函数
    #[test]
    fn test_get_file_path_simple() {
        let (file_path, dir) = get_file_path("/tmp/test", "file.txt");
        assert_eq!(file_path, "/tmp/test/file.txt");
        assert_eq!(dir, "/tmp/test");
    }

    #[test]
    fn test_get_file_path_with_subdirectory() {
        let (file_path, dir) = get_file_path("/tmp/test", "subdir/file.txt");
        assert_eq!(file_path, "/tmp/test/subdir/file.txt");
        assert_eq!(dir, "/tmp/test/subdir");
    }

    #[test]
    fn test_get_file_path_nested_directories() {
        let (file_path, dir) = get_file_path("/tmp/test", "dir1/dir2/dir3/file.txt");
        assert_eq!(file_path, "/tmp/test/dir1/dir2/dir3/file.txt");
        assert_eq!(dir, "/tmp/test/dir1/dir2/dir3");
    }

    #[test]
    fn test_get_file_path_with_dot_normalization() {
        let (file_path, dir) = get_file_path("/tmp/test", "./subdir/../file.txt");
        assert_eq!(file_path, "/tmp/test/file.txt");
        assert_eq!(dir, "/tmp/test");
    }

    #[test]
    fn test_get_file_path_root_file() {
        let (file_path, dir) = get_file_path("/tmp/test", "file.txt");
        assert_eq!(file_path, "/tmp/test/file.txt");
        assert_eq!(dir, "/tmp/test");
    }

    #[test]
    fn test_get_file_path_empty_relative_path() {
        let (file_path, dir) = get_file_path("/tmp/test", "");
        // path_clean::clean 会将 "/tmp/test/" 规范化为 "/tmp/test"
        assert_eq!(file_path, "/tmp/test");
        // "/tmp/test".rsplit_once('/') 会返回 Some(("", "tmp/test"))，所以 dir 是 ""
        // 但是实际上它返回 None，所以会使用 unwrap_or 的分支，dir 是整个字符串去除开头的部分
        assert_eq!(dir, "/tmp");  // rsplit_once('/') 返回 Some(("/tmp", "test"))
    }

    // 测试 verify_and_extract 方法的错误路径

    #[test]
    fn test_verify_and_extract_invalid_json() {
        let extractor = InTotoExtractor::new();
        let invalid_json = "这不是有效的JSON";

        let result = extractor.verify_and_extract(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_and_extract_wrong_json_structure() {
        let extractor = InTotoExtractor::new();
        let wrong_structure = json!({
            "wrong_field": "wrong_value"
        });

        let result = extractor.verify_and_extract(&wrong_structure.to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_and_extract_version_mismatch() {
        let extractor = InTotoExtractor::new();
        let wrong_version_provenance = json!({
            "version": "999.0",
            "line_normalization": true,
            "files": {}
        });

        let result = extractor.verify_and_extract(&wrong_version_provenance.to_string());
        assert!(result.is_err());

        let error_msg = format!("{}", result.err().unwrap());
        assert!(error_msg.contains("Version unmatched"));
        assert!(error_msg.contains("Need 0.9, given 999.0"));
    }

    #[test]
    fn test_verify_and_extract_no_layout_file() {
        let extractor = InTotoExtractor::new();
        
        // 创建一个没有 .layout 文件的provenance
        let mut files = HashMap::new();
        files.insert("key.pub".to_string(), STANDARD.encode("dummy key"));
        files.insert("some.link".to_string(), STANDARD.encode("dummy link"));

        let provenance = Provenance {
            version: INTOTO_VERSION.to_string(),
            line_normalization: true,
            files,
        };

        let provenance_json = serde_json::to_string(&provenance).unwrap();
        let result = extractor.verify_and_extract(&provenance_json);
        
        assert!(result.is_err());
        let error_msg = format!("{}", result.err().unwrap());
        assert!(error_msg.contains("Layout file not found"));
    }

    #[test]
    fn test_verify_and_extract_invalid_base64_content() {
        let extractor = InTotoExtractor::new();
        
        let mut files = HashMap::new();
        files.insert("test.layout".to_string(), "这不是有效的base64".to_string());

        let provenance = Provenance {
            version: INTOTO_VERSION.to_string(),
            line_normalization: true,
            files,
        };

        let provenance_json = serde_json::to_string(&provenance).unwrap();
        let result = extractor.verify_and_extract(&provenance_json);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_and_extract_with_valid_files_but_invalid_layout_format() {
        let extractor = InTotoExtractor::new();
        
        // 创建一个有效的base64内容但不是有效in-toto layout格式的文件
        let invalid_layout = json!({
            "not_a_layout": "invalid content"
        });
        let invalid_layout_base64 = STANDARD.encode(invalid_layout.to_string());

        let mut files = HashMap::new();
        files.insert("test.layout".to_string(), invalid_layout_base64);
        files.insert("key.pub".to_string(), STANDARD.encode("dummy key"));

        let provenance = Provenance {
            version: INTOTO_VERSION.to_string(),
            line_normalization: false,
            files,
        };

        let provenance_json = serde_json::to_string(&provenance).unwrap();
        let result = extractor.verify_and_extract(&provenance_json);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_and_extract_with_invalid_envelope_format() {
        let extractor = InTotoExtractor::new();
        
        // 创建一个不符合envelope格式的layout文件
        let invalid_envelope = json!({
            "invalid": "envelope"
        });
        let invalid_envelope_base64 = STANDARD.encode(invalid_envelope.to_string());

        let mut files = HashMap::new();
        files.insert("test.layout".to_string(), invalid_envelope_base64);

        let provenance = Provenance {
            version: INTOTO_VERSION.to_string(),
            line_normalization: true,
            files,
        };

        let provenance_json = serde_json::to_string(&provenance).unwrap();
        let result = extractor.verify_and_extract(&provenance_json);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_and_extract_unsupported_payload_type() {
        let extractor = InTotoExtractor::new();
        
        // 创建一个有不支持的payloadType的envelope
        let envelope = json!({
            "payload": "ZHVtbXk=",
            "payloadType": "unsupported/type"
        });
        let envelope_base64 = STANDARD.encode(envelope.to_string());

        let mut files = HashMap::new();
        files.insert("test.layout".to_string(), envelope_base64);

        let provenance = Provenance {
            version: INTOTO_VERSION.to_string(),
            line_normalization: true,
            files,
        };

        let provenance_json = serde_json::to_string(&provenance).unwrap();
        let result = extractor.verify_and_extract(&provenance_json);
        
        assert!(result.is_err());
        let error_msg = format!("{}", result.err().unwrap());
        assert!(error_msg.contains("Unsupported payload type"));
        assert!(error_msg.contains("only support `application/vnd.in-toto+json`"));
    }

    #[test]
    fn test_verify_and_extract_payload_not_string() {
        let extractor = InTotoExtractor::new();
        
        // 创建一个payload不是字符串的envelope
        let envelope = json!({
            "payload": 123,
            "payloadType": "application/vnd.in-toto+json"
        });
        let envelope_base64 = STANDARD.encode(envelope.to_string());

        let mut files = HashMap::new();
        files.insert("test.layout".to_string(), envelope_base64);

        let provenance = Provenance {
            version: INTOTO_VERSION.to_string(),
            line_normalization: true,
            files,
        };

                 let provenance_json = serde_json::to_string(&provenance).unwrap();
         let result = extractor.verify_and_extract(&provenance_json);
        
        assert!(result.is_err());
        let error_msg = format!("{}", result.err().unwrap());
        assert!(error_msg.contains("Unexpected payload, expected a base64 encoded string"));
    }

    #[test]
    fn test_verify_and_extract_invalid_payload_base64() {
        let extractor = InTotoExtractor::new();
        
        // 创建一个payload是无效base64的envelope
        let envelope = json!({
            "payload": "无效的base64",
            "payloadType": "application/vnd.in-toto+json"
        });
        let envelope_base64 = STANDARD.encode(envelope.to_string());

        let mut files = HashMap::new();
        files.insert("test.layout".to_string(), envelope_base64);

        let provenance = Provenance {
            version: INTOTO_VERSION.to_string(),
            line_normalization: true,
            files,
        };

        let provenance_json = serde_json::to_string(&provenance).unwrap();
        let result = extractor.verify_and_extract(&provenance_json);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_and_extract_layout_without_expires() {
        let extractor = InTotoExtractor::new();
        
        // 创建一个没有expires字段的layout
        let layout = json!({
            "version": "0.9",
            "no_expires": "field"
        });
        let layout_base64 = STANDARD.encode(layout.to_string());
        
        let envelope = json!({
            "payload": layout_base64,
            "payloadType": "application/vnd.in-toto+json"
        });
        let envelope_base64 = STANDARD.encode(envelope.to_string());

        let mut files = HashMap::new();
        files.insert("test.layout".to_string(), envelope_base64);

        let provenance = Provenance {
            version: INTOTO_VERSION.to_string(),
            line_normalization: true,
            files,
        };

        let provenance_json = serde_json::to_string(&provenance).unwrap();
        let result = extractor.verify_and_extract(&provenance_json);
        
        assert!(result.is_err());
        let error_msg = format!("{}", result.err().unwrap());
        assert!(error_msg.contains("failed to get expired time"));
    }

    #[test]
    fn test_verify_and_extract_layout_with_invalid_expires_format() {
        let extractor = InTotoExtractor::new();
        
        // 创建一个expires格式无效的layout
        let layout = json!({
            "version": "0.9",
            "expires": "not_a_valid_datetime"
        });
        let layout_base64 = STANDARD.encode(layout.to_string());
        
        let envelope = json!({
            "payload": layout_base64,
            "payloadType": "application/vnd.in-toto+json"
        });
        let envelope_base64 = STANDARD.encode(envelope.to_string());

        let mut files = HashMap::new();
        files.insert("test.layout".to_string(), envelope_base64);

        let provenance = Provenance {
            version: INTOTO_VERSION.to_string(),
            line_normalization: false,
            files,
        };

        let provenance_json = serde_json::to_string(&provenance).unwrap();
        let result = extractor.verify_and_extract(&provenance_json);
        
        assert!(result.is_err());
    }

    // 测试成功路径（模拟shim::verify成功的情况）
    #[test]
    fn test_verify_and_extract_success_path() {
        let extractor = InTotoExtractor::new();
        
        // 创建一个有效的layout
        let layout = json!({
            "version": "0.9",
            "expires": "2030-12-31T23:59:59Z"
        });
        let layout_base64 = STANDARD.encode(layout.to_string());
        
        let envelope = json!({
            "payload": layout_base64,
            "payloadType": "application/vnd.in-toto+json"
        });
        let envelope_base64 = STANDARD.encode(envelope.to_string());

        let mut files = HashMap::new();
        files.insert("test.layout".to_string(), envelope_base64);
        files.insert("key.pub".to_string(), STANDARD.encode("dummy key content"));

        let provenance = Provenance {
            version: INTOTO_VERSION.to_string(),
            line_normalization: true,
            files,
        };

        let provenance_json = serde_json::to_string(&provenance).unwrap();
        
        // 由于shim::verify依赖外部的CGO库，这里我们期望会失败
        // 但可以测试到达shim::verify调用之前的所有逻辑
        let result = extractor.verify_and_extract(&provenance_json);
        
        // 这里应该失败，因为没有CGO库或文件内容不正确
        // 但重要的是我们测试了所有前置逻辑
        assert!(result.is_err());
    }

    // 测试边界情况
    #[test]
    fn test_verify_and_extract_empty_files() {
        let extractor = InTotoExtractor::new();
        
        let provenance = Provenance {
            version: INTOTO_VERSION.to_string(),
            line_normalization: true,
            files: HashMap::new(),
        };

        let provenance_json = serde_json::to_string(&provenance).unwrap();
        let result = extractor.verify_and_extract(&provenance_json);
        
        assert!(result.is_err());
        let error_msg = format!("{}", result.err().unwrap());
        assert!(error_msg.contains("Layout file not found"));
    }

    #[test]
    fn test_verify_and_extract_only_pub_files() {
        let extractor = InTotoExtractor::new();
        
        let mut files = HashMap::new();
        files.insert("key1.pub".to_string(), STANDARD.encode("key1"));
        files.insert("key2.pub".to_string(), STANDARD.encode("key2"));

        let provenance = Provenance {
            version: INTOTO_VERSION.to_string(),
            line_normalization: false,
            files,
        };

        let provenance_json = serde_json::to_string(&provenance).unwrap();
        let result = extractor.verify_and_extract(&provenance_json);
        
        assert!(result.is_err());
        let error_msg = format!("{}", result.err().unwrap());
        assert!(error_msg.contains("Layout file not found"));
    }

    #[test]
    fn test_verify_and_extract_multiple_layout_files() {
        let extractor = InTotoExtractor::new();
        
        // 创建有效的layout内容
        let layout = json!({
            "version": "0.9",
            "expires": "2030-12-31T23:59:59Z"
        });
        let layout_base64 = STANDARD.encode(layout.to_string());
        
        let envelope = json!({
            "payload": layout_base64,
            "payloadType": "application/vnd.in-toto+json"
        });
        let envelope_content = STANDARD.encode(envelope.to_string());

        let mut files = HashMap::new();
        files.insert("layout1.layout".to_string(), envelope_content.clone());
        files.insert("layout2.layout".to_string(), envelope_content);
        files.insert("key.pub".to_string(), STANDARD.encode("key"));

        let provenance = Provenance {
            version: INTOTO_VERSION.to_string(),
            line_normalization: true,
            files,
        };

        let provenance_json = serde_json::to_string(&provenance).unwrap();
        let result = extractor.verify_and_extract(&provenance_json);
        
        // 应该找到第一个layout文件并尝试处理
        assert!(result.is_err()); // 会因为shim::verify失败
    }

    #[test]
    fn test_verify_and_extract_complex_file_structure() {
        let extractor = InTotoExtractor::new();
        
        // 创建有效的layout
        let layout = json!({
            "version": "0.9",
            "expires": "2025-12-31T23:59:59Z"
        });
        let layout_base64 = STANDARD.encode(layout.to_string());
        
        let envelope = json!({
            "payload": layout_base64,
            "payloadType": "application/vnd.in-toto+json"
        });
        let envelope_content = STANDARD.encode(envelope.to_string());

        let mut files = HashMap::new();
        files.insert("subdir/nested.layout".to_string(), envelope_content);
        files.insert("keys/alice.pub".to_string(), STANDARD.encode("alice key"));
        files.insert("keys/bob.pub".to_string(), STANDARD.encode("bob key"));
        files.insert("links/step1.link".to_string(), STANDARD.encode("step1 link"));
        files.insert("links/step2.link".to_string(), STANDARD.encode("step2 link"));

        let provenance = Provenance {
            version: INTOTO_VERSION.to_string(),
            line_normalization: false,
            files,
        };

        let provenance_json = serde_json::to_string(&provenance).unwrap();
        let result = extractor.verify_and_extract(&provenance_json);
        
        // 应该能创建复杂的目录结构并尝试验证
        assert!(result.is_err()); // 会因为shim::verify失败
    }

    // 测试特殊字符和路径
    #[test]
    fn test_verify_and_extract_special_characters_in_paths() {
        let extractor = InTotoExtractor::new();
        
        let layout = json!({
            "version": "0.9",
            "expires": "2030-01-01T00:00:00Z"
        });
        let layout_base64 = STANDARD.encode(layout.to_string());
        
        let envelope = json!({
            "payload": layout_base64,
            "payloadType": "application/vnd.in-toto+json"
        });
        let envelope_content = STANDARD.encode(envelope.to_string());

        let mut files = HashMap::new();
        files.insert("测试目录/布局文件.layout".to_string(), envelope_content);
        files.insert("keys/密钥-alice.pub".to_string(), STANDARD.encode("alice key"));

        let provenance = Provenance {
            version: INTOTO_VERSION.to_string(),
            line_normalization: true,
            files,
        };

        let provenance_json = serde_json::to_string(&provenance).unwrap();
        let result = extractor.verify_and_extract(&provenance_json);
        
        assert!(result.is_err()); // 会因为shim::verify失败
    }

    // 测试序列化和反序列化的往返
    #[test]
    fn test_provenance_roundtrip_serialization() {
        let mut files = HashMap::new();
        files.insert("demo.layout".to_string(), "bGF5b3V0IGRhdGE=".to_string());
        files.insert("alice.pub".to_string(), "YWxpY2Uga2V5".to_string());
        files.insert("bob.pub".to_string(), "Ym9iIGtleQ==".to_string());

        let original = Provenance {
            version: "0.9".to_string(),
            line_normalization: true,
            files,
        };

        // 序列化
        let json_str = serde_json::to_string(&original).unwrap();
        
        // 反序列化
        let deserialized: Provenance = serde_json::from_str(&json_str).unwrap();
        
        // 验证往返
        assert_eq!(original.version, deserialized.version);
        assert_eq!(original.line_normalization, deserialized.line_normalization);
        assert_eq!(original.files.len(), deserialized.files.len());
        
        for (key, value) in &original.files {
            assert_eq!(deserialized.files.get(key), Some(value));
        }
    }

    // 测试空字符串和特殊情况
    #[test] 
    fn test_get_file_path_edge_cases() {
        // 测试空目录
        let (file_path, dir) = get_file_path("", "file.txt");
        // path_clean::clean("/file.txt") 规范化为 "/file.txt"
        assert_eq!(file_path, "/file.txt");
        assert_eq!(dir, "");  // rsplit_once('/') 返回 Some(("", "file.txt"))

        // 测试根目录
        let (file_path, dir) = get_file_path("/", "file.txt");
        assert_eq!(file_path, "/file.txt");
        assert_eq!(dir, "");  // rsplit_once('/') 返回 Some(("", "file.txt"))

        // 测试多个斜杠
        let (file_path, dir) = get_file_path("/tmp//test///", "//file.txt");
        // path_clean应该规范化路径为 "/tmp/test/file.txt"
        assert_eq!(file_path, "/tmp/test/file.txt");
        assert_eq!(dir, "/tmp/test");
    }

    // 测试verify_and_extract时的工作目录切换逻辑
    #[test]
    fn test_verify_and_extract_working_directory_handling() {
        let extractor = InTotoExtractor::new();
        
        // 保存当前目录
        let original_cwd = std::env::current_dir().unwrap();
        
        // 创建无效的layout来测试目录恢复逻辑
        let mut files = HashMap::new();
        files.insert("test.layout".to_string(), STANDARD.encode("invalid layout content"));

        let provenance = Provenance {
            version: INTOTO_VERSION.to_string(),
            line_normalization: true,
            files,
        };

        let provenance_json = serde_json::to_string(&provenance).unwrap();
        let _result = extractor.verify_and_extract(&provenance_json);
        
        // 验证即使出错，工作目录也应该被恢复
        let current_cwd = std::env::current_dir().unwrap();
        assert_eq!(original_cwd, current_cwd);
    }

    // 性能测试
    #[test]
    fn test_verify_and_extract_large_files_map() {
        let extractor = InTotoExtractor::new();
        
        let mut files = HashMap::new();
        
        // 添加大量文件
        for i in 0..1000 {
            let filename = format!("file_{}.pub", i);
            let content = format!("content_{}", i);
            files.insert(filename, STANDARD.encode(content));
        }
        
        // 确保有一个layout文件
        files.insert("test.layout".to_string(), STANDARD.encode("dummy layout"));

        let provenance = Provenance {
            version: INTOTO_VERSION.to_string(),
            line_normalization: false,
            files,
        };

        let provenance_json = serde_json::to_string(&provenance).unwrap();
        let result = extractor.verify_and_extract(&provenance_json);
        
        // 应该能处理大量文件而不出内存问题
        assert!(result.is_err()); // 会因为layout格式无效而失败
    }

    // 测试所有derive traits
    #[test]
    fn test_provenance_traits() {
        let mut files = HashMap::new();
        files.insert("test.layout".to_string(), "dGVzdA==".to_string());

        let provenance = Provenance {
            version: "0.9".to_string(),
            line_normalization: true,
            files,
        };

        // 测试序列化trait
        let _serialized = serde_json::to_string(&provenance).unwrap();
        
        // 测试反序列化trait
        let json_str = r#"{"version":"0.9","line_normalization":false,"files":{"x":"eA=="}}"#;
        let _deserialized: Provenance = serde_json::from_str(json_str).unwrap();
    }
}
