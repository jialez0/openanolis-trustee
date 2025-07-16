// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This Store stores RV information inside a local file

use anyhow::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::ReferenceValue;

use super::ReferenceValueStorage;

/// Local directory path to store the reference values,
/// which is created by sled engine.
const FILE_PATH: &str = "/opt/confidential-containers/attestation-service/reference_values";

/// `LocalFs` implements [`ReferenceValueStorage`] trait. And
/// it uses rocksdb inside.
pub struct LocalFs {
    engine: sled::Db,
}

fn default_file_path() -> String {
    FILE_PATH.to_string()
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Config {
    #[serde(default = "default_file_path")]
    pub file_path: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            file_path: default_file_path(),
        }
    }
}

impl LocalFs {
    /// Create a new [`LocalFs`] with given config
    pub fn new(config: Config) -> Result<Self> {
        let engine = sled::open(config.file_path)?;
        Ok(Self { engine })
    }
}

#[async_trait]
impl ReferenceValueStorage for LocalFs {
    async fn set(&self, name: String, rv: ReferenceValue) -> Result<Option<ReferenceValue>> {
        let rv_serde = serde_json::to_vec(&rv)?;
        let res = match self
            .engine
            .insert(name, rv_serde)
            .context("insert into sled")?
        {
            Some(v) => {
                let v = serde_json::from_slice(&v)?;
                Ok(Some(v))
            }
            None => Ok(None),
        };

        self.engine.flush()?;
        res
    }

    async fn get(&self, name: &str) -> Result<Option<ReferenceValue>> {
        match self.engine.get(name).context("read from sled")? {
            Some(v) => {
                let v = serde_json::from_slice(&v)?;
                Ok(Some(v))
            }
            None => Ok(None),
        }
    }

    async fn get_values(&self) -> Result<Vec<ReferenceValue>> {
        let mut values = Vec::new();

        for (_k, v) in self.engine.iter().flatten() {
            values.push(serde_json::from_slice(&v)?);
        }

        Ok(values)
    }

    async fn delete(&self, name: &str) -> Result<Option<ReferenceValue>> {
        match self.engine.remove(name).context("remove from sled")? {
            Some(v) => {
                let rv = serde_json::from_slice(&v)?;
                self.engine.flush()?;
                Ok(Some(rv))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use serial_test::serial;

    use crate::{ReferenceValue, ReferenceValueStorage};

    use super::{Config, LocalFs, default_file_path, FILE_PATH};

    const KEY: &str = "test1";

    /// This test will test the `set` and `get` interface
    /// for [`LocalFs`].
    #[tokio::test]
    #[serial]
    async fn set_and_get() {
        let temp_dir = tempfile::tempdir().expect("create tempdir failed");
        let dir_str = temp_dir.path().to_string_lossy().to_string();
        {
            let storage =
                LocalFs::new(Config { file_path: dir_str }).expect("create local fs store failed.");
            let rv = ReferenceValue::new().expect("create ReferenceValue failed.");
            assert!(
                storage
                    .set(KEY.to_owned(), rv.clone())
                    .await
                    .expect("set rv failed.")
                    .is_none(),
                "the storage has previous key of {}",
                KEY
            );
            let got = storage
                .get(KEY)
                .await
                .expect("get rv failed.")
                .expect("get None from LocalFs Store");
            assert_eq!(got, rv);
        }
    }

    /// This test will test the `set` interface with the
    /// duplicated key for [`LocalFs`].
    #[tokio::test]
    #[serial]
    async fn set_duplicated() {
        let temp_dir = tempfile::tempdir().expect("create tempdir failed");
        let dir_str = temp_dir.path().to_string_lossy().to_string();
        {
            let storage =
                LocalFs::new(Config { file_path: dir_str }).expect("create local fs store failed.");
            let rv_old = ReferenceValue::new()
                .expect("create ReferenceValue failed.")
                .set_name("old");

            let rv_new = ReferenceValue::new()
                .expect("create ReferenceValue failed.")
                .set_name("new");

            assert!(
                storage
                    .set(KEY.to_owned(), rv_old.clone())
                    .await
                    .expect("set rv failed.")
                    .is_none(),
                "the storage has previous key of {}",
                KEY
            );

            let got = storage
                .set(KEY.to_owned(), rv_new)
                .await
                .expect("get rv failed.")
                .expect("get None from LocalFs Store");

            assert_eq!(got, rv_old);
        }
    }

    /// This test will simulate a restart operation
    /// for [`LocalFs`].
    #[tokio::test]
    #[serial]
    async fn restart() {
        let rv = ReferenceValue::new().expect("create ReferenceValue failed.");
        let temp_dir = tempfile::tempdir().expect("create tempdir failed");
        let dir_str = temp_dir.path().to_string_lossy().to_string();
        {
            let storage = LocalFs::new(Config {
                file_path: dir_str.clone(),
            })
            .expect("create local fs store failed.");
            storage
                .set(KEY.to_owned(), rv.clone())
                .await
                .expect("set rv failed.");
        }
        {
            let storage =
                LocalFs::new(Config { file_path: dir_str }).expect("create local fs store failed.");
            let got = storage
                .get(KEY)
                .await
                .expect("get rv failed.")
                .expect("get None from LocalFs Store");
            assert_eq!(got, rv);
        }
    }

    // 测试 default_file_path 函数 - 覆盖第26-27行
    #[test]
    fn test_default_file_path() {
        let path = default_file_path();
        assert_eq!(path, FILE_PATH);
        assert_eq!(path, "/opt/confidential-containers/attestation-service/reference_values");
    }

    // 测试 Config 的 Default trait - 覆盖第37, 39行
    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.file_path, FILE_PATH);
        assert_eq!(config.file_path, "/opt/confidential-containers/attestation-service/reference_values");
    }

    // 测试 Config 的序列化和反序列化
    #[test]
    fn test_config_serde() {
        // 测试序列化
        let config = Config {
            file_path: "/tmp/test".to_string(),
        };
        let serialized = serde_json::to_string(&config).unwrap();
        
        // 测试反序列化
        let deserialized: Config = serde_json::from_str(&serialized).unwrap();
        assert_eq!(config, deserialized);
        
        // 测试使用默认值的反序列化
        let json_str = "{}";
        let config_default: Config = serde_json::from_str(json_str).unwrap();
        assert_eq!(config_default.file_path, FILE_PATH);
    }

    // 测试 Config 的 Clone 和 Debug traits
    #[test]
    fn test_config_traits() {
        let config1 = Config {
            file_path: "/tmp/test".to_string(),
        };
        
        // 测试 Clone
        let config2 = config1.clone();
        assert_eq!(config1, config2);
        
        // 测试 Debug
        let debug_str = format!("{:?}", config1);
        assert!(debug_str.contains("/tmp/test"));
    }

    // 测试 get 方法当键不存在时 - 覆盖第78行的None分支
    #[tokio::test]
    #[serial]
    async fn test_get_nonexistent_key() {
        let temp_dir = tempfile::tempdir().expect("create tempdir failed");
        let dir_str = temp_dir.path().to_string_lossy().to_string();
        let storage = LocalFs::new(Config { file_path: dir_str }).expect("create local fs store failed.");
        
        // 测试第78行：engine.get()返回None的情况
        let result = storage.get("nonexistent_key").await.expect("get should not fail");
        assert!(result.is_none());
    }

    // 测试 get_values 方法 - 覆盖第82-86行
    #[tokio::test]
    #[serial]
    async fn test_get_values() {
        let temp_dir = tempfile::tempdir().expect("create tempdir failed");
        let dir_str = temp_dir.path().to_string_lossy().to_string();
        let storage = LocalFs::new(Config { file_path: dir_str }).expect("create local fs store failed.");
        
        // 先添加一些数据
        let rv1 = ReferenceValue::new().expect("create ReferenceValue failed.").set_name("rv1");
        let rv2 = ReferenceValue::new().expect("create ReferenceValue failed.").set_name("rv2");
        let rv3 = ReferenceValue::new().expect("create ReferenceValue failed.").set_name("rv3");
        
        storage.set("key1".to_string(), rv1.clone()).await.expect("set rv1 failed");
        storage.set("key2".to_string(), rv2.clone()).await.expect("set rv2 failed");
        storage.set("key3".to_string(), rv3.clone()).await.expect("set rv3 failed");
        
        // 测试第82-86行：get_values的完整逻辑
        let values = storage.get_values().await.expect("get_values failed");
        assert_eq!(values.len(), 3);
        
        // 检查是否包含所有的值
        let names: Vec<String> = values.iter().map(|rv| rv.name.clone()).collect();
        assert!(names.contains(&"rv1".to_string()));
        assert!(names.contains(&"rv2".to_string()));
        assert!(names.contains(&"rv3".to_string()));
    }

    // 测试空存储的 get_values - 覆盖第82-86行的空情况
    #[tokio::test]
    #[serial]
    async fn test_get_values_empty() {
        let temp_dir = tempfile::tempdir().expect("create tempdir failed");
        let dir_str = temp_dir.path().to_string_lossy().to_string();
        let storage = LocalFs::new(Config { file_path: dir_str }).expect("create local fs store failed.");
        
        // 测试空存储的get_values
        let values = storage.get_values().await.expect("get_values failed");
        assert!(values.is_empty());
    }

    // 测试 delete 方法当键存在时 - 覆盖第89, 92-97行
    #[tokio::test]
    #[serial]
    async fn test_delete_existing_key() {
        let temp_dir = tempfile::tempdir().expect("create tempdir failed");
        let dir_str = temp_dir.path().to_string_lossy().to_string();
        let storage = LocalFs::new(Config { file_path: dir_str }).expect("create local fs store failed.");
        
        let rv = ReferenceValue::new().expect("create ReferenceValue failed.").set_name("test_rv");
        
        // 先设置一个值
        storage.set(KEY.to_string(), rv.clone()).await.expect("set rv failed");
        
        // 测试第89行：engine.remove()返回Some的情况
        // 测试第92-97行：删除存在的键的完整逻辑
        let deleted = storage.delete(KEY).await.expect("delete failed");
        assert!(deleted.is_some());
        assert_eq!(deleted.unwrap().name, "test_rv");
        
        // 验证确实被删除了
        let result = storage.get(KEY).await.expect("get after delete failed");
        assert!(result.is_none());
    }

    // 测试 delete 方法当键不存在时 - 覆盖第99行
    #[tokio::test]
    #[serial]
    async fn test_delete_nonexistent_key() {
        let temp_dir = tempfile::tempdir().expect("create tempdir failed");
        let dir_str = temp_dir.path().to_string_lossy().to_string();
        let storage = LocalFs::new(Config { file_path: dir_str }).expect("create local fs store failed.");
        
        // 测试第99行：engine.remove()返回None的情况
        let result = storage.delete("nonexistent_key").await.expect("delete should not fail");
        assert!(result.is_none());
    }

    // 测试 set 方法的序列化 - 覆盖第59行
    #[tokio::test]
    #[serial]
    async fn test_set_serialization() {
        let temp_dir = tempfile::tempdir().expect("create tempdir failed");
        let dir_str = temp_dir.path().to_string_lossy().to_string();
        let storage = LocalFs::new(Config { file_path: dir_str }).expect("create local fs store failed.");
        
        // 创建一个复杂的ReferenceValue来测试序列化
        let rv = ReferenceValue::new()
            .expect("create ReferenceValue failed.")
            .set_name("complex_rv")
            .set_version("1.0.0")
            .add_hash_value("sha256".to_string(), "abc123".to_string());
        
        // 测试第59行：serde_json::to_vec(&rv)的序列化
        let result = storage.set("complex_key".to_string(), rv.clone()).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        
        // 验证可以正确读取
        let retrieved = storage.get("complex_key").await.expect("get failed").expect("should exist");
        assert_eq!(retrieved.name, "complex_rv");
        assert_eq!(retrieved.version, "1.0.0");
    }

    // 测试多次 set 和 get 操作的组合
    #[tokio::test]
    #[serial]
    async fn test_multiple_operations() {
        let temp_dir = tempfile::tempdir().expect("create tempdir failed");
        let dir_str = temp_dir.path().to_string_lossy().to_string();
        let storage = LocalFs::new(Config { file_path: dir_str }).expect("create local fs store failed.");
        
        // 测试多个操作的组合，确保所有代码路径都被覆盖
        let rv1 = ReferenceValue::new().expect("create ReferenceValue failed.").set_name("rv1");
        let rv2 = ReferenceValue::new().expect("create ReferenceValue failed.").set_name("rv2");
        
        // 设置多个值
        storage.set("key1".to_string(), rv1.clone()).await.expect("set rv1 failed");
        storage.set("key2".to_string(), rv2.clone()).await.expect("set rv2 failed");
        
        // 获取所有值
        let all_values = storage.get_values().await.expect("get_values failed");
        assert_eq!(all_values.len(), 2);
        
        // 删除一个值
        let deleted = storage.delete("key1").await.expect("delete failed");
        assert!(deleted.is_some());
        
        // 确认剩余的值
        let remaining_values = storage.get_values().await.expect("get_values failed");
        assert_eq!(remaining_values.len(), 1);
        assert_eq!(remaining_values[0].name, "rv2");
        
        // 尝试删除已删除的键
        let not_found = storage.delete("key1").await.expect("delete failed");
        assert!(not_found.is_none());
    }

    // 测试 Config 在不同场景下的行为
    #[test]
    fn test_config_with_different_paths() {
        // 测试自定义路径
        let custom_config = Config {
            file_path: "/custom/path".to_string(),
        };
        assert_eq!(custom_config.file_path, "/custom/path");
        
        // 测试默认路径
        let default_config = Config::default();
        assert_eq!(default_config.file_path, FILE_PATH);
        
        // 测试PartialEq
        let config1 = Config { file_path: "/same/path".to_string() };
        let config2 = Config { file_path: "/same/path".to_string() };
        let config3 = Config { file_path: "/different/path".to_string() };
        
        assert_eq!(config1, config2);
        assert_ne!(config1, config3);
    }

    // 测试边界情况和错误处理
    #[tokio::test]
    #[serial]
    async fn test_edge_cases() {
        let temp_dir = tempfile::tempdir().expect("create tempdir failed");
        let dir_str = temp_dir.path().to_string_lossy().to_string();
        let storage = LocalFs::new(Config { file_path: dir_str }).expect("create local fs store failed.");
        
        // 测试空字符串键
        let rv = ReferenceValue::new().expect("create ReferenceValue failed.");
        storage.set("".to_string(), rv.clone()).await.expect("set with empty key failed");
        
        let result = storage.get("").await.expect("get with empty key failed");
        assert!(result.is_some());
        
        // 测试非常长的键名
        let long_key = "a".repeat(1000);
        storage.set(long_key.clone(), rv.clone()).await.expect("set with long key failed");
        
        let result = storage.get(&long_key).await.expect("get with long key failed");
        assert!(result.is_some());
    }
}
