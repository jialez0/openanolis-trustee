use std::{fs, path::PathBuf};

use super::ReferenceValueStorage;
use crate::ReferenceValue;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use log::debug;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

const FILE_PATH: &str = "/opt/confidential-containers/attestation-service/reference_values.json";

#[derive(Debug)]
pub struct LocalJson {
    file_path: String,
    lock: RwLock<i32>,
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

impl LocalJson {
    pub fn new(config: Config) -> Result<Self> {
        let mut path = PathBuf::new();
        path.push(&config.file_path);

        let parent_dir = path.parent().ok_or_else(|| {
            anyhow!("Illegal `file_path` for LocalJson's config without a parent dir.")
        })?;
        debug!("create path for LocalJson: {:?}", parent_dir);
        fs::create_dir_all(parent_dir)?;

        if !path.exists() {
            debug!("Creating empty file for LocalJson reference values.");
            std::fs::write(config.file_path.clone(), "[]")?;
        }

        Ok(Self {
            file_path: config.file_path,
            lock: RwLock::new(0),
        })
    }
}

#[async_trait]
impl ReferenceValueStorage for LocalJson {
    async fn set(&self, name: String, rv: ReferenceValue) -> Result<Option<ReferenceValue>> {
        let _ = self.lock.write().await;
        let file = tokio::fs::read(&self.file_path).await?;
        let mut rvs: Vec<ReferenceValue> = serde_json::from_slice(&file)?;
        let mut res = None;
        if let Some(item) = rvs.iter_mut().find(|it| it.name == name) {
            res = Some(item.to_owned());
            *item = rv;
        } else {
            rvs.push(rv);
        }

        let contents = serde_json::to_vec(&rvs)?;
        tokio::fs::write(&self.file_path, contents).await?;
        Ok(res)
    }

    async fn get(&self, name: &str) -> Result<Option<ReferenceValue>> {
        let _ = self.lock.read().await;
        let file = tokio::fs::read(&self.file_path).await?;
        let rvs: Vec<ReferenceValue> = serde_json::from_slice(&file)?;
        let rv = rvs.into_iter().find(|rv| rv.name == name);
        Ok(rv)
    }

    async fn get_values(&self) -> Result<Vec<ReferenceValue>> {
        let _ = self.lock.read().await;
        let file = tokio::fs::read(&self.file_path).await?;
        let rvs: Vec<ReferenceValue> = serde_json::from_slice(&file)?;
        Ok(rvs)
    }

    async fn delete(&self, name: &str) -> Result<Option<ReferenceValue>> {
        let _ = self.lock.write().await;
        let file = tokio::fs::read(&self.file_path).await?;
        let mut rvs: Vec<ReferenceValue> = serde_json::from_slice(&file)?;

        let mut deleted_rv = None;
        if let Some(pos) = rvs.iter().position(|rv| rv.name == name) {
            deleted_rv = Some(rvs.remove(pos));
        }

        let contents = serde_json::to_vec(&rvs)?;
        tokio::fs::write(&self.file_path, contents).await?;
        Ok(deleted_rv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use std::fs;
    use tempfile::TempDir;


    fn create_test_reference_value(name: &str) -> ReferenceValue {
        ReferenceValue::new()
            .unwrap()
            .set_name(name)
            .set_expiration(Utc.with_ymd_and_hms(2025, 12, 31, 23, 59, 59).unwrap())
            .add_hash_value("sha256".to_string(), "test_hash_value".to_string())
    }

    #[test]
    fn test_default_file_path() {
        let path = default_file_path();
        assert_eq!(path, FILE_PATH);
    }

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.file_path, FILE_PATH);
    }

    #[test]
    fn test_config_serde() {
        // 测试序列化
        let config = Config {
            file_path: "/tmp/test.json".to_string(),
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

    #[test]
    fn test_local_json_new_success() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.json").to_string_lossy().to_string();
        
        let config = Config { file_path: file_path.clone() };
        let local_json = LocalJson::new(config).unwrap();
        
        assert_eq!(local_json.file_path, file_path);
        
        // 验证文件是否被创建并包含空数组
        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "[]");
    }

    #[test]
    fn test_local_json_new_with_existing_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("existing.json").to_string_lossy().to_string();
        
        // 先创建一个已存在的文件
        fs::write(&file_path, r#"[{"name":"test","version":"0.1.0","expiration":"2025-12-31T23:59:59Z","hash-value":[]}]"#).unwrap();
        
        let config = Config { file_path: file_path.clone() };
        let local_json = LocalJson::new(config).unwrap();
        
        assert_eq!(local_json.file_path, file_path);
        
        // 验证文件内容没有被覆盖
        let content = fs::read_to_string(&file_path).unwrap();
        assert_ne!(content, "[]");
    }

    #[test]
    fn test_local_json_new_creates_parent_directories() {
        let temp_dir = TempDir::new().unwrap();
        let nested_path = temp_dir.path().join("nested").join("dir").join("test.json");
        let file_path = nested_path.to_string_lossy().to_string();
        
        let config = Config { file_path: file_path.clone() };
        let local_json = LocalJson::new(config).unwrap();
        
        assert_eq!(local_json.file_path, file_path);
        assert!(nested_path.exists());
    }

    #[test]
    fn test_local_json_new_fails_without_parent_dir() {
        // 使用根路径这样的无效路径（没有父目录）
        let config = Config { file_path: "/".to_string() };
        let result = LocalJson::new(config);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("without a parent dir"));
    }

    #[tokio::test]
    async fn test_set_new_reference_value() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_set.json").to_string_lossy().to_string();
        
        let config = Config { file_path };
        let local_json = LocalJson::new(config).unwrap();
        
        let rv = create_test_reference_value("test_artifact");
        let result = local_json.set("test_artifact".to_string(), rv.clone()).await.unwrap();
        
        // 新插入应该返回 None
        assert!(result.is_none());
        
        // 验证文件内容
        let file_content = tokio::fs::read(&local_json.file_path).await.unwrap();
        let rvs: Vec<ReferenceValue> = serde_json::from_slice(&file_content).unwrap();
        assert_eq!(rvs.len(), 1);
        assert_eq!(rvs[0].name, "test_artifact");
    }

    #[tokio::test]
    async fn test_set_update_existing_reference_value() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_update.json").to_string_lossy().to_string();
        
        let config = Config { file_path };
        let local_json = LocalJson::new(config).unwrap();
        
        // 先插入一个值
        let rv1 = create_test_reference_value("test_artifact");
        local_json.set("test_artifact".to_string(), rv1.clone()).await.unwrap();
        
        // 更新同一个名称的值
        let rv2 = create_test_reference_value("test_artifact")
            .add_hash_value("sha512".to_string(), "new_hash".to_string());
        let result = local_json.set("test_artifact".to_string(), rv2.clone()).await.unwrap();
        
        // 更新应该返回旧值
        assert!(result.is_some());
        let old_rv = result.unwrap();
        assert_eq!(old_rv.hash_values().len(), 1); // 旧值只有一个hash
        
        // 验证文件内容被更新
        let file_content = tokio::fs::read(&local_json.file_path).await.unwrap();
        let rvs: Vec<ReferenceValue> = serde_json::from_slice(&file_content).unwrap();
        assert_eq!(rvs.len(), 1);
        assert_eq!(rvs[0].hash_values().len(), 2); // 新值有两个hash
    }

    #[tokio::test]
    async fn test_get_existing_reference_value() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_get.json").to_string_lossy().to_string();
        
        let config = Config { file_path };
        let local_json = LocalJson::new(config).unwrap();
        
        let rv = create_test_reference_value("test_artifact");
        local_json.set("test_artifact".to_string(), rv.clone()).await.unwrap();
        
        let result = local_json.get("test_artifact").await.unwrap();
        assert!(result.is_some());
        
        let retrieved_rv = result.unwrap();
        assert_eq!(retrieved_rv.name, "test_artifact");
        assert_eq!(retrieved_rv.hash_values().len(), 1);
    }

    #[tokio::test]
    async fn test_get_non_existing_reference_value() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_get_none.json").to_string_lossy().to_string();
        
        let config = Config { file_path };
        let local_json = LocalJson::new(config).unwrap();
        
        let result = local_json.get("non_existing").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_values_empty() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_get_values_empty.json").to_string_lossy().to_string();
        
        let config = Config { file_path };
        let local_json = LocalJson::new(config).unwrap();
        
        let result = local_json.get_values().await.unwrap();
        assert_eq!(result.len(), 0);
    }

    #[tokio::test]
    async fn test_get_values_with_data() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_get_values.json").to_string_lossy().to_string();
        
        let config = Config { file_path };
        let local_json = LocalJson::new(config).unwrap();
        
        // 添加多个值
        let rv1 = create_test_reference_value("artifact1");
        let rv2 = create_test_reference_value("artifact2");
        
        local_json.set("artifact1".to_string(), rv1).await.unwrap();
        local_json.set("artifact2".to_string(), rv2).await.unwrap();
        
        let result = local_json.get_values().await.unwrap();
        assert_eq!(result.len(), 2);
        
        let names: Vec<&str> = result.iter().map(|rv| rv.name.as_str()).collect();
        assert!(names.contains(&"artifact1"));
        assert!(names.contains(&"artifact2"));
    }

    #[tokio::test]
    async fn test_delete_existing_reference_value() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_delete.json").to_string_lossy().to_string();
        
        let config = Config { file_path };
        let local_json = LocalJson::new(config).unwrap();
        
        // 先添加两个值
        let rv1 = create_test_reference_value("artifact1");
        let rv2 = create_test_reference_value("artifact2");
        
        local_json.set("artifact1".to_string(), rv1.clone()).await.unwrap();
        local_json.set("artifact2".to_string(), rv2).await.unwrap();
        
        // 删除其中一个
        let result = local_json.delete("artifact1").await.unwrap();
        assert!(result.is_some());
        
        let deleted_rv = result.unwrap();
        assert_eq!(deleted_rv.name, "artifact1");
        
        // 验证文件中只剩一个值
        let remaining = local_json.get_values().await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].name, "artifact2");
    }

    #[tokio::test]
    async fn test_delete_non_existing_reference_value() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_delete_none.json").to_string_lossy().to_string();
        
        let config = Config { file_path };
        let local_json = LocalJson::new(config).unwrap();
        
        let result = local_json.delete("non_existing").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_concurrent.json").to_string_lossy().to_string();
        
        let config = Config { file_path };
        let local_json = std::sync::Arc::new(LocalJson::new(config).unwrap());
        
        // 顺序添加一些值，然后并发读取以测试读锁
        let rv1 = create_test_reference_value("artifact1");
        let rv2 = create_test_reference_value("artifact2");
        local_json.set("artifact1".to_string(), rv1).await.unwrap();
        local_json.set("artifact2".to_string(), rv2).await.unwrap();
        
        // 创建多个并发读任务
        let mut handles = vec![];
        
        for _ in 0..3 {
            let local_json_clone = local_json.clone();
            let handle = tokio::spawn(async move {
                let result1 = local_json_clone.get("artifact1").await.unwrap();
                let result2 = local_json_clone.get("artifact2").await.unwrap();
                assert!(result1.is_some());
                assert!(result2.is_some());
                (result1.unwrap().name, result2.unwrap().name)
            });
            handles.push(handle);
        }
        
        // 等待所有任务完成
        for handle in handles {
            let (name1, name2) = handle.await.unwrap();
            assert_eq!(name1, "artifact1");
            assert_eq!(name2, "artifact2");
        }
        
        // 验证总数仍然是2
        let result = local_json.get_values().await.unwrap();
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_file_corruption_handling() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_corruption.json").to_string_lossy().to_string();
        
        let config = Config { file_path: file_path.clone() };
        let local_json = LocalJson::new(config).unwrap();
        
        // 写入无效的JSON数据
        tokio::fs::write(&file_path, "invalid json").await.unwrap();
        
        // 尝试读取应该失败
        let result = local_json.get("any").await;
        assert!(result.is_err());
        
        let result = local_json.get_values().await;
        assert!(result.is_err());
        
        let result = local_json.set("test".to_string(), create_test_reference_value("test")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_lock_behavior() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_lock.json").to_string_lossy().to_string();
        
        let config = Config { file_path };
        let local_json = std::sync::Arc::new(LocalJson::new(config).unwrap());
        
        // 测试读锁不阻塞其他读操作
        let local_json1 = local_json.clone();
        let local_json2 = local_json.clone();
        
        let handle1 = tokio::spawn(async move {
            let _guard = local_json1.lock.read().await;
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            "read1"
        });
        
        let handle2 = tokio::spawn(async move {
            let _guard = local_json2.lock.read().await;
            "read2"
        });
        
        let (result1, result2) = tokio::join!(handle1, handle2);
        assert_eq!(result1.unwrap(), "read1");
        assert_eq!(result2.unwrap(), "read2");
    }

    #[test]
    fn test_config_clone() {
        let config1 = Config {
            file_path: "/tmp/test.json".to_string(),
        };
        let config2 = config1.clone();
        
        assert_eq!(config1, config2);
        assert_eq!(config1.file_path, config2.file_path);
    }

    #[test]
    fn test_config_debug() {
        let config = Config {
            file_path: "/tmp/test.json".to_string(),
        };
        
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("/tmp/test.json"));
    }

    #[tokio::test]
    async fn test_edge_cases() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_edge.json").to_string_lossy().to_string();
        
        let config = Config { file_path };
        let local_json = LocalJson::new(config).unwrap();
        
        // 测试空字符串名称
        let rv = create_test_reference_value("");
        local_json.set("".to_string(), rv).await.unwrap();
        
        let result = local_json.get("").await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "");
        
        // 测试删除空字符串名称
        let deleted = local_json.delete("").await.unwrap();
        assert!(deleted.is_some());
        assert_eq!(deleted.unwrap().name, "");
    }
}
