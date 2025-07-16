// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::{ResourceDesc, StorageBackend};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    boxed::Box,
    fs,
    path::{Path, PathBuf},
    pin::Pin,
};
use tokio::fs as async_fs;

pub const DEFAULT_REPO_DIR_PATH: &str = "/opt/confidential-containers/kbs/repository";

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct LocalFsRepoDesc {
    #[serde(default)]
    pub dir_path: String,
}

impl Default for LocalFsRepoDesc {
    fn default() -> Self {
        Self {
            dir_path: DEFAULT_REPO_DIR_PATH.into(),
        }
    }
}

pub struct LocalFs {
    pub repo_dir_path: String,
}

#[async_trait::async_trait]
impl StorageBackend for LocalFs {
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        let mut resource_path = PathBuf::from(&self.repo_dir_path);

        let ref_resource_path = format!(
            "{}/{}/{}",
            resource_desc.repository_name, resource_desc.resource_type, resource_desc.resource_tag
        );
        resource_path.push(ref_resource_path);

        let resource_byte = tokio::fs::read(&resource_path)
            .await
            .context("read resource from local fs")?;
        Ok(resource_byte)
    }

    async fn write_secret_resource(&self, resource_desc: ResourceDesc, data: &[u8]) -> Result<()> {
        let mut resource_path = PathBuf::from(&self.repo_dir_path);
        resource_path.push(resource_desc.repository_name);
        resource_path.push(resource_desc.resource_type);

        if !Path::new(&resource_path).exists() {
            tokio::fs::create_dir_all(&resource_path)
                .await
                .context("create new resource path")?;
        }

        resource_path.push(resource_desc.resource_tag);

        // Note that the local fs does not handle synchronization conditions
        // because it is only for test use case and we assume the write request
        // will not happen togetherly with reads.
        // If it is to be used in productive scenarios, it is recommended that
        // the storage is marked as read-only and written out-of-band.
        tokio::fs::write(resource_path, data)
            .await
            .context("write local fs")
    }

    async fn delete_secret_resource(&self, resource_desc: ResourceDesc) -> Result<()> {
        let mut resource_path = PathBuf::from(&self.repo_dir_path);

        let ref_resource_path = format!(
            "{}/{}/{}",
            resource_desc.repository_name, resource_desc.resource_type, resource_desc.resource_tag
        );
        resource_path.push(ref_resource_path);

        // Check if the resource file exists
        if !resource_path.exists() {
            return Err(anyhow::anyhow!("Resource not found: {}", resource_desc));
        }

        tokio::fs::remove_file(&resource_path)
            .await
            .context("delete resource from local fs")?;

        Ok(())
    }

    async fn list_secret_resources(&self) -> Result<Vec<ResourceDesc>> {
        let base_path = PathBuf::from(&self.repo_dir_path);
        let results = Self::scan_directory(&base_path, Vec::new()).await?;
        Ok(results)
    }
}

impl LocalFs {
    fn scan_directory(
        path: &Path,
        path_components: Vec<String>,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Vec<ResourceDesc>>> + Send + '_>> {
        Box::pin(async move {
            let mut results = Vec::new();

            let mut entries = match async_fs::read_dir(path).await {
                Ok(entries) => entries,
                Err(_) => return Ok(results),
            };
            while let Ok(Some(entry)) = entries.next_entry().await {
                let metadata = match entry.metadata().await {
                    Ok(metadata) => metadata,
                    Err(_) => continue,
                };

                let entry_name = match entry.file_name().to_str() {
                    Some(name) => name.to_string(),
                    None => continue,
                };

                let mut current_path_components = path_components.clone();
                current_path_components.push(entry_name);

                if metadata.is_dir() && current_path_components.len() < 3 {
                    let sub_results =
                        Self::scan_directory(&entry.path(), current_path_components).await?;
                    results.extend(sub_results);
                } else if metadata.is_file() && current_path_components.len() == 3 {
                    results.push(ResourceDesc {
                        repository_name: current_path_components[0].clone(),
                        resource_type: current_path_components[1].clone(),
                        resource_tag: current_path_components[2].clone(),
                    });
                }
            }

            Ok(results)
        })
    }

    pub fn new(repo_desc: &LocalFsRepoDesc) -> anyhow::Result<Self> {
        // Create repository dir.
        if !Path::new(&repo_desc.dir_path).exists() {
            fs::create_dir_all(&repo_desc.dir_path)?;
        }
        // Create default repo.
        if !Path::new(&format!("{}/default", &repo_desc.dir_path)).exists() {
            fs::create_dir_all(format!("{}/default", &repo_desc.dir_path))?;
        }

        Ok(Self {
            repo_dir_path: repo_desc.dir_path.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        local_fs::{LocalFs, LocalFsRepoDesc, DEFAULT_REPO_DIR_PATH},
        ResourceDesc, StorageBackend,
    };
    use std::path::Path;

    const TEST_DATA: &[u8] = b"testdata";

    // 辅助函数：创建测试环境
    async fn setup_test_env() -> (tempfile::TempDir, LocalFs, ResourceDesc) {
        let tmp_dir = tempfile::tempdir().expect("create temp dir failed");
        let repo_desc = LocalFsRepoDesc {
            dir_path: tmp_dir.path().to_string_lossy().to_string(),
        };

        let local_fs = LocalFs::new(&repo_desc).expect("create local fs failed");
        let resource_desc = ResourceDesc {
            repository_name: "default".into(),
            resource_type: "test".into(),
            resource_tag: "test".into(),
        };

        (tmp_dir, local_fs, resource_desc)
    }

    #[tokio::test]
    async fn test_default_repo_desc() {
        let default_desc = LocalFsRepoDesc::default();
        assert_eq!(default_desc.dir_path, DEFAULT_REPO_DIR_PATH);
    }

    #[tokio::test]
    async fn test_new_local_fs() {
        let tmp_dir = tempfile::tempdir().expect("create temp dir failed");
        let repo_desc = LocalFsRepoDesc {
            dir_path: tmp_dir.path().to_string_lossy().to_string(),
        };

        let _local_fs = LocalFs::new(&repo_desc).expect("create local fs failed");
        assert!(Path::new(&format!("{}/default", &repo_desc.dir_path)).exists());
    }

    #[tokio::test]
    async fn test_write_and_read_resource() {
        let (_tmp_dir, local_fs, resource_desc) = setup_test_env().await;

        local_fs
            .write_secret_resource(resource_desc.clone(), TEST_DATA)
            .await
            .expect("write secret resource failed");
        let data = local_fs
            .read_secret_resource(resource_desc)
            .await
            .expect("read secret resource failed");

        assert_eq!(&data[..], TEST_DATA);
    }

    #[tokio::test]
    async fn test_delete_resource() {
        let (_tmp_dir, local_fs, resource_desc) = setup_test_env().await;

        // 先写入资源
        local_fs
            .write_secret_resource(resource_desc.clone(), TEST_DATA)
            .await
            .expect("write secret resource failed");

        // 删除资源
        local_fs
            .delete_secret_resource(resource_desc.clone())
            .await
            .expect("delete secret resource failed");

        // 验证资源已被删除
        let result = local_fs.read_secret_resource(resource_desc.clone()).await;
        assert!(result.is_err());

        // 尝试删除不存在的资源
        let result = local_fs.delete_secret_resource(resource_desc).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_resources() {
        let (_tmp_dir, local_fs, resource_desc) = setup_test_env().await;

        // 写入一些测试资源
        local_fs
            .write_secret_resource(resource_desc.clone(), TEST_DATA)
            .await
            .expect("write secret resource failed");

        // 写入第二个资源
        let resource_desc2 = ResourceDesc {
            repository_name: "default".into(),
            resource_type: "test2".into(),
            resource_tag: "test2".into(),
        };
        local_fs
            .write_secret_resource(resource_desc2.clone(), TEST_DATA)
            .await
            .expect("write second secret resource failed");

        // 列出所有资源
        let resources = local_fs.list_secret_resources().await.expect("list resources failed");
        assert_eq!(resources.len(), 2);
        assert!(resources.contains(&resource_desc));
        assert!(resources.contains(&resource_desc2));
    }

    #[tokio::test]
    async fn test_write_to_nonexistent_directory() {
        let (_tmp_dir, local_fs, mut resource_desc) = setup_test_env().await;

        // 使用不存在的目录路径
        resource_desc.repository_name = "nonexistent".into();
        resource_desc.resource_type = "newtype".into();

        // 写入应该成功，因为会自动创建目录
        let result = local_fs
            .write_secret_resource(resource_desc.clone(), TEST_DATA)
            .await;
        assert!(result.is_ok());

        // 验证目录被创建
        let path = Path::new(&local_fs.repo_dir_path)
            .join("nonexistent")
            .join("newtype");
        assert!(path.exists());
    }

    #[tokio::test]
    async fn test_scan_empty_directory() {
        let (_tmp_dir, local_fs, _) = setup_test_env().await;
        
        // 列出空目录的资源
        let resources = local_fs.list_secret_resources().await.expect("list resources failed");
        assert!(resources.is_empty());
    }

    #[tokio::test]
    async fn test_invalid_resource_paths() {
        let (_tmp_dir, local_fs, _) = setup_test_env().await;
        
        // 创建一个无效的资源描述（路径不完整）
        let invalid_resource = ResourceDesc {
            repository_name: "invalid".into(),
            resource_type: "".into(),
            resource_tag: "".into(),
        };

        // 尝试读取无效资源
        let result = local_fs.read_secret_resource(invalid_resource.clone()).await;
        assert!(result.is_err());
    }
}
