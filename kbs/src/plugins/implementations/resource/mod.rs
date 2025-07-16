// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

pub mod local_fs;

#[cfg(feature = "aliyun")]
pub mod aliyun_kms;

use actix_web::http::Method;
use anyhow::{bail, Context, Result};

pub mod backend;
pub use backend::*;

use super::super::plugin_manager::ClientPlugin;

#[async_trait::async_trait]
impl ClientPlugin for ResourceStorage {
    async fn handle(
        &self,
        body: &[u8],
        _query: &str,
        path: &str,
        method: &Method,
    ) -> Result<Vec<u8>> {
        let resource_desc = path
            .strip_prefix('/')
            .context("accessed path is illegal, should start with `/`")?;
        match method.as_str() {
            "POST" => {
                let resource_description = ResourceDesc::try_from(resource_desc)?;
                self.set_secret_resource(resource_description, body).await?;
                Ok(vec![])
            }
            "GET" => {
                // Check if this is a list request based on path pattern
                if resource_desc == "resources" {
                    let resources = self.list_secret_resources().await?;
                    let json_response = serde_json::to_vec(&resources)
                        .context("Failed to serialize resource list")?;
                    Ok(json_response)
                } else {
                    // Handle single resource request
                    let resource_description = ResourceDesc::try_from(resource_desc)?;
                    let resource = self.get_secret_resource(resource_description).await?;
                    Ok(resource)
                }
            }
            "DELETE" => {
                let resource_description = ResourceDesc::try_from(resource_desc)?;
                self.delete_secret_resource(resource_description).await?;
                Ok(vec![])
            }
            _ => bail!("Illegal HTTP method. Only supports `GET`, `POST`, and `DELETE`"),
        }
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        method: &Method,
    ) -> Result<bool> {
        if method.as_str() == "POST" || method.as_str() == "DELETE" {
            return Ok(true);
        }

        Ok(false)
    }

    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        method: &Method,
    ) -> Result<bool> {
        if method.as_str() == "GET" {
            return Ok(true);
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::Method;
    use std::collections::HashMap;
    use tokio;

    // Mock ResourceStorage for testing
    struct MockResourceStorage {
        resources: std::sync::Mutex<HashMap<String, Vec<u8>>>,
        should_fail_set: bool,
        should_fail_get: bool,
        should_fail_delete: bool,
        should_fail_list: bool,
    }

    impl MockResourceStorage {
        fn new() -> Self {
            Self {
                resources: std::sync::Mutex::new(HashMap::new()),
                should_fail_set: false,
                should_fail_get: false,
                should_fail_delete: false,
                should_fail_list: false,
            }
        }

        fn with_set_failure(mut self) -> Self {
            self.should_fail_set = true;
            self
        }

        fn with_get_failure(mut self) -> Self {
            self.should_fail_get = true;
            self
        }

        fn with_delete_failure(mut self) -> Self {
            self.should_fail_delete = true;
            self
        }

        fn with_list_failure(mut self) -> Self {
            self.should_fail_list = true;
            self
        }
    }

    impl MockResourceStorage {
        async fn set_secret_resource(&self, desc: ResourceDesc, data: &[u8]) -> Result<()> {
            if self.should_fail_set {
                return Err(anyhow::anyhow!("Mock set failure"));
            }
            let key = format!("{}/{}/{}", desc.repository_name, desc.resource_type, desc.resource_tag);
            self.resources.lock().unwrap().insert(key, data.to_vec());
            Ok(())
        }

        async fn get_secret_resource(&self, desc: ResourceDesc) -> Result<Vec<u8>> {
            if self.should_fail_get {
                return Err(anyhow::anyhow!("Mock get failure"));
            }
            let key = format!("{}/{}/{}", desc.repository_name, desc.resource_type, desc.resource_tag);
            self.resources
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("Resource not found"))
        }

        async fn delete_secret_resource(&self, desc: ResourceDesc) -> Result<()> {
            if self.should_fail_delete {
                return Err(anyhow::anyhow!("Mock delete failure"));
            }
            let key = format!("{}/{}/{}", desc.repository_name, desc.resource_type, desc.resource_tag);
            self.resources.lock().unwrap().remove(&key);
            Ok(())
        }

        async fn list_secret_resources(&self) -> Result<Vec<ResourceDesc>> {
            if self.should_fail_list {
                return Err(anyhow::anyhow!("Mock list failure"));
            }
            let resources: Vec<ResourceDesc> = self.resources.lock().unwrap().keys()
                .map(|key| {
                    let parts: Vec<&str> = key.split('/').collect();
                    if parts.len() == 3 {
                        ResourceDesc {
                            repository_name: parts[0].to_string(),
                            resource_type: parts[1].to_string(),
                            resource_tag: parts[2].to_string(),
                        }
                    } else {
                        ResourceDesc {
                            repository_name: "unknown".to_string(),
                            resource_type: "unknown".to_string(),
                            resource_tag: "unknown".to_string(),
                        }
                    }
                })
                .collect();
            Ok(resources)
        }
    }

    #[async_trait::async_trait]
    impl ClientPlugin for MockResourceStorage {
        async fn handle(
            &self,
            body: &[u8],
            _query: &str,
            path: &str,
            method: &Method,
        ) -> Result<Vec<u8>> {
            let resource_desc = path
                .strip_prefix('/')
                .context("accessed path is illegal, should start with `/`")?;
            match method.as_str() {
                "POST" => {
                    let resource_description = ResourceDesc::try_from(resource_desc)?;
                    self.set_secret_resource(resource_description, body).await?;
                    Ok(vec![])
                }
                "GET" => {
                    // Check if this is a list request based on path pattern
                    if resource_desc == "resources" {
                        let resources = self.list_secret_resources().await?;
                        let json_response = serde_json::to_vec(&resources)
                            .context("Failed to serialize resource list")?;
                        Ok(json_response)
                    } else {
                        // Handle single resource request
                        let resource_description = ResourceDesc::try_from(resource_desc)?;
                        let resource = self.get_secret_resource(resource_description).await?;
                        Ok(resource)
                    }
                }
                "DELETE" => {
                    let resource_description = ResourceDesc::try_from(resource_desc)?;
                    self.delete_secret_resource(resource_description).await?;
                    Ok(vec![])
                }
                _ => bail!("Illegal HTTP method. Only supports `GET`, `POST`, and `DELETE`"),
            }
        }

        async fn validate_auth(
            &self,
            _body: &[u8],
            _query: &str,
            _path: &str,
            method: &Method,
        ) -> Result<bool> {
            if method.as_str() == "POST" || method.as_str() == "DELETE" {
                return Ok(true);
            }

            Ok(false)
        }

        async fn encrypted(
            &self,
            _body: &[u8],
            _query: &str,
            _path: &str,
            method: &Method,
        ) -> Result<bool> {
            if method.as_str() == "GET" {
                return Ok(true);
            }

            Ok(false)
        }
    }

    // Test handle method for POST requests
    #[tokio::test]
    async fn test_handle_post_success() {
        let storage = MockResourceStorage::new();
        let body = b"test-resource-data";
        let path = "/repo/type/tag";
        let method = Method::POST;

        let result = storage.handle(body, "", path, &method).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Vec::<u8>::new());
    }

    #[tokio::test]
    async fn test_handle_post_failure() {
        let storage = MockResourceStorage::new().with_set_failure();
        let body = b"test-resource-data";
        let path = "/repo/type/tag";
        let method = Method::POST;

        let result = storage.handle(body, "", path, &method).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Mock set failure"));
    }

    #[tokio::test]
    async fn test_handle_post_invalid_path() {
        let storage = MockResourceStorage::new();
        let body = b"test-resource-data";
        let path = "invalid-path"; // Missing leading slash
        let method = Method::POST;

        let result = storage.handle(body, "", path, &method).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("accessed path is illegal"));
    }

    // Test handle method for GET requests (single resource)
    #[tokio::test]
    async fn test_handle_get_single_resource_success() {
        let storage = MockResourceStorage::new();
        let path = "/repo/type/tag";
        let method = Method::GET;

        // First set a resource
        let _ = storage.handle(b"test-data", "", path, &Method::POST).await;

        // Then get it
        let result = storage.handle(b"", "", path, &method).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"test-data");
    }

    #[tokio::test]
    async fn test_handle_get_single_resource_not_found() {
        let storage = MockResourceStorage::new();
        let path = "/repo/type/nonexistent";
        let method = Method::GET;

        let result = storage.handle(b"", "", path, &method).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Resource not found"));
    }

    #[tokio::test]
    async fn test_handle_get_single_resource_failure() {
        let storage = MockResourceStorage::new().with_get_failure();
        let path = "/repo/type/tag";
        let method = Method::GET;

        let result = storage.handle(b"", "", path, &method).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Mock get failure"));
    }

    // Test handle method for GET requests (list resources)
    #[tokio::test]
    async fn test_handle_get_list_resources_success() {
        let storage = MockResourceStorage::new();
        let path = "/resources";
        let method = Method::GET;

        // First set some resources
        let _ = storage.handle(b"data1", "", "/repo1/type1/tag1", &Method::POST).await;
        let _ = storage.handle(b"data2", "", "/repo2/type2/tag2", &Method::POST).await;

        // Then list them
        let result = storage.handle(b"", "", path, &method).await;
        assert!(result.is_ok());
        
        let json_data = result.unwrap();
        let resources: Vec<ResourceDesc> = serde_json::from_slice(&json_data).unwrap();
        assert_eq!(resources.len(), 2);
        assert!(resources.iter().any(|r| r.repository_name == "repo1" && r.resource_type == "type1" && r.resource_tag == "tag1"));
        assert!(resources.iter().any(|r| r.repository_name == "repo2" && r.resource_type == "type2" && r.resource_tag == "tag2"));
    }

    #[tokio::test]
    async fn test_handle_get_list_resources_empty() {
        let storage = MockResourceStorage::new();
        let path = "/resources";
        let method = Method::GET;

        let result = storage.handle(b"", "", path, &method).await;
        assert!(result.is_ok());
        
        let json_data = result.unwrap();
        let resources: Vec<ResourceDesc> = serde_json::from_slice(&json_data).unwrap();
        assert_eq!(resources.len(), 0);
    }

    #[tokio::test]
    async fn test_handle_get_list_resources_failure() {
        let storage = MockResourceStorage::new().with_list_failure();
        let path = "/resources";
        let method = Method::GET;

        let result = storage.handle(b"", "", path, &method).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Mock list failure"));
    }

    // Test handle method for DELETE requests
    #[tokio::test]
    async fn test_handle_delete_success() {
        let storage = MockResourceStorage::new();
        let path = "/repo/type/tag";
        let method = Method::DELETE;

        // First set a resource
        let _ = storage.handle(b"test-data", "", path, &Method::POST).await;

        // Then delete it
        let result = storage.handle(b"", "", path, &method).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Vec::<u8>::new());

        // Verify it's deleted
        let get_result = storage.handle(b"", "", path, &Method::GET).await;
        assert!(get_result.is_err());
    }

    #[tokio::test]
    async fn test_handle_delete_failure() {
        let storage = MockResourceStorage::new().with_delete_failure();
        let path = "/repo/type/tag";
        let method = Method::DELETE;

        let result = storage.handle(b"", "", path, &method).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Mock delete failure"));
    }

    // Test handle method for unsupported HTTP methods
    #[tokio::test]
    async fn test_handle_unsupported_method() {
        let storage = MockResourceStorage::new();
        let path = "/repo/type/tag";
        let method = Method::PUT;

        let result = storage.handle(b"", "", path, &method).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Illegal HTTP method"));
    }

    #[tokio::test]
    async fn test_handle_patch_method() {
        let storage = MockResourceStorage::new();
        let path = "/repo/type/tag";
        let method = Method::PATCH;

        let result = storage.handle(b"", "", path, &method).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Illegal HTTP method"));
    }

    // Test validate_auth method
    #[tokio::test]
    async fn test_validate_auth_post_method() {
        let storage = MockResourceStorage::new();
        let method = Method::POST;

        let result = storage.validate_auth(b"", "", "/path", &method).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[tokio::test]
    async fn test_validate_auth_delete_method() {
        let storage = MockResourceStorage::new();
        let method = Method::DELETE;

        let result = storage.validate_auth(b"", "", "/path", &method).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[tokio::test]
    async fn test_validate_auth_get_method() {
        let storage = MockResourceStorage::new();
        let method = Method::GET;

        let result = storage.validate_auth(b"", "", "/path", &method).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false);
    }

    #[tokio::test]
    async fn test_validate_auth_other_methods() {
        let storage = MockResourceStorage::new();
        let methods = vec![Method::PUT, Method::PATCH, Method::HEAD, Method::OPTIONS];

        for method in methods {
            let result = storage.validate_auth(b"", "", "/path", &method).await;
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), false);
        }
    }

    // Test encrypted method
    #[tokio::test]
    async fn test_encrypted_get_method() {
        let storage = MockResourceStorage::new();
        let method = Method::GET;

        let result = storage.encrypted(b"", "", "/path", &method).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[tokio::test]
    async fn test_encrypted_post_method() {
        let storage = MockResourceStorage::new();
        let method = Method::POST;

        let result = storage.encrypted(b"", "", "/path", &method).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false);
    }

    #[tokio::test]
    async fn test_encrypted_delete_method() {
        let storage = MockResourceStorage::new();
        let method = Method::DELETE;

        let result = storage.encrypted(b"", "", "/path", &method).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false);
    }

    #[tokio::test]
    async fn test_encrypted_other_methods() {
        let storage = MockResourceStorage::new();
        let methods = vec![Method::PUT, Method::PATCH, Method::HEAD, Method::OPTIONS];

        for method in methods {
            let result = storage.encrypted(b"", "", "/path", &method).await;
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), false);
        }
    }

    // Edge case tests
    #[tokio::test]
    async fn test_handle_empty_path() {
        let storage = MockResourceStorage::new();
        let path = "/";
        let method = Method::POST;

        let result = storage.handle(b"data", "", path, &method).await;
        assert!(result.is_err()); // Should fail to parse ResourceDesc from empty string
    }

    #[tokio::test]
    async fn test_handle_resources_path_exact_match() {
        let storage = MockResourceStorage::new();
        let path = "/resources";
        let method = Method::GET;

        let result = storage.handle(b"", "", path, &method).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_resources_path_with_extra() {
        let storage = MockResourceStorage::new();
        let path = "/resources/extra";
        let method = Method::GET;

        // This should not be treated as a list request, but as a regular resource
        let result = storage.handle(b"", "", path, &method).await;
        assert!(result.is_err()); // Should fail because resource doesn't exist
    }

    #[tokio::test]
    async fn test_handle_large_body() {
        let storage = MockResourceStorage::new();
        let large_body = vec![0u8; 1024 * 1024]; // 1MB
        let path = "/repo/type/large";
        let method = Method::POST;

        let result = storage.handle(&large_body, "", path, &method).await;
        assert!(result.is_ok());

        // Verify we can get it back
        let get_result = storage.handle(b"", "", path, &Method::GET).await;
        assert!(get_result.is_ok());
        assert_eq!(get_result.unwrap(), large_body);
    }

    #[tokio::test]
    async fn test_handle_special_characters_in_path() {
        let storage = MockResourceStorage::new();
        let path = "/repo-name/type_name/tag.version";
        let method = Method::POST;

        let result = storage.handle(b"data", "", path, &method).await;
        // This depends on ResourceDesc::try_from implementation
        // We test that the method handles the path properly
        assert!(result.is_ok() || result.is_err()); // Either should be handled gracefully
    }

    // Integration-style tests
    #[tokio::test]
    async fn test_complete_resource_lifecycle() {
        let storage = MockResourceStorage::new();
        let path = "/my-repo/secret/v1.0";
        let test_data = b"sensitive-data";

        // Create resource
        let create_result = storage.handle(test_data, "", path, &Method::POST).await;
        assert!(create_result.is_ok());
        assert_eq!(create_result.unwrap(), Vec::<u8>::new());

        // Read resource
        let read_result = storage.handle(b"", "", path, &Method::GET).await;
        assert!(read_result.is_ok());
        assert_eq!(read_result.unwrap(), test_data);

        // List resources
        let list_result = storage.handle(b"", "", "/resources", &Method::GET).await;
        assert!(list_result.is_ok());
        let resources: Vec<ResourceDesc> = serde_json::from_slice(&list_result.unwrap()).unwrap();
        assert!(resources.iter().any(|r| r.repository_name == "my-repo" && r.resource_type == "secret" && r.resource_tag == "v1.0"));

        // Delete resource
        let delete_result = storage.handle(b"", "", path, &Method::DELETE).await;
        assert!(delete_result.is_ok());

        // Verify deletion
        let read_after_delete = storage.handle(b"", "", path, &Method::GET).await;
        assert!(read_after_delete.is_err());
    }

    // Test concurrent operations
    #[tokio::test]
    async fn test_concurrent_operations() {
        let storage = std::sync::Arc::new(MockResourceStorage::new());
        let mut handles = vec![];

        // Spawn multiple concurrent operations
        for i in 0..10 {
            let storage_clone = storage.clone();
            let handle = tokio::spawn(async move {
                let path = format!("/repo{}/type/tag", i);
                let data = format!("data-{}", i).into_bytes();
                
                // Set resource
                let set_result = storage_clone.handle(&data, "", &path, &Method::POST).await;
                
                // Get resource
                let get_result = storage_clone.handle(b"", "", &path, &Method::GET).await;
                
                // Delete resource
                let delete_result = storage_clone.handle(b"", "", &path, &Method::DELETE).await;
                
                (set_result, get_result, delete_result)
            });
            handles.push(handle);
        }

        // Wait for all operations to complete
        for handle in handles {
            let (set_result, get_result, delete_result) = handle.await.unwrap();
            assert!(set_result.is_ok());
            assert!(get_result.is_ok());
            assert!(delete_result.is_ok());
        }
    }
}
