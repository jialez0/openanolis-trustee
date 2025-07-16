// Copyright (c) 2025 IBM
//
// SPDX-License-Identifier: Apache-2.0
//
// Helpers for building a client for the RVPS

use anyhow::*;

use crate::rvps_api::reference::{
    reference_value_provider_service_client::ReferenceValueProviderServiceClient,
    ReferenceValueDeleteRequest, ReferenceValueQueryRequest, ReferenceValueRegisterRequest,
};

pub async fn register(address: String, message: String) -> Result<()> {
    let mut client = ReferenceValueProviderServiceClient::connect(address).await?;
    let req = tonic::Request::new(ReferenceValueRegisterRequest { message });

    client.register_reference_value(req).await?;

    Ok(())
}

pub async fn query(address: String) -> Result<String> {
    let mut client = ReferenceValueProviderServiceClient::connect(address).await?;
    let req = tonic::Request::new(ReferenceValueQueryRequest {});

    let rvs = client
        .query_reference_value(req)
        .await?
        .into_inner()
        .reference_value_results;

    Ok(rvs)
}

pub async fn delete(address: String, name: String) -> Result<()> {
    let mut client = ReferenceValueProviderServiceClient::connect(address).await?;
    let req = tonic::Request::new(ReferenceValueDeleteRequest { name });

    client.delete_reference_value(req).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rvps_api::reference::{
        reference_value_provider_service_server::{ReferenceValueProviderService, ReferenceValueProviderServiceServer},
        ReferenceValueQueryResponse, ReferenceValueRegisterResponse, ReferenceValueDeleteResponse,
    };
    use tonic::{Request, Response, Status};
    use tonic::transport::Server;
    use async_trait::async_trait;
    use std::result::Result as StdResult;
    use tokio::net::TcpListener;
    use std::net::SocketAddr;
    use std::time::Duration;

    // 获取可用端口的辅助函数
    async fn get_available_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    }

    // Mock服务实现
    #[derive(Debug, Default, Clone)]
    struct MockReferenceValueProviderService {
        should_fail_register: bool,
        should_fail_query: bool,
        should_fail_delete: bool,
        query_response: String,
    }

    impl MockReferenceValueProviderService {
        fn new() -> Self {
            Self {
                should_fail_register: false,
                should_fail_query: false,
                should_fail_delete: false,
                query_response: "test_results".to_string(),
            }
        }

        fn with_query_response(mut self, response: String) -> Self {
            self.query_response = response;
            self
        }

        fn with_register_failure(mut self) -> Self {
            self.should_fail_register = true;
            self
        }

        fn with_query_failure(mut self) -> Self {
            self.should_fail_query = true;
            self
        }

        fn with_delete_failure(mut self) -> Self {
            self.should_fail_delete = true;
            self
        }
    }

    #[async_trait]
    impl ReferenceValueProviderService for MockReferenceValueProviderService {
        async fn query_reference_value(
            &self,
            _request: Request<ReferenceValueQueryRequest>,
        ) -> StdResult<Response<ReferenceValueQueryResponse>, Status> {
            if self.should_fail_query {
                return Err(Status::internal("Mock query error"));
            }
            
            let response = ReferenceValueQueryResponse {
                reference_value_results: self.query_response.clone(),
            };
            StdResult::Ok(Response::new(response))
        }

        async fn register_reference_value(
            &self,
            _request: Request<ReferenceValueRegisterRequest>,
        ) -> StdResult<Response<ReferenceValueRegisterResponse>, Status> {
            if self.should_fail_register {
                return Err(Status::invalid_argument("Mock register error"));
            }
            
            let response = ReferenceValueRegisterResponse {};
            StdResult::Ok(Response::new(response))
        }

        async fn delete_reference_value(
            &self,
            _request: Request<ReferenceValueDeleteRequest>,
        ) -> StdResult<Response<ReferenceValueDeleteResponse>, Status> {
            if self.should_fail_delete {
                return Err(Status::not_found("Mock delete error"));
            }
            
            let response = ReferenceValueDeleteResponse {};
            StdResult::Ok(Response::new(response))
        }
    }

    // 启动测试服务器的辅助函数
    async fn start_mock_server(service: MockReferenceValueProviderService) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let port = get_available_port().await;
        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        
        let server = ReferenceValueProviderServiceServer::new(service);
        
        let handle = tokio::spawn(async move {
            Server::builder()
                .add_service(server)
                .serve(addr)
                .await
                .unwrap();
        });
        
        // 等待服务器启动
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        (addr, handle)
    }

    // 测试 register 函数成功路径 - 覆盖第14-20行
    #[tokio::test]
    async fn test_register_success() {
        let service = MockReferenceValueProviderService::new();
        let (addr, _handle) = start_mock_server(service).await;
        let address = format!("http://{}", addr);
        let message = "test_message".to_string();

        // 测试第14行：函数调用
        // 测试第15行：ReferenceValueProviderServiceClient::connect调用
        // 测试第16行：创建Request
        // 测试第18行：client.register_reference_value调用
        // 测试第20行：返回Ok(())
        let result = register(address, message).await;
        
        assert!(result.is_ok());
    }

    // 测试 register 函数连接失败 - 覆盖第14-16行
    #[tokio::test]
    async fn test_register_connection_failure() {
        let address = "http://127.0.0.1:99999".to_string(); // 无效地址
        let message = "test_message".to_string();

        // 测试第14行：函数调用
        // 测试第15行：ReferenceValueProviderServiceClient::connect失败
        let result = register(address, message).await;
        
        assert!(result.is_err());
    }

    // 测试 register 函数服务调用失败 - 覆盖第14-20行
    #[tokio::test]
    async fn test_register_service_failure() {
        let service = MockReferenceValueProviderService::new().with_register_failure();
        let (addr, _handle) = start_mock_server(service).await;
        let address = format!("http://{}", addr);
        let message = "test_message".to_string();

        // 测试第14行：函数调用
        // 测试第15行：ReferenceValueProviderServiceClient::connect成功
        // 测试第16行：创建Request成功
        // 测试第18行：client.register_reference_value失败
        let result = register(address, message).await;
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Mock register error"));
    }

    // 测试 query 函数成功路径 - 覆盖第23-31行
    #[tokio::test]
    async fn test_query_success() {
        let expected_response = "test_query_results".to_string();
        let service = MockReferenceValueProviderService::new()
            .with_query_response(expected_response.clone());
        let (addr, _handle) = start_mock_server(service).await;
        let address = format!("http://{}", addr);

        // 测试第23行：函数调用
        // 测试第24行：ReferenceValueProviderServiceClient::connect调用
        // 测试第25行：创建Request
        // 测试第27-31行：client.query_reference_value调用和结果处理
        let result = query(address).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_response);
    }

    // 测试 query 函数连接失败 - 覆盖第23-25行
    #[tokio::test]
    async fn test_query_connection_failure() {
        let address = "http://127.0.0.1:99998".to_string(); // 无效地址

        // 测试第23行：函数调用
        // 测试第24行：ReferenceValueProviderServiceClient::connect失败
        let result = query(address).await;
        
        assert!(result.is_err());
    }

    // 测试 query 函数服务调用失败 - 覆盖第23-31行
    #[tokio::test]
    async fn test_query_service_failure() {
        let service = MockReferenceValueProviderService::new().with_query_failure();
        let (addr, _handle) = start_mock_server(service).await;
        let address = format!("http://{}", addr);

        // 测试第23行：函数调用
        // 测试第24行：ReferenceValueProviderServiceClient::connect成功
        // 测试第25行：创建Request成功
        // 测试第27行：client.query_reference_value失败
        let result = query(address).await;
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Mock query error"));
    }

    // 测试 delete 函数成功路径 - 覆盖第33-42行
    #[tokio::test]
    async fn test_delete_success() {
        let service = MockReferenceValueProviderService::new();
        let (addr, _handle) = start_mock_server(service).await;
        let address = format!("http://{}", addr);
        let name = "test_name".to_string();

        // 测试第33行：函数调用
        // 测试第36行：ReferenceValueProviderServiceClient::connect调用
        // 测试第37行：创建Request
        // 测试第40行：client.delete_reference_value调用
        // 测试第42行：返回Ok(())
        let result = delete(address, name).await;
        
        assert!(result.is_ok());
    }

    // 测试 delete 函数连接失败 - 覆盖第33-38行
    #[tokio::test]
    async fn test_delete_connection_failure() {
        let address = "http://127.0.0.1:99997".to_string(); // 无效地址
        let name = "test_name".to_string();

        // 测试第33行：函数调用
        // 测试第36行：ReferenceValueProviderServiceClient::connect失败
        let result = delete(address, name).await;
        
        assert!(result.is_err());
    }

    // 测试 delete 函数服务调用失败 - 覆盖第33-42行
    #[tokio::test]
    async fn test_delete_service_failure() {
        let service = MockReferenceValueProviderService::new().with_delete_failure();
        let (addr, _handle) = start_mock_server(service).await;
        let address = format!("http://{}", addr);
        let name = "test_name".to_string();

        // 测试第33行：函数调用
        // 测试第36行：ReferenceValueProviderServiceClient::connect成功
        // 测试第37行：创建Request成功
        // 测试第40行：client.delete_reference_value失败
        let result = delete(address, name).await;
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Mock delete error"));
    }

    // 测试空消息的 register - 覆盖第14-20行
    #[tokio::test]
    async fn test_register_empty_message() {
        let service = MockReferenceValueProviderService::new();
        let (addr, _handle) = start_mock_server(service).await;
        let address = format!("http://{}", addr);
        let message = "".to_string(); // 空消息

        // 测试第16行：创建带空消息的Request
        let result = register(address, message).await;
        
        assert!(result.is_ok()); // Mock服务不验证消息内容
    }

    // 测试空名称的 delete - 覆盖第33-42行
    #[tokio::test]
    async fn test_delete_empty_name() {
        let service = MockReferenceValueProviderService::new();
        let (addr, _handle) = start_mock_server(service).await;
        let address = format!("http://{}", addr);
        let name = "".to_string(); // 空名称

        // 测试第37行：创建带空名称的Request
        let result = delete(address, name).await;
        
        assert!(result.is_ok()); // Mock服务不验证名称内容
    }

    // 综合测试：测试所有函数的完整流程
    #[tokio::test]
    async fn test_complete_client_flow() {
        let service = MockReferenceValueProviderService::new()
            .with_query_response("flow_test_results".to_string());
        let (addr, _handle) = start_mock_server(service).await;
        let address = format!("http://{}", addr);

        // 1. 测试注册 - 覆盖第14-20行
        let register_result = register(address.clone(), "test_message".to_string()).await;
        assert!(register_result.is_ok());

        // 2. 测试查询 - 覆盖第23-31行
        let query_result = query(address.clone()).await;
        assert!(query_result.is_ok());
        assert_eq!(query_result.unwrap(), "flow_test_results");

        // 3. 测试删除 - 覆盖第33-42行
        let delete_result = delete(address, "test_name".to_string()).await;
        assert!(delete_result.is_ok());
    }

    // 测试各种错误情况下的错误传播
    #[tokio::test]
    async fn test_error_propagation() {
        // 测试各种gRPC错误是否正确传播
        let invalid_address = "invalid://address".to_string();
        
        // register 错误传播 - 覆盖第14-20行
        let register_result = register(invalid_address.clone(), "message".to_string()).await;
        assert!(register_result.is_err());
        
        // query 错误传播 - 覆盖第23-31行
        let query_result = query(invalid_address.clone()).await;
        assert!(query_result.is_err());
        
        // delete 错误传播 - 覆盖第33-42行
        let delete_result = delete(invalid_address, "name".to_string()).await;
        assert!(delete_result.is_err());
    }

    // 测试Request结构体的创建
    #[test]
    fn test_request_creation() {
        // 测试第16行：ReferenceValueRegisterRequest创建
        let register_req = ReferenceValueRegisterRequest {
            message: "test".to_string(),
        };
        assert_eq!(register_req.message, "test");

        // 测试第25行：ReferenceValueQueryRequest创建  
        let _query_req = ReferenceValueQueryRequest {};
        // Query request 是空结构体，只需验证能创建

        // 测试第37行：ReferenceValueDeleteRequest创建
        let delete_req = ReferenceValueDeleteRequest {
            name: "test_name".to_string(),
        };
        assert_eq!(delete_req.name, "test_name");
    }

    // 测试不同的连接地址格式
    #[tokio::test]
    async fn test_different_address_formats() {
        // 测试不同的地址格式是否都能正确处理连接错误
        let addresses = vec![
            "".to_string(),
            "invalid".to_string(), 
            "http://".to_string(),
            "https://localhost:99999".to_string(),
        ];

        for address in addresses {
            // 每个函数都应该正确处理无效地址
            let register_result = register(address.clone(), "msg".to_string()).await;
            let query_result = query(address.clone()).await;
            let delete_result = delete(address.clone(), "name".to_string()).await;
            
            // 所有调用都应该失败，但不应该panic
            assert!(register_result.is_err());
            assert!(query_result.is_err());
            assert!(delete_result.is_err());
        }
    }
}
