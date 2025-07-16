// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse};
use anyhow::{anyhow, bail, Context};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use kbs_types::{Attestation, Challenge, Request, Tee};
use lazy_static::lazy_static;
use log::{debug, info};
use rand::{thread_rng, Rng};
use semver::{BuildMetadata, Prerelease, Version, VersionReq};
use serde::Deserialize;
use serde_json::json;

use crate::attestation::session::KBS_SESSION_ID;

use super::{
    config::{AttestationConfig, AttestationServiceConfig},
    session::{SessionMap, SessionStatus},
    Error, Result,
};

static KBS_MAJOR_VERSION: u64 = 0;
static KBS_MINOR_VERSION: u64 = 1;
static KBS_PATCH_VERSION: u64 = 0;

lazy_static! {
    static ref VERSION_REQ: VersionReq = {
        let kbs_version = Version {
            major: KBS_MAJOR_VERSION,
            minor: KBS_MINOR_VERSION,
            patch: KBS_PATCH_VERSION,
            pre: Prerelease::EMPTY,
            build: BuildMetadata::EMPTY,
        };

        VersionReq::parse(&format!("={kbs_version}")).unwrap()
    };
}

/// Number of bytes in a nonce.
const NONCE_SIZE_BYTES: usize = 32;

/// Create a nonce and return as a base-64 encoded string.
pub async fn make_nonce() -> anyhow::Result<String> {
    let mut nonce: Vec<u8> = vec![0; NONCE_SIZE_BYTES];

    thread_rng()
        .try_fill(&mut nonce[..])
        .map_err(anyhow::Error::from)?;

    Ok(STANDARD.encode(&nonce))
}

pub(crate) async fn generic_generate_challenge(
    _tee: Tee,
    _tee_parameters: String,
) -> anyhow::Result<Challenge> {
    let nonce = make_nonce().await?;

    Ok(Challenge {
        nonce,
        extra_params: String::new(),
    })
}

/// Interface for Attestation Services.
///
/// Attestation Service implementations should implement this interface.
#[async_trait]
pub trait Attest: Send + Sync {
    /// Set Attestation Policy
    async fn set_policy(&self, _policy_id: &str, _policy: &str) -> anyhow::Result<()> {
        Err(anyhow!("Set Policy API is unimplemented"))
    }

    /// Get Attestation Policy
    async fn get_policy(&self, _policy_id: &str) -> anyhow::Result<String> {
        Err(anyhow!("Get Policy API is unimplemented"))
    }

    /// List Attestation Policies
    async fn list_policies(&self) -> anyhow::Result<HashMap<String, String>> {
        Err(anyhow!("List Policies API is unimplemented"))
    }

    /// Delete Attestation Policy
    async fn delete_policy(&self, _policy_id: &str) -> anyhow::Result<()> {
        Err(anyhow!("Delete Policy API is unimplemented"))
    }

    /// Verify Attestation Evidence
    /// Return Attestation Results Token
    async fn verify(&self, tee: Tee, nonce: &str, attestation: &str) -> anyhow::Result<String>;

    /// generate the Challenge to pass to attester based on Tee and nonce
    async fn generate_challenge(
        &self,
        tee: Tee,
        tee_parameters: String,
    ) -> anyhow::Result<Challenge> {
        generic_generate_challenge(tee, tee_parameters).await
    }
}

/// Attestation Service
#[derive(Clone)]
pub struct AttestationService {
    /// Attestation Module
    inner: Arc<dyn Attest>,

    /// A concurrent safe map to keep status of RCAR status
    session_map: Arc<SessionMap>,

    /// Maximum session expiration time.
    timeout: i64,
}

#[derive(Deserialize, Debug, serde::Serialize)]
pub struct SetPolicyInput {
    policy_id: String,
    policy: String,
}

impl AttestationService {
    pub async fn new(config: AttestationConfig) -> Result<Self> {
        let inner = match config.attestation_service {
            #[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
            AttestationServiceConfig::CoCoASBuiltIn(cfg) => {
                let built_in_as = super::coco::builtin::BuiltInCoCoAs::new(cfg)
                    .await
                    .map_err(|e| Error::AttestationServiceInitialization { source: e })?;
                Arc::new(built_in_as) as _
            }
            #[cfg(feature = "coco-as-grpc")]
            AttestationServiceConfig::CoCoASGrpc(cfg) => {
                let grpc_coco_as = super::coco::grpc::GrpcClientPool::new(cfg)
                    .await
                    .map_err(|e| Error::AttestationServiceInitialization { source: e })?;
                Arc::new(grpc_coco_as) as _
            }
        };

        let session_map = Arc::new(SessionMap::new());

        tokio::spawn({
            let session_map_clone = session_map.clone();
            async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    session_map_clone
                        .sessions
                        .retain_async(|_, v| !v.is_expired())
                        .await;
                }
            }
        });
        Ok(Self {
            inner,
            timeout: config.timeout,
            session_map,
        })
    }

    pub async fn set_policy(&self, request: &[u8]) -> Result<()> {
        self.__set_policy(request)
            .await
            .map_err(|e| Error::SetPolicy { source: e })
    }

    async fn __set_policy(&self, request: &[u8]) -> anyhow::Result<()> {
        let input: SetPolicyInput =
            serde_json::from_slice(request).context("parse set policy request")?;
        self.inner.set_policy(&input.policy_id, &input.policy).await
    }

    pub async fn get_policy(&self, policy_id: &str) -> Result<String> {
        self.inner
            .get_policy(policy_id)
            .await
            .map_err(|e| Error::GetPolicy { source: e })
    }

    pub async fn list_policies(&self) -> Result<HashMap<String, String>> {
        self.inner
            .list_policies()
            .await
            .map_err(|e| Error::ListPolicies { source: e })
    }

    pub async fn delete_policy(&self, policy_id: &str) -> Result<()> {
        self.inner
            .delete_policy(policy_id)
            .await
            .map_err(|e| Error::DeletePolicy { source: e })
    }

    pub async fn auth(&self, request: &[u8]) -> Result<HttpResponse> {
        self.__auth(request)
            .await
            .map_err(|e| Error::RcarAuthFailed { source: e })
    }

    async fn __auth(&self, request: &[u8]) -> anyhow::Result<HttpResponse> {
        let request: Request = serde_json::from_slice(request).context("deserialize Request")?;
        let version = Version::parse(&request.version).context("failed to parse KBS version")?;
        if !VERSION_REQ.matches(&version) {
            bail!(
                "KBS Client Protocol Version Mismatch: expect {} while the request is {}",
                *VERSION_REQ,
                request.version
            );
        }

        let challenge = self
            .inner
            .generate_challenge(request.tee, request.extra_params.clone())
            .await
            .context("Attestation Service generate challenge failed")?;

        let session = SessionStatus::auth(request, self.timeout, challenge);

        let response = HttpResponse::Ok()
            .cookie(session.cookie())
            .json(session.challenge());

        self.session_map.insert(session);

        Ok(response)
    }

    pub async fn attest(&self, attestation: &[u8], request: HttpRequest) -> Result<HttpResponse> {
        self.__attest(attestation, request)
            .await
            .map_err(|e| Error::RcarAttestFailed { source: e })
    }

    async fn __attest(
        &self,
        attestation: &[u8],
        request: HttpRequest,
    ) -> anyhow::Result<HttpResponse> {
        let cookie = request.cookie(KBS_SESSION_ID).context("cookie not found")?;

        let session_id = cookie.value();

        let attestation: Attestation =
            serde_json::from_slice(attestation).context("deserialize Attestation")?;
        let (tee, nonce) = {
            let session = self
                .session_map
                .sessions
                .get_async(session_id)
                .await
                .ok_or(anyhow!("No cookie found"))?;
            let session = session.get();

            debug!("Session ID {}", session.id());

            if session.is_expired() {
                bail!("session expired.");
            }

            if let SessionStatus::Attested { token, .. } = session {
                debug!(
                    "Session {} is already attested. Skip attestation and return the old token",
                    session.id()
                );
                let body = serde_json::to_string(&json!({
                    "token": token,
                }))
                .context("Serialize token failed")?;

                return Ok(HttpResponse::Ok()
                    .cookie(session.cookie())
                    .content_type("application/json")
                    .body(body));
            }

            let attestation_str = serde_json::to_string_pretty(&attestation)
                .context("Failed to serialize Attestation")?;
            debug!("Attestation: {attestation_str}");

            (session.request().tee, session.challenge().nonce.to_string())
        };

        let attestation_str =
            serde_json::to_string(&attestation).context("serialize attestation failed")?;
        let token = self
            .inner
            .verify(tee, &nonce, &attestation_str)
            .await
            .context("verify TEE evidence failed")?;

        let mut session = self
            .session_map
            .sessions
            .get_async(session_id)
            .await
            .ok_or(anyhow!("session not found"))?;
        let session = session.get_mut();

        let body = serde_json::to_string(&json!({
            "token": token,
        }))
        .context("Serialize token failed")?;

        session.attest(token);

        Ok(HttpResponse::Ok()
            .cookie(session.cookie())
            .content_type("application/json")
            .body(body))
    }

    pub async fn get_attest_token_from_session(
        &self,
        request: &HttpRequest,
    ) -> anyhow::Result<String> {
        let cookie = request
            .cookie(KBS_SESSION_ID)
            .context("KBS session cookie not found")?;

        let session = self
            .session_map
            .sessions
            .get_async(cookie.value())
            .await
            .context("session not found")?;

        let session = session.get();

        info!("Cookie {} request to get resource", session.id());

        if session.is_expired() {
            bail!("The session is expired");
        }

        let SessionStatus::Attested { token, .. } = session else {
            bail!("The session is not authorized");
        };

        Ok(token.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;
    use std::sync::Mutex;
    use tokio::time::{sleep, Duration};

    // Mock implementation of Attest trait for testing
    #[derive(Debug, Clone)]
    struct MockAttest {
        policies: Arc<Mutex<HashMap<String, String>>>,
        verify_result: Arc<Mutex<Option<std::result::Result<String, String>>>>,
        challenge_result: Arc<Mutex<Option<std::result::Result<Challenge, String>>>>,
        should_fail_policy_ops: Arc<Mutex<bool>>,
    }

    impl MockAttest {
        fn new() -> Self {
            Self {
                policies: Arc::new(Mutex::new(HashMap::new())),
                verify_result: Arc::new(Mutex::new(Some(Ok("test-token".to_string())))),
                challenge_result: Arc::new(Mutex::new(Some(Ok(Challenge {
                    nonce: "test-nonce".to_string(),
                    extra_params: "test-params".to_string(),
                })))),
                should_fail_policy_ops: Arc::new(Mutex::new(false)),
            }
        }

        fn set_verify_result(&self, result: std::result::Result<String, String>) {
            *self.verify_result.lock().unwrap() = Some(result);
        }

        fn set_challenge_result(&self, result: std::result::Result<Challenge, String>) {
            *self.challenge_result.lock().unwrap() = Some(result);
        }

        fn set_policy_ops_failure(&self, should_fail: bool) {
            *self.should_fail_policy_ops.lock().unwrap() = should_fail;
        }
    }

    #[async_trait]
    impl Attest for MockAttest {
        async fn set_policy(&self, policy_id: &str, policy: &str) -> anyhow::Result<()> {
            if *self.should_fail_policy_ops.lock().unwrap() {
                return Err(anyhow::anyhow!("Mock set policy failure"));
            }
            self.policies
                .lock()
                .unwrap()
                .insert(policy_id.to_string(), policy.to_string());
            Ok(())
        }

        async fn get_policy(&self, policy_id: &str) -> anyhow::Result<String> {
            if *self.should_fail_policy_ops.lock().unwrap() {
                return Err(anyhow::anyhow!("Mock get policy failure"));
            }
            self.policies
                .lock()
                .unwrap()
                .get(policy_id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("Policy not found"))
        }

        async fn list_policies(&self) -> anyhow::Result<HashMap<String, String>> {
            if *self.should_fail_policy_ops.lock().unwrap() {
                return Err(anyhow::anyhow!("Mock list policies failure"));
            }
            Ok(self.policies.lock().unwrap().clone())
        }

        async fn delete_policy(&self, policy_id: &str) -> anyhow::Result<()> {
            if *self.should_fail_policy_ops.lock().unwrap() {
                return Err(anyhow::anyhow!("Mock delete policy failure"));
            }
            self.policies.lock().unwrap().remove(policy_id);
            Ok(())
        }

        async fn verify(&self, _tee: Tee, _nonce: &str, _attestation: &str) -> anyhow::Result<String> {
            let result = self.verify_result.lock().unwrap().take().unwrap_or(Ok("test-token".to_string()));
            match result {
                Ok(token) => Ok(token),
                Err(msg) => Err(anyhow::anyhow!(msg)),
            }
        }

        async fn generate_challenge(
            &self,
            _tee: Tee,
            _tee_parameters: String,
        ) -> anyhow::Result<Challenge> {
            let result = self.challenge_result.lock().unwrap().take().unwrap_or(Ok(Challenge {
                nonce: "test-nonce".to_string(),
                extra_params: "test-params".to_string(),
            }));
            match result {
                Ok(challenge) => Ok(challenge),
                Err(msg) => Err(anyhow::anyhow!(msg)),
            }
        }
    }

    // Helper function to create a test AttestationService
    async fn create_test_service() -> AttestationService {
        let mock_attest = Arc::new(MockAttest::new());
        let session_map = Arc::new(SessionMap::new());
        
        AttestationService {
            inner: mock_attest,
            session_map,
            timeout: 5,
        }
    }

    // Helper function to create a test AttestationService with custom mock
    async fn create_test_service_with_mock(mock: Arc<MockAttest>) -> AttestationService {
        let session_map = Arc::new(SessionMap::new());
        
        AttestationService {
            inner: mock,
            session_map,
            timeout: 5,
        }
    }

    #[tokio::test]
    async fn test_make_nonce() {
        const BITS_PER_BYTE: usize = 8;

        /// A base-64 encoded value is this many bits in length.
        const BASE64_BITS_CHUNK: usize = 6;

        /// Number of bytes that base64 encoding requires the result to align on.
        const BASE64_ROUNDING_MULTIPLE: usize = 4;

        /// The nominal base64 encoded length.
        const BASE64_NONCE_LENGTH_UNROUNDED_BYTES: usize =
            (NONCE_SIZE_BYTES * BITS_PER_BYTE) / BASE64_BITS_CHUNK;

        /// The actual base64 encoded length is rounded up to the specified multiple.
        const EXPECTED_LENGTH_BYTES: usize =
            BASE64_NONCE_LENGTH_UNROUNDED_BYTES.next_multiple_of(BASE64_ROUNDING_MULTIPLE);

        // Number of nonce tests to run (arbitrary)
        let nonce_count = 13;

        let mut nonces = vec![];

        for _ in 0..nonce_count {
            let nonce = make_nonce().await.unwrap();

            assert_eq!(nonce.len(), EXPECTED_LENGTH_BYTES);

            let found = nonces.contains(&nonce);

            // The nonces should be unique
            assert_eq!(found, false);

            nonces.push(nonce);
        }
    }

    #[tokio::test]
    async fn test_generic_generate_challenge() {
        let tee = Tee::Tdx;
        let params = "test-params".to_string();
        
        let challenge = generic_generate_challenge(tee, params).await.unwrap();
        
        assert!(!challenge.nonce.is_empty());
        assert_eq!(challenge.extra_params, "");
        
        // Verify nonce is valid base64
        let decoded = STANDARD.decode(&challenge.nonce);
        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap().len(), NONCE_SIZE_BYTES);
    }

    #[tokio::test]
    async fn test_version_req_creation() {
        // Test that the VERSION_REQ is created correctly
        let expected_version = format!("={}.{}.{}", KBS_MAJOR_VERSION, KBS_MINOR_VERSION, KBS_PATCH_VERSION);
        assert_eq!(VERSION_REQ.to_string(), expected_version);
    }

    #[tokio::test]
    async fn test_set_policy_success() {
        let service = create_test_service().await;
        let input = SetPolicyInput {
            policy_id: "test-policy".to_string(),
            policy: "test-policy-content".to_string(),
        };
        let request = serde_json::to_vec(&input).unwrap();
        
        let result = service.set_policy(&request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_set_policy_invalid_json() {
        let service = create_test_service().await;
        let invalid_json = b"invalid json";
        
        let result = service.set_policy(invalid_json).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_set_policy_failure() {
        let mock = Arc::new(MockAttest::new());
        mock.set_policy_ops_failure(true);
        let service = create_test_service_with_mock(mock).await;
        
        let input = SetPolicyInput {
            policy_id: "test-policy".to_string(),
            policy: "test-policy-content".to_string(),
        };
        let request = serde_json::to_vec(&input).unwrap();
        
        let result = service.set_policy(&request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_policy_success() {
        let mock = Arc::new(MockAttest::new());
        // First set a policy
        mock.set_policy("test-policy", "test-content").await.unwrap();
        let service = create_test_service_with_mock(mock).await;
        
        let result = service.get_policy("test-policy").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test-content");
    }

    #[tokio::test]
    async fn test_get_policy_not_found() {
        let service = create_test_service().await;
        
        let result = service.get_policy("non-existent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_policy_failure() {
        let mock = Arc::new(MockAttest::new());
        mock.set_policy_ops_failure(true);
        let service = create_test_service_with_mock(mock).await;
        
        let result = service.get_policy("test-policy").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_policies_success() {
        let mock = Arc::new(MockAttest::new());
        mock.set_policy("policy1", "content1").await.unwrap();
        mock.set_policy("policy2", "content2").await.unwrap();
        let service = create_test_service_with_mock(mock).await;
        
        let result = service.list_policies().await;
        assert!(result.is_ok());
        let policies = result.unwrap();
        assert_eq!(policies.len(), 2);
        assert!(policies.contains_key("policy1"));
        assert!(policies.contains_key("policy2"));
    }

    #[tokio::test]
    async fn test_list_policies_failure() {
        let mock = Arc::new(MockAttest::new());
        mock.set_policy_ops_failure(true);
        let service = create_test_service_with_mock(mock).await;
        
        let result = service.list_policies().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_policy_success() {
        let mock = Arc::new(MockAttest::new());
        mock.set_policy("test-policy", "test-content").await.unwrap();
        let service = create_test_service_with_mock(mock.clone()).await;
        
        // Verify policy exists
        let get_result = service.get_policy("test-policy").await;
        assert!(get_result.is_ok());
        
        // Delete policy
        let delete_result = service.delete_policy("test-policy").await;
        assert!(delete_result.is_ok());
        
        // Verify policy is deleted
        let get_after_delete = service.get_policy("test-policy").await;
        assert!(get_after_delete.is_err());
    }

    #[tokio::test]
    async fn test_delete_policy_failure() {
        let mock = Arc::new(MockAttest::new());
        mock.set_policy_ops_failure(true);
        let service = create_test_service_with_mock(mock).await;
        
        let result = service.delete_policy("test-policy").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_auth_success() {
        let service = create_test_service().await;
        let request = Request {
            version: format!("{}.{}.{}", KBS_MAJOR_VERSION, KBS_MINOR_VERSION, KBS_PATCH_VERSION),
            tee: Tee::Tdx,
            extra_params: "test-params".to_string(),
        };
        let request_bytes = serde_json::to_vec(&request).unwrap();
        
        let result = service.auth(&request_bytes).await;
        assert!(result.is_ok());
        
        let response = result.unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_auth_invalid_json() {
        let service = create_test_service().await;
        let invalid_json = b"invalid json";
        
        let result = service.auth(invalid_json).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_auth_version_mismatch() {
        let service = create_test_service().await;
        let request = Request {
            version: "999.999.999".to_string(),
            tee: Tee::Tdx,
            extra_params: "test-params".to_string(),
        };
        let request_bytes = serde_json::to_vec(&request).unwrap();
        
        let result = service.auth(&request_bytes).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_auth_invalid_version_format() {
        let service = create_test_service().await;
        let request = Request {
            version: "invalid-version".to_string(),
            tee: Tee::Tdx,
            extra_params: "test-params".to_string(),
        };
        let request_bytes = serde_json::to_vec(&request).unwrap();
        
        let result = service.auth(&request_bytes).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_auth_challenge_generation_failure() {
        let mock = Arc::new(MockAttest::new());
        mock.set_challenge_result(Err("Challenge generation failed".to_string()));
        let service = create_test_service_with_mock(mock).await;
        
        let request = Request {
            version: format!("{}.{}.{}", KBS_MAJOR_VERSION, KBS_MINOR_VERSION, KBS_PATCH_VERSION),
            tee: Tee::Tdx,
            extra_params: "test-params".to_string(),
        };
        let request_bytes = serde_json::to_vec(&request).unwrap();
        
        let result = service.auth(&request_bytes).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_attest_success() {
        let service = create_test_service().await;
        
        // First do auth to create a session
        let auth_request = Request {
            version: format!("{}.{}.{}", KBS_MAJOR_VERSION, KBS_MINOR_VERSION, KBS_PATCH_VERSION),
            tee: Tee::Tdx,
            extra_params: "test-params".to_string(),
        };
        let auth_request_bytes = serde_json::to_vec(&auth_request).unwrap();
        let auth_response = service.auth(&auth_request_bytes).await.unwrap();
        
        // Extract session cookie
        let session_cookie = auth_response.headers().get("set-cookie").unwrap();
        let cookie_str = session_cookie.to_str().unwrap();
        let session_id = cookie_str.split('=').nth(1).unwrap().split(';').next().unwrap();
        
        // Create HTTP request with cookie
        let req = TestRequest::default()
            .cookie(actix_web::cookie::Cookie::new(KBS_SESSION_ID, session_id))
            .to_http_request();
        
        // Create a proper test Attestation with correct types
        let test_tee_pubkey = kbs_types::TeePubKey {
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            k_mod: "test_modulus".to_string(),
            k_exp: "test_exponent".to_string(),
        };
        
        let attestation = Attestation {
            tee_pubkey: test_tee_pubkey,
            tee_evidence: "test-evidence-string".to_string(),
        };
        let attestation_bytes = serde_json::to_vec(&attestation).unwrap();
        
        let result = service.attest(&attestation_bytes, req).await;
        assert!(result.is_ok());
        
        let response = result.unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_attest_no_cookie() {
        let service = create_test_service().await;
        let req = TestRequest::default().to_http_request();
        
        let test_tee_pubkey = kbs_types::TeePubKey {
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            k_mod: "test_modulus".to_string(),
            k_exp: "test_exponent".to_string(),
        };
        
        let attestation = Attestation {
            tee_pubkey: test_tee_pubkey,
            tee_evidence: "test-evidence-string".to_string(),
        };
        let attestation_bytes = serde_json::to_vec(&attestation).unwrap();
        
        let result = service.attest(&attestation_bytes, req).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_attest_invalid_session() {
        let service = create_test_service().await;
        let req = TestRequest::default()
            .cookie(actix_web::cookie::Cookie::new(KBS_SESSION_ID, "invalid-session"))
            .to_http_request();
        
        let test_tee_pubkey = kbs_types::TeePubKey {
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            k_mod: "test_modulus".to_string(),
            k_exp: "test_exponent".to_string(),
        };
        
        let attestation = Attestation {
            tee_pubkey: test_tee_pubkey,
            tee_evidence: "test-evidence-string".to_string(),
        };
        let attestation_bytes = serde_json::to_vec(&attestation).unwrap();
        
        let result = service.attest(&attestation_bytes, req).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_attest_invalid_json() {
        let service = create_test_service().await;
        
        // First do auth to create a session
        let auth_request = Request {
            version: format!("{}.{}.{}", KBS_MAJOR_VERSION, KBS_MINOR_VERSION, KBS_PATCH_VERSION),
            tee: Tee::Tdx,
            extra_params: "test-params".to_string(),
        };
        let auth_request_bytes = serde_json::to_vec(&auth_request).unwrap();
        let auth_response = service.auth(&auth_request_bytes).await.unwrap();
        
        // Extract session cookie
        let session_cookie = auth_response.headers().get("set-cookie").unwrap();
        let cookie_str = session_cookie.to_str().unwrap();
        let session_id = cookie_str.split('=').nth(1).unwrap().split(';').next().unwrap();
        
        let req = TestRequest::default()
            .cookie(actix_web::cookie::Cookie::new(KBS_SESSION_ID, session_id))
            .to_http_request();
        
        let invalid_json = b"invalid json";
        
        let result = service.attest(invalid_json, req).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_attest_already_attested() {
        let service = create_test_service().await;
        
        // First do auth to create a session
        let auth_request = Request {
            version: format!("{}.{}.{}", KBS_MAJOR_VERSION, KBS_MINOR_VERSION, KBS_PATCH_VERSION),
            tee: Tee::Tdx,
            extra_params: "test-params".to_string(),
        };
        let auth_request_bytes = serde_json::to_vec(&auth_request).unwrap();
        let auth_response = service.auth(&auth_request_bytes).await.unwrap();
        
        // Extract session cookie
        let session_cookie = auth_response.headers().get("set-cookie").unwrap();
        let cookie_str = session_cookie.to_str().unwrap();
        let session_id = cookie_str.split('=').nth(1).unwrap().split(';').next().unwrap();
        
        let req = TestRequest::default()
            .cookie(actix_web::cookie::Cookie::new(KBS_SESSION_ID, session_id))
            .to_http_request();
        
        let test_tee_pubkey = kbs_types::TeePubKey {
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            k_mod: "test_modulus".to_string(),
            k_exp: "test_exponent".to_string(),
        };
        
        let attestation = Attestation {
            tee_pubkey: test_tee_pubkey.clone(),
            tee_evidence: "test-evidence-string".to_string(),
        };
        let attestation_bytes = serde_json::to_vec(&attestation).unwrap();
        
        // First attestation
        let result1 = service.attest(&attestation_bytes, req.clone()).await;
        assert!(result1.is_ok());
        
        // Second attestation - should return existing token
        let attestation2 = Attestation {
            tee_pubkey: test_tee_pubkey,
            tee_evidence: "test-evidence-string2".to_string(),
        };
        let attestation_bytes2 = serde_json::to_vec(&attestation2).unwrap();
        let result2 = service.attest(&attestation_bytes2, req).await;
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap().status(), 200);
    }

    #[tokio::test]
    async fn test_attest_verification_failure() {
        let mock = Arc::new(MockAttest::new());
        mock.set_verify_result(Err("Verification failed".to_string()));
        let service = create_test_service_with_mock(mock).await;
        
        // First do auth to create a session
        let auth_request = Request {
            version: format!("{}.{}.{}", KBS_MAJOR_VERSION, KBS_MINOR_VERSION, KBS_PATCH_VERSION),
            tee: Tee::Tdx,
            extra_params: "test-params".to_string(),
        };
        let auth_request_bytes = serde_json::to_vec(&auth_request).unwrap();
        let auth_response = service.auth(&auth_request_bytes).await.unwrap();
        
        // Extract session cookie
        let session_cookie = auth_response.headers().get("set-cookie").unwrap();
        let cookie_str = session_cookie.to_str().unwrap();
        let session_id = cookie_str.split('=').nth(1).unwrap().split(';').next().unwrap();
        
        let req = TestRequest::default()
            .cookie(actix_web::cookie::Cookie::new(KBS_SESSION_ID, session_id))
            .to_http_request();
        
        let test_tee_pubkey = kbs_types::TeePubKey {
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            k_mod: "test_modulus".to_string(),
            k_exp: "test_exponent".to_string(),
        };
        
        let attestation = Attestation {
            tee_pubkey: test_tee_pubkey,
            tee_evidence: "test-evidence-string".to_string(),
        };
        let attestation_bytes = serde_json::to_vec(&attestation).unwrap();
        
        let result = service.attest(&attestation_bytes, req).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_attest_token_from_session_success() {
        let service = create_test_service().await;
        
        // First do auth and attest to create an attested session
        let auth_request = Request {
            version: format!("{}.{}.{}", KBS_MAJOR_VERSION, KBS_MINOR_VERSION, KBS_PATCH_VERSION),
            tee: Tee::Tdx,
            extra_params: "test-params".to_string(),
        };
        let auth_request_bytes = serde_json::to_vec(&auth_request).unwrap();
        let auth_response = service.auth(&auth_request_bytes).await.unwrap();
        
        // Extract session cookie
        let session_cookie = auth_response.headers().get("set-cookie").unwrap();
        let cookie_str = session_cookie.to_str().unwrap();
        let session_id = cookie_str.split('=').nth(1).unwrap().split(';').next().unwrap();
        
        let req = TestRequest::default()
            .cookie(actix_web::cookie::Cookie::new(KBS_SESSION_ID, session_id))
            .to_http_request();
        
        let test_tee_pubkey = kbs_types::TeePubKey {
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            k_mod: "test_modulus".to_string(),
            k_exp: "test_exponent".to_string(),
        };
        
        let attestation = Attestation {
            tee_pubkey: test_tee_pubkey,
            tee_evidence: "test-evidence-string".to_string(),
        };
        let attestation_bytes = serde_json::to_vec(&attestation).unwrap();
        
        // Attest
        let _attest_response = service.attest(&attestation_bytes, req.clone()).await.unwrap();
        
        // Get token
        let result = service.get_attest_token_from_session(&req).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test-token");
    }

    #[tokio::test]
    async fn test_get_attest_token_no_cookie() {
        let service = create_test_service().await;
        let req = TestRequest::default().to_http_request();
        
        let result = service.get_attest_token_from_session(&req).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_attest_token_invalid_session() {
        let service = create_test_service().await;
        let req = TestRequest::default()
            .cookie(actix_web::cookie::Cookie::new(KBS_SESSION_ID, "invalid-session"))
            .to_http_request();
        
        let result = service.get_attest_token_from_session(&req).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_attest_token_not_attested() {
        let service = create_test_service().await;
        
        // Only do auth, don't attest
        let auth_request = Request {
            version: format!("{}.{}.{}", KBS_MAJOR_VERSION, KBS_MINOR_VERSION, KBS_PATCH_VERSION),
            tee: Tee::Tdx,
            extra_params: "test-params".to_string(),
        };
        let auth_request_bytes = serde_json::to_vec(&auth_request).unwrap();
        let auth_response = service.auth(&auth_request_bytes).await.unwrap();
        
        // Extract session cookie
        let session_cookie = auth_response.headers().get("set-cookie").unwrap();
        let cookie_str = session_cookie.to_str().unwrap();
        let session_id = cookie_str.split('=').nth(1).unwrap().split(';').next().unwrap();
        
        let req = TestRequest::default()
            .cookie(actix_web::cookie::Cookie::new(KBS_SESSION_ID, session_id))
            .to_http_request();
        
        let result = service.get_attest_token_from_session(&req).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_session_expiration() {
        let service = AttestationService {
            inner: Arc::new(MockAttest::new()),
            session_map: Arc::new(SessionMap::new()),
            timeout: 0, // Set very short timeout for testing
        };
        
        // Create a session
        let auth_request = Request {
            version: format!("{}.{}.{}", KBS_MAJOR_VERSION, KBS_MINOR_VERSION, KBS_PATCH_VERSION),
            tee: Tee::Tdx,
            extra_params: "test-params".to_string(),
        };
        let auth_request_bytes = serde_json::to_vec(&auth_request).unwrap();
        let auth_response = service.auth(&auth_request_bytes).await.unwrap();
        
        // Extract session cookie
        let session_cookie = auth_response.headers().get("set-cookie").unwrap();
        let cookie_str = session_cookie.to_str().unwrap();
        let session_id = cookie_str.split('=').nth(1).unwrap().split(';').next().unwrap();
        
        let req = TestRequest::default()
            .cookie(actix_web::cookie::Cookie::new(KBS_SESSION_ID, session_id))
            .to_http_request();
        
        // Wait for session to expire (timeout is 0 minutes, so it should be expired)
        sleep(Duration::from_millis(100)).await;
        
        let test_tee_pubkey = kbs_types::TeePubKey {
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            k_mod: "test_modulus".to_string(),
            k_exp: "test_exponent".to_string(),
        };
        
        let attestation = Attestation {
            tee_pubkey: test_tee_pubkey,
            tee_evidence: "test-evidence-string".to_string(),
        };
        let attestation_bytes = serde_json::to_vec(&attestation).unwrap();
        
        let result = service.attest(&attestation_bytes, req).await;
        assert!(result.is_err());
    }

    #[tokio::test] 
    async fn test_session_map_cleanup() {
        let session_map = Arc::new(SessionMap::new());
        
        // Create a test session with expired timeout
        let request = Request {
            version: format!("{}.{}.{}", KBS_MAJOR_VERSION, KBS_MINOR_VERSION, KBS_PATCH_VERSION),
            tee: Tee::Tdx,
            extra_params: "test-params".to_string(),
        };
        let challenge = Challenge {
            nonce: "test-nonce".to_string(),
            extra_params: "".to_string(),
        };
        let session = SessionStatus::auth(request, -1, challenge); // Negative timeout = expired
        
        let session_id = session.id().to_string();
        session_map.insert(session);
        
        // Verify session exists
        assert!(session_map.sessions.get_async(&session_id).await.is_some());
        
        // Manually trigger cleanup (simulate what the background task does)
        session_map.sessions.retain_async(|_, v| !v.is_expired()).await;
        
        // Verify expired session is removed
        assert!(session_map.sessions.get_async(&session_id).await.is_none());
    }

    #[tokio::test]
    async fn test_set_policy_input_deserialization() {
        let json_str = r#"{"policy_id": "test", "policy": "content"}"#;
        let input: SetPolicyInput = serde_json::from_str(json_str).unwrap();
        assert_eq!(input.policy_id, "test");
        assert_eq!(input.policy, "content");
    }

    #[tokio::test]
    async fn test_default_attest_trait_methods() {
        struct DefaultAttest;
        
        #[async_trait]
        impl Attest for DefaultAttest {
            async fn verify(&self, _tee: Tee, _nonce: &str, _attestation: &str) -> anyhow::Result<String> {
                Ok("test".to_string())
            }
        }
        
        let attest = DefaultAttest;
        
        // Test default implementations return errors
        assert!(attest.set_policy("id", "policy").await.is_err());
        assert!(attest.get_policy("id").await.is_err());
        assert!(attest.list_policies().await.is_err());
        assert!(attest.delete_policy("id").await.is_err());
        
        // Test default generate_challenge implementation
        let challenge = attest.generate_challenge(Tee::Tdx, "params".to_string()).await.unwrap();
        assert!(!challenge.nonce.is_empty());
        assert_eq!(challenge.extra_params, "");
    }

    #[tokio::test] 
    async fn test_version_constants() {
        // Test that version constants are used correctly
        assert_eq!(KBS_MAJOR_VERSION, 0);
        assert_eq!(KBS_MINOR_VERSION, 1);
        assert_eq!(KBS_PATCH_VERSION, 0);
        
        // Test version requirement parsing
        let version_str = format!("={}.{}.{}", KBS_MAJOR_VERSION, KBS_MINOR_VERSION, KBS_PATCH_VERSION);
        let parsed_req = VersionReq::parse(&version_str).unwrap();
        assert_eq!(parsed_req.to_string(), VERSION_REQ.to_string());
    }

    #[tokio::test]
    async fn test_nonce_size_constant() {
        assert_eq!(NONCE_SIZE_BYTES, 32);
    }
}
