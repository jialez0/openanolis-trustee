// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use kbs_types::{Response, TeePubKey};
use rand::{rngs::OsRng, Rng};
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPublicKey};
use serde_json::json;

const RSA_ALGORITHM: &str = "RSA1_5";
const AES_GCM_256_ALGORITHM: &str = "A256GCM";

pub fn jwe(tee_pub_key: TeePubKey, payload_data: Vec<u8>) -> Result<Response> {
    if tee_pub_key.alg != *RSA_ALGORITHM {
        bail!("algorithm is not {RSA_ALGORITHM} but {}", tee_pub_key.alg);
    }

    let mut rng = rand::thread_rng();

    let aes_sym_key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&aes_sym_key);
    let iv = rng.gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&iv);
    let encrypted_payload_data = cipher
        .encrypt(nonce, payload_data.as_slice())
        .map_err(|e| anyhow!("AES encrypt Resource payload failed: {e}"))?;

    let k_mod = URL_SAFE_NO_PAD
        .decode(&tee_pub_key.k_mod)
        .context("base64 decode k_mod failed")?;
    let n = BigUint::from_bytes_be(&k_mod);
    let k_exp = URL_SAFE_NO_PAD
        .decode(&tee_pub_key.k_exp)
        .context("base64 decode k_exp failed")?;
    let e = BigUint::from_bytes_be(&k_exp);

    let rsa_pub_key =
        RsaPublicKey::new(n, e).context("Building RSA key from modulus and exponent failed")?;
    let sym_key: &[u8] = aes_sym_key.as_slice();
    let wrapped_sym_key = rsa_pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, sym_key)
        .context("RSA encrypt sym key failed")?;

    let protected_header = json!(
    {
       "alg": RSA_ALGORITHM.to_string(),
       "enc": AES_GCM_256_ALGORITHM.to_string(),
    });

    Ok(Response {
        protected: serde_json::to_string(&protected_header)
            .context("serde protected_header failed")?,
        encrypted_key: URL_SAFE_NO_PAD.encode(wrapped_sym_key),
        iv: URL_SAFE_NO_PAD.encode(iv),
        ciphertext: URL_SAFE_NO_PAD.encode(encrypted_payload_data),
        tag: "".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::{RsaPrivateKey, RsaPublicKey, traits::PublicKeyParts};
    use rand::thread_rng;

    fn create_test_rsa_keypair() -> (RsaPrivateKey, TeePubKey) {
        let mut rng = thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        
        let n_bytes = public_key.n().to_bytes_be();
        let e_bytes = public_key.e().to_bytes_be();
        
        let tee_pub_key = TeePubKey {
            kty: "RSA".to_string(),
            alg: "RSA1_5".to_string(),
            k_mod: URL_SAFE_NO_PAD.encode(&n_bytes),
            k_exp: URL_SAFE_NO_PAD.encode(&e_bytes),
        };
        
        (private_key, tee_pub_key)
    }

    #[test]
    fn test_jwe_successful_encryption() {
        let (_private_key, tee_pub_key) = create_test_rsa_keypair();
        let payload_data = b"test payload data".to_vec();
        
        let result = jwe(tee_pub_key, payload_data);
        assert!(result.is_ok());
        
        let response = result.unwrap();
        assert!(!response.protected.is_empty());
        assert!(!response.encrypted_key.is_empty());
        assert!(!response.iv.is_empty());
        assert!(!response.ciphertext.is_empty());
        assert_eq!(response.tag, "");
    }

    #[test]
    fn test_jwe_invalid_algorithm() {
        let (_private_key, mut tee_pub_key) = create_test_rsa_keypair();
        tee_pub_key.alg = "INVALID_ALG".to_string();
        let payload_data = b"test payload data".to_vec();
        
        let result = jwe(tee_pub_key, payload_data);
        assert!(result.is_err());
        
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("algorithm is not RSA1_5"));
    }

    #[test]
    fn test_jwe_invalid_base64_k_mod() {
        let (_private_key, mut tee_pub_key) = create_test_rsa_keypair();
        tee_pub_key.k_mod = "invalid_base64!@#".to_string();
        let payload_data = b"test payload data".to_vec();
        
        let result = jwe(tee_pub_key, payload_data);
        assert!(result.is_err());
        
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("base64 decode k_mod failed"));
    }

    #[test]
    fn test_jwe_invalid_base64_k_exp() {
        let (_private_key, mut tee_pub_key) = create_test_rsa_keypair();
        tee_pub_key.k_exp = "invalid_base64!@#".to_string();
        let payload_data = b"test payload data".to_vec();
        
        let result = jwe(tee_pub_key, payload_data);
        assert!(result.is_err());
        
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("base64 decode k_exp failed"));
    }

    #[test]
    fn test_jwe_empty_payload() {
        let (_private_key, tee_pub_key) = create_test_rsa_keypair();
        let payload_data = Vec::new();
        
        let result = jwe(tee_pub_key, payload_data);
        assert!(result.is_ok());
        
        let response = result.unwrap();
        assert!(!response.ciphertext.is_empty()); // Even empty payload produces some ciphertext
    }

    #[test]
    fn test_jwe_large_payload() {
        let (_private_key, tee_pub_key) = create_test_rsa_keypair();
        let payload_data = vec![0u8; 10000]; // 10KB payload
        
        let result = jwe(tee_pub_key, payload_data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_jwe_protected_header_format() {
        let (_private_key, tee_pub_key) = create_test_rsa_keypair();
        let payload_data = b"test payload data".to_vec();
        
        let result = jwe(tee_pub_key, payload_data).unwrap();
        
        let protected_header: serde_json::Value = serde_json::from_str(&result.protected).unwrap();
        assert_eq!(protected_header["alg"], "RSA1_5");
        assert_eq!(protected_header["enc"], "A256GCM");
    }

    #[test]
    fn test_jwe_base64_encoding() {
        let (_private_key, tee_pub_key) = create_test_rsa_keypair();
        let payload_data = b"test payload data".to_vec();
        
        let result = jwe(tee_pub_key, payload_data).unwrap();
        
        // Test that all base64 encoded fields can be decoded
        assert!(URL_SAFE_NO_PAD.decode(&result.encrypted_key).is_ok());
        assert!(URL_SAFE_NO_PAD.decode(&result.iv).is_ok());
        assert!(URL_SAFE_NO_PAD.decode(&result.ciphertext).is_ok());
        
        // Test IV length (should be 12 bytes for AES-GCM)
        let iv_bytes = URL_SAFE_NO_PAD.decode(&result.iv).unwrap();
        assert_eq!(iv_bytes.len(), 12);
    }

    #[test]
    fn test_jwe_deterministic_parts() {
        let (_private_key, tee_pub_key) = create_test_rsa_keypair();
        let payload_data = b"test payload data".to_vec();
        
        let result = jwe(tee_pub_key, payload_data).unwrap();
        
        // Protected header should always be the same for same algorithm
        let protected_header: serde_json::Value = serde_json::from_str(&result.protected).unwrap();
        assert_eq!(protected_header["alg"], "RSA1_5");
        assert_eq!(protected_header["enc"], "A256GCM");
        
        // Tag should always be empty string
        assert_eq!(result.tag, "");
    }

    #[test]
    fn test_jwe_constants() {
        assert_eq!(RSA_ALGORITHM, "RSA1_5");
        assert_eq!(AES_GCM_256_ALGORITHM, "A256GCM");
    }
}
