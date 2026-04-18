use base64::{
    engine::general_purpose::URL_SAFE_NO_PAD,
    Engine as _,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{
    Algorithm,
    DecodingKey, EncodingKey,
    Header, Validation,
    decode, encode, get_current_timestamp
};
use rsa::{
    pkcs8::DecodePublicKey,
    RsaPublicKey,
    traits::PublicKeyParts,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
}

pub fn create_token(
    user_id: &str, 
    private_key_pem: &[u8],
    kid: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let iat = now.timestamp() as usize;

    let exp = (now + Duration::hours(1)).timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        iat,
        exp,
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(private_key_pem)?,
    )
}

pub fn create_id_token(
    user_id: &str,
    client_id: &str,
    issure: &str,
    private_key_pem: &[u8],
    kid: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let exp = get_current_timestamp() + 60 * 60; // 1hour
    let claims = IdTokenClaims {
        iss: issure.to_string(),
        sub: user_id.to_string(),
        aud: client_id.to_string(),
        exp: exp as usize,
        iat: now.timestamp() as usize,
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    
    encode(
        &header, 
        &claims,
        &EncodingKey::from_rsa_pem(private_key_pem)?,
    )
}

pub fn verify_token(token: &str, public_key_pem: &[u8]) -> Result<String, jsonwebtoken::errors::Error> {
    let key = DecodingKey::from_rsa_pem(public_key_pem)?;
    let validation = Validation::new(Algorithm::RS256);

    let token_data = decode::<Claims>(token, &key, &validation)?;

    Ok(token_data.claims.sub)
}

pub fn get_jwks(public_key_pem: &str, kid: &str) -> Result<serde_json::Value, String> {
    let pub_key = RsaPublicKey::from_public_key_pem(public_key_pem)
        .map_err(|e| format!("公開鍵のパースに失敗: {}", e))?;
    
    let n = URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());
    
    Ok(json!({
        "keys": [
            {
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": kid,
                "n": n,
                "e": e
            }
        ]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PRIVATE_KEY: &[u8] = include_bytes!("../../keys/private_key.pem");
    const TEST_PUBLIC_KEY: &[u8] = include_bytes!("../../keys/public_key.pem");
    const TEST_KID: &str = "key-1";

    #[test]
    fn test_creat_and_verify_token() {
        let user_id = "user123";

        let token = create_token(user_id, TEST_PRIVATE_KEY, TEST_KID).expect("トークンの作成に失敗しました");
        assert_eq!(token.split('.').count(), 3, "トークンは3つの部分から構成されている必要があります");

        let claims = verify_token(&token, TEST_PUBLIC_KEY).expect("トークンの検証に失敗しました");
        assert_eq!(claims, user_id, "クレームはユーザーIDと一致する必要があります");
    }

    #[test]
    fn test_verify_token_with_wrong_secret() {
        let user_id = "user123";
        let mut token = create_token(user_id, TEST_PRIVATE_KEY, TEST_KID).unwrap();
        token.push_str("invalid_signature_data");

        let result = verify_token(&token, TEST_PUBLIC_KEY);
        assert!(result.is_err(), "改ざんされたトークンの検証は失敗する必要があります");
    }

    #[test]
    fn test_create_and_verify_id_token() {
        let user_id = "user123";
        let client_id = "client123";
        let issuer = "http://localhost:3000";
        let token = create_id_token(user_id, client_id, issuer, TEST_PRIVATE_KEY, TEST_KID).expect("IDトークンの作成に失敗しました");
        assert_eq!(token.split('.').count(), 3, "IDトークンは3つの部分から構成されている必要があります");

        let key = DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY).expect("公開鍵のパースに失敗しました");
        let mut validation = Validation::new(Algorithm::RS256);

        validation.set_audience(&[client_id]);
        validation.set_issuer(&[issuer]);

        let decoded = decode::<IdTokenClaims>(&token, &key, &validation).expect("IDトークンの検証に失敗しました");
        
        let claims = decoded.claims;
        assert_eq!(claims.sub, user_id, "ユーザーIDが一致しません");
        assert_eq!(claims.aud, client_id, "クライアントIDが一致しません");
        assert_eq!(claims.iss, issuer, "発行者が一致しません");
        assert!(claims.exp > claims.iat, "expがiatよりも後である必要があります");
        assert_eq!(claims.exp - claims.iat, 3600, "有効期限が1時間ではありません")
    }

    #[test]
    fn test_verify_id_token_with_wrong_secret() {
        let user_id = "user123";
        let client_id = "client123";
        let issuer = "http://localhost:3000";
        let mut token = create_id_token(user_id, client_id, issuer, TEST_PRIVATE_KEY, TEST_KID).expect("IDトークンの作成に失敗しました");

        token.push_str("invalid_signature_data");
        let key = DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY).expect("公開鍵のパースに失敗しました");
        let mut validation = Validation::new(Algorithm::RS256);

        validation.set_audience(&[client_id]);
        validation.set_issuer(&[issuer]);

        let result = decode::<IdTokenClaims>(&token, &key, &validation);
        assert!(result.is_err(), "間違ったシークレットでの検証は失敗する必要があります");
    }
    
    #[test]
    fn test_get_jwks_structure() {
        let jwks = get_jwks(std::str::from_utf8(TEST_PUBLIC_KEY).unwrap(), TEST_KID).expect("JWKSの取得に失敗しました");
        assert!(jwks.is_object(), "JWKSはオブジェクトである必要があります");
        
        let keys = jwks["keys"].as_array().expect("keysは配列である必要があります");
        assert_eq!(keys.len(), 1);
        
        let key = &keys[0];
        assert_eq!(key["kty"], "RSA");
        assert_eq!(key["alg"], "RS256");
        assert_eq!(key["use"], "sig");
        assert_eq!(key["kid"], TEST_KID);
        assert!(!key["n"].as_str().unwrap().is_empty());
        assert!(!key["e"].as_str().unwrap().is_empty());
    }
}
