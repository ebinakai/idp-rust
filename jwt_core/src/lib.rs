use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode, get_current_timestamp,
};
use rsa::{RsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts};
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

pub fn verify_token(
    token: &str,
    public_key_pem: &[u8],
) -> Result<String, jsonwebtoken::errors::Error> {
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
