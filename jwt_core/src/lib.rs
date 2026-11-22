use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rsa::{RsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts};
use serde::{Deserialize, Serialize};
use serde_json::json;

pub const ACCESS_TOKEN_TTL_SECS: i64 = 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub iat: usize,
    pub exp: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub exp: usize,
    pub iat: usize,
}

pub fn create_token(
    user_id: &str,
    client_id: &str,
    issuer: &str,
    scope: Option<&str>,
    private_key_pem: &[u8],
    kid: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let iat = now.timestamp() as usize;
    let exp = (now + Duration::seconds(ACCESS_TOKEN_TTL_SECS)).timestamp() as usize;

    let claims = Claims {
        iss: issuer.to_string(),
        sub: user_id.to_string(),
        aud: client_id.to_string(),
        scope: scope.map(str::to_string),
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
    issuer: &str,
    nonce: Option<&str>,
    private_key_pem: &[u8],
    kid: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let iat = now.timestamp() as usize;
    let exp = (now + Duration::seconds(ACCESS_TOKEN_TTL_SECS)).timestamp() as usize;
    let claims = IdTokenClaims {
        iss: issuer.to_string(),
        sub: user_id.to_string(),
        aud: client_id.to_string(),
        nonce: nonce.map(str::to_string),
        exp,
        iat,
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
    expected_issuer: &str,
) -> Result<Claims, jsonwebtoken::errors::Error> {
    let key = DecodingKey::from_rsa_pem(public_key_pem)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[expected_issuer]);
    // /userinfo はクライアント共通で受け付けるため aud は個別チェックしない
    validation.validate_aud = false;

    let token_data = decode::<Claims>(token, &key, &validation)?;

    Ok(token_data.claims)
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
