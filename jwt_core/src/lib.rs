use chrono::{Duration, Utc};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode, get_current_timestamp
};
use serde::{Deserialize, Serialize};

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

pub fn create_token(user_id: &str, secret: &[u8]) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let iat = now.timestamp() as usize;

    let exp = (now + Duration::hours(1)).timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        iat,
        exp,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
}

pub fn create_id_token(
    user_id: &str,
    client_id: &str,
    issure: &str,
    secret: &[u8],
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
    let header = Header::new(Algorithm::HS256);
    
    encode(&header, &claims, &EncodingKey::from_secret(secret))
}

pub fn verify_token(token: &str, secret: &[u8]) -> Result<String, jsonwebtoken::errors::Error> {
    let key = DecodingKey::from_secret(secret);
    let validation = Validation::new(Algorithm::HS256);
    
    let token_data = decode::<Claims>(token, &key, &validation);

    Ok(token_data?.claims.sub)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"dummy_secret_key";

    #[test]
    fn test_creat_and_verify_token() {
        let user_id = "user123";

        let token = create_token(user_id, SECRET).expect("トークンの作成に失敗しました");
        assert_eq!(token.split('.').count(), 3, "トークンは3つの部分から構成されている必要があります");

        let claims = verify_token(&token, SECRET).expect("トークンの検証に失敗しました");
        assert_eq!(claims, user_id, "クレームはユーザーIDと一致する必要があります");
    }
    
    #[test]
    fn test_verify_token_with_wrong_secret() {
        let user_id = "user123";
        let token = create_token(user_id, SECRET).unwrap();
        let wrong_secret = b"wrong_secret_key";

        let result = verify_token(&token, wrong_secret);
        assert!(result.is_err(), "間違ったシークレットでの検証は失敗する必要があります");
    }
    
    #[test]
    fn test_creat_and_verify_id_token() {
        let user_id = "user123";
        let client_id = "client123";
        let issuer = "http://localhost:3000";
        let token = create_id_token(user_id, client_id, issuer, SECRET).expect("IDトークンの作成に失敗しました");
        assert_eq!(token.split('.').count(), 3, "IDトークンは3つの部分から構成されている必要があります");
        
        let key = DecodingKey::from_secret(SECRET);
        let mut validation = Validation::new(Algorithm::HS256);
        
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
        let token = create_id_token(user_id, client_id, issuer, SECRET).expect("IDトークンの作成に失敗しました");
        
        let wrong_secret = b"wrong_secret";
        let key = DecodingKey::from_secret(wrong_secret);
        let mut validation = Validation::new(Algorithm::HS256);
        
        validation.set_audience(&[client_id]);
        validation.set_issuer(&[issuer]);

        let result = decode::<IdTokenClaims>(&token, &key, &validation);
        assert!(result.is_err(), "間違ったシークレットでの検証は失敗する必要があります");
    }
}