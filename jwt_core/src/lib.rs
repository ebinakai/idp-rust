use chrono::{Duration, Utc};
use jsonwebtoken::{
    decode,
    encode,
    DecodingKey,
    EncodingKey,
    Header,
    Validation,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
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

pub fn verify_token(token: &str, secret: &[u8]) -> Result<Claims, jsonwebtoken::errors::Error> {
    let validation = Validation::default();

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret),
        &validation,
    );

    Ok(token_data?.claims)
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
        assert_eq!(claims.sub, user_id, "クレームのsubはユーザーIDと一致する必要があります");
    }

    #[test]
    fn test_verify_with_wrong_secret() {
        let user_id = "user123";
        let token = create_token(user_id, SECRET).unwrap();
        let wrong_secret = b"wrong_secret_key";

        let result = verify_token(&token, wrong_secret);
        assert!(result.is_err(), "間違ったシークレットでの検証は失敗する必要があります");
    }
}