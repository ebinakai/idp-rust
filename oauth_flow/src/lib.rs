use base64::{
    engine::general_purpose::URL_SAFE_NO_PAD, 
    Engine as _,
};
use chrono::{Utc, Duration, NaiveDateTime};
use rand::RngExt;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AuthCode {
    pub code: String,
    pub user_id: String,
    pub client_id: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: String,
    pub client_id: String,
}

impl AuthCode {
    pub fn new(user_id: &str, client_id: &str) -> Self {
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        let code_string = URL_SAFE_NO_PAD.encode(&bytes);

        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("システム時刻が異常です")
            .as_secs() + 600;

        Self {
            code: code_string,
            user_id: user_id.to_string(),
            client_id: client_id.to_string(),
            expires_at,
        }
    }

    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("システム時刻が異常です")
            .as_secs();

        self.expires_at > now
    }

    pub fn verify_for_exchange(&self, request: &TokenRequest) -> Result<String, &'static str> {
        if request.grant_type != "authorization_code" {
            return Err("grant_typeはauthorization_codeでなければなりません");
        }

        if request.code != self.code {
            return Err("提供された認可コードが一致しません");
        }

        if request.client_id != self.client_id {
            return Err("提供されたクライアントIDが一致しません");
        }

        if !self.is_valid() {
            return Err("認可コードはすでに期限切れです");
        }

        Ok(self.user_id.clone())
    }
}

pub struct RefreshTokenData {
    pub token: String,
    pub expires_at: NaiveDateTime,
}

impl RefreshTokenData {
    pub fn generate(duration_days: i64) -> Self {
        Self {
            token: Uuid::new_v4().to_string(),
            expires_at: (Utc::now() + Duration::days(duration_days)).naive_utc(),
        }
    }
}
