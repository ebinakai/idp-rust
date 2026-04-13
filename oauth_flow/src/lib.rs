use base64::{
    engine::general_purpose::URL_SAFE_NO_PAD, 
    Engine as _,
};
use rand::RngExt;
use std::time::{SystemTime, UNIX_EPOCH};

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
            .expect("Time went backwards")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_code_generation_and_validation() {
        let user_id = "test_user".to_string();
        let client_id = "client_123";

        let auth_code = AuthCode::new(&user_id, client_id);
        assert!(!auth_code.code.is_empty(), "認可コードが生成されていません");
        assert_eq!(auth_code.user_id, user_id, "ユーザーIDが一致しません");
        assert_eq!(auth_code.client_id, client_id, "クライアントIDが一致しません");
        assert!(auth_code.is_valid(), "認可コードがすでに期限切れと判定されています");        
        assert_eq!(auth_code.code.len(), 43, "Base64エンコードされた認可コードの長さが期待値と異なります");
    }

    #[test]
    fn test_verify_for_exchange() {
        let user_id = "test_user".to_string();
        let client_id = "client_123";
        let auth_code = AuthCode::new(&user_id, client_id);

        let valid_request = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: auth_code.code.clone(),
            client_id: client_id.to_string(),
        };
        let result = auth_code.verify_for_exchange(&valid_request)
            .expect("認可コードの検証に失敗しました");
        assert_eq!(result, "test_user", "検証後のユーザーIDが一致しません");

        let invalid_request = TokenRequest {
            grant_type: "password".to_string(),
            code: "invalid_code".to_string(),
            client_id: client_id.to_string(),
        };
        assert!(auth_code.verify_for_exchange(&invalid_request).is_err(), "無効なリクエストが検証に成功しました");


        let malicious_request = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: "invalid_code".to_string(),
            client_id: "wrong_client".to_string(),
        };
        assert!(auth_code.verify_for_exchange(&malicious_request).is_err(), "不正なクライアントIDが検証に成功しました");
    }
}