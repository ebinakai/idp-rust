use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

type JwksCache = Arc<RwLock<HashMap<String, Jwk>>>;

#[derive(Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Deserialize, Clone)]
pub struct Jwk {
    pub kid: String,
    pub n: String,
    pub e: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub iat: usize,
    pub exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub nonce: Option<String>,
    pub iat: usize,
    pub exp: usize,
}

#[derive(Clone)]
pub struct AppState {
    pub reqwest_client: reqwest::Client,
    pub jwks_cache: JwksCache,
    pub client_id: String,
    pub client_secret: String,
    pub idp_base_url: String,
    pub client_url: String,
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Serialize)]
pub struct IdpTokenReq {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    pub code_verifier: String,
}

#[derive(Deserialize)]
pub struct IdpTokenRes {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<i64>,
    #[allow(dead_code)]
    pub scope: Option<String>,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTokens {
    pub access_token: String,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Serialize)]
pub struct RefreshTokenReq {
    pub grant_type: String,
    pub refresh_token: String,
}
