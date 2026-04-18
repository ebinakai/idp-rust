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
    pub sub: String,
    pub exp: usize,
}

#[derive(Clone)]
pub struct AppState {
    pub reqwest_client: reqwest::Client,
    pub jwks_cache: JwksCache,
    pub client_id: String,
    pub idp_base_url: String,
}

#[derive(Deserialize)]
pub struct LoginPayload {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct IdpLoginReq {
    pub username: String,
    pub password: String,
    pub client_id: String,
}

#[derive(Deserialize)]
pub struct IdpLoginRes {
    pub auth_code: String,
}

#[derive(Serialize)]
pub struct IdpTokenReq {
    pub grant_type: String,
    pub code: String,
    pub client_id: String,
    pub scope: Option<String>,
}

#[derive(Deserialize)]
pub struct IdpTokenRes {
    pub access_token: String,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub _token_type: Option<String>,
}

#[derive(Serialize)]
pub struct ClientRes {
    pub access_token: String,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct RefreshReq {
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct RefreshTokenReq {
    pub grant_type: String,
    pub refresh_token: String,
    pub client_id: String,
}

#[derive(serde::Deserialize)]
pub struct LogoutReq {
    pub refresh_token: String,
}
