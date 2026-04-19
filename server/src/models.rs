use db_client::DbClient;
use oauth_flow::AuthCode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct AppState {
    pub db: DbClient,
    pub auth_codes: Arc<Mutex<HashMap<String, AuthCode>>>,
    pub private_key: String,
    pub public_key: String,
    pub kid: String,
    pub issuer: String,
    pub refresh_token_ttl_days: i64,
}

#[derive(Deserialize)]
pub struct RegisterReq {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginReq {
    pub username: String,
    pub password: String,
    pub client_id: String,
}

#[derive(Serialize)]
pub struct LoginRes {
    pub auth_code: String,
}

#[derive(Deserialize)]
pub struct TokenReq {
    pub grant_type: String,
    pub code: Option<String>,
    pub client_id: String,
    pub scope: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Serialize)]
pub struct TokenRes {
    pub access_token: String,
    pub token_type: String,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Deserialize)]
pub struct RevokeReq {
    pub token: String,
}
