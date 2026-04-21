use askama::Template;
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
pub struct AuthorizeReq {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

#[derive(serde::Deserialize)]
pub struct ConsentReq {
    pub client_id: String,
    pub redirect_uri: String,
    pub action: String, // "allow" または "deny" が入る
}

#[derive(Deserialize)]
pub struct LoginReq {
    pub username: String,
    pub password: String,
    pub client_id: String,
    pub redirect_uri: String,
}

#[derive(Deserialize)]
pub struct TokenReq {
    pub grant_type: String,
    pub code: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
    pub refresh_token: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
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

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uri: String,
}

#[derive(Template)]
#[template(path = "consent.html")]
pub struct ConsentTemplate {
    pub client_name: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub username: String,
}
