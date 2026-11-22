use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub is_admin: bool,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    pub id: String,
    pub name: String,
    pub secret: Option<String>,
    pub redirect_uris: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DbClient {
    pub pool: MySqlPool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RefreshToken {
    pub id: String,
    pub user_id: String,
    pub client_id: String,
    pub expires_at: NaiveDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PasskeyRecord {
    pub id: String,
    pub user_id: String,
    pub credential_id: String,
    pub label: String,
    pub passkey_json: String,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct UserConsentRecord {
    pub client_id: String,
    pub client_name: String,
    pub created_at: Option<DateTime<Utc>>,
}
