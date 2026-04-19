use chrono::{DateTime, Utc, NaiveDateTime};
use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
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

pub struct RefreshToken {
    pub id: String,
    pub user_id: String,
    pub client_id: String,
    pub expires_at: NaiveDateTime,
}