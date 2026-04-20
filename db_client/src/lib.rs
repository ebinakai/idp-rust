mod models;

pub use models::{DbClient, OAuthClient, RefreshToken, User};
use sqlx::mysql::MySqlPoolOptions;
use std::time::Duration;

impl DbClient {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = MySqlPoolOptions::new()
            .max_connections(5)
            .min_connections(1)
            .idle_timeout(Duration::from_secs(60 * 10))
            .max_lifetime(Duration::from_secs(60 * 30))
            .test_before_acquire(true)
            .connect(database_url)
            .await?;

        Ok(Self { pool })
    }

    pub async fn create_oauth_client(&self, client: &OAuthClient) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "INSERT INTO oauth_clients (id, name, secret) VALUES (?, ?, ?)",
            client.id,
            client.name,
            client.secret,
        )
        .execute(&self.pool)
        .await?;

        for redirect_uri in &client.redirect_uris {
            sqlx::query!(
                "INSERT INTO oauth_client_redirect_uris (client_id, uri) VALUES (?, ?)",
                client.id,
                redirect_uri,
            )
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    pub async fn get_oauth_client(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuthClient>, sqlx::Error> {
        let client_record = sqlx::query!(
            "SELECT id, name, secret FROM oauth_clients WHERE id = ?",
            client_id,
        )
        .fetch_optional(&self.pool)
        .await?;

        let client_record = match client_record {
            Some(record) => record,
            None => return Ok(None),
        };

        let uri_records = sqlx::query!(
            "SELECT uri FROM oauth_client_redirect_uris WHERE client_id = ?",
            client_id,
        )
        .fetch_all(&self.pool)
        .await?;

        let redirect_uris: Vec<String> = uri_records.into_iter().map(|r| r.uri).collect();

        Ok(Some(OAuthClient {
            id: client_record.id,
            name: client_record.name,
            secret: client_record.secret,
            redirect_uris,
        }))
    }

    pub async fn create_user(&self, user: &User) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
            user.id,
            user.username,
            user.password_hash
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn give_consent(&self, user_id: &str, client_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "INSERT INTO user_consents (user_id, client_id) VALUES (?, ?)",
            user_id,
            client_id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn has_user_consent(
        &self,
        user_id: &str,
        client_id: &str,
    ) -> Result<bool, sqlx::Error> {
        let row = sqlx::query!(
            "SELECT user_id FROM user_consents WHERE user_id = ? AND client_id = ?",
            user_id,
            client_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.is_some())
    }

    pub async fn save_refresh_token(&self, token: &RefreshToken) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "INSERT INTO refresh_tokens (id, user_id, client_id, expires_at) VALUES (?, ?, ?, ?)",
            token.id,
            token.user_id,
            token.client_id,
            token.expires_at,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_valid_refresh_token(
        &self,
        token_id: &str,
    ) -> Result<Option<RefreshToken>, sqlx::Error> {
        let row = sqlx::query_as!(
            RefreshToken,
            "SELECT id, user_id, client_id, expires_at 
                FROM refresh_tokens 
                WHERE id = ? 
                    AND expires_at > NOW() 
                    AND is_revoked = FALSE",
            token_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn get_user(&self, user_id: &str) -> Result<Option<User>, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, username, password_hash, created_at, updated_at FROM users WHERE id = ?",
            user_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn get_user_by_name(&self, username: &str) -> Result<Option<User>, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, username, password_hash, created_at, updated_at FROM users WHERE username = ?",
            username
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn delete_user(&self, user_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query!("DELETE FROM users WHERE id = ?", user_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn delete_refresh_token(&self, token_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query!("DELETE FROM refresh_tokens WHERE id = ?", token_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
