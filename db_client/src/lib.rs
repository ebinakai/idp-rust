mod models;

pub use models::{DbClient, OAuthClient, RefreshToken, User};
use sqlx::mysql::MySqlPoolOptions;
use std::collections::HashMap;
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
        let mut tx = self.pool.begin().await?;

        sqlx::query("INSERT INTO oauth_clients (id, name, secret) VALUES (?, ?, ?)")
            .bind(&client.id)
            .bind(&client.name)
            .bind(&client.secret)
            .execute(&mut *tx)
            .await?;

        for redirect_uri in &client.redirect_uris {
            sqlx::query("INSERT INTO oauth_client_redirect_uris (client_id, uri) VALUES (?, ?)")
                .bind(&client.id)
                .bind(redirect_uri)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    pub async fn get_oauth_client(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuthClient>, sqlx::Error> {
        let client_record = sqlx::query_as::<_, (String, String, Option<String>)>(
            "SELECT id, name, secret FROM oauth_clients WHERE id = ?",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?;

        let (id, name, secret) = match client_record {
            Some(record) => record,
            None => return Ok(None),
        };

        let redirect_uris = sqlx::query_scalar::<_, String>(
            "SELECT uri FROM oauth_client_redirect_uris WHERE client_id = ?",
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(Some(OAuthClient {
            id,
            name,
            secret,
            redirect_uris,
        }))
    }

    pub async fn list_oauth_clients(&self) -> Result<Vec<OAuthClient>, sqlx::Error> {
        let clients = sqlx::query_as::<_, (String, String, Option<String>)>(
            "SELECT id, name, secret FROM oauth_clients ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        let uri_rows = sqlx::query_as::<_, (String, String)>(
            "SELECT client_id, uri FROM oauth_client_redirect_uris",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut uris_map: HashMap<String, Vec<String>> = HashMap::new();
        for (client_id, uri) in uri_rows {
            uris_map.entry(client_id).or_default().push(uri);
        }

        Ok(clients
            .into_iter()
            .map(|(id, name, secret)| {
                let redirect_uris = uris_map.remove(&id).unwrap_or_default();
                OAuthClient {
                    id,
                    name,
                    secret,
                    redirect_uris,
                }
            })
            .collect())
    }

    pub async fn create_user(&self, user: &User) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)")
            .bind(&user.id)
            .bind(&user.username)
            .bind(&user.password_hash)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn give_consent(&self, user_id: &str, client_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT IGNORE INTO user_consents (user_id, client_id) VALUES (?, ?)")
            .bind(user_id)
            .bind(client_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn has_user_consent(
        &self,
        user_id: &str,
        client_id: &str,
    ) -> Result<bool, sqlx::Error> {
        let row = sqlx::query_scalar::<_, String>(
            "SELECT user_id FROM user_consents WHERE user_id = ? AND client_id = ?",
        )
        .bind(user_id)
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.is_some())
    }

    pub async fn save_refresh_token(&self, token: &RefreshToken) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO refresh_tokens (id, user_id, client_id, expires_at) VALUES (?, ?, ?, ?)",
        )
        .bind(&token.id)
        .bind(&token.user_id)
        .bind(&token.client_id)
        .bind(token.expires_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_valid_refresh_token(
        &self,
        token_id: &str,
    ) -> Result<Option<RefreshToken>, sqlx::Error> {
        sqlx::query_as::<_, RefreshToken>(
            "SELECT id, user_id, client_id, expires_at
                FROM refresh_tokens
                WHERE id = ?
                    AND expires_at > NOW()
                    AND is_revoked = FALSE",
        )
        .bind(token_id)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn get_user(&self, user_id: &str) -> Result<Option<User>, sqlx::Error> {
        sqlx::query_as::<_, User>(
            "SELECT id, username, password_hash, created_at, updated_at FROM users WHERE id = ?",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn get_user_by_name(&self, username: &str) -> Result<Option<User>, sqlx::Error> {
        sqlx::query_as::<_, User>(
            "SELECT id, username, password_hash, created_at, updated_at FROM users WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn delete_user(&self, user_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn delete_refresh_token(&self, token_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM refresh_tokens WHERE id = ?")
            .bind(token_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
