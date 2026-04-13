use sqlx::{
    mysql::MySqlPoolOptions,
    MySqlPool
};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct DbClient {
    pub pool: MySqlPool,
}

impl DbClient {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = MySqlPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;

        Ok(Self { pool })
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
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    #[tokio::test]
    async fn test_database_connection() {
        dotenvy::dotenv().ok();
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URLが設定されていません");
        
        let client_result = DbClient::new(&database_url).await;
        assert!(
            client_result.is_ok(),
            "データベースへの接続に失敗しました: {:?}",
            client_result.err()
        )
    }

    #[tokio::test]
    async fn test_create_and_get_user() {
        dotenvy::dotenv().ok();
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URLが設定されていません");
        let client = DbClient::new(&database_url).await.expect("データベースへの接続に失敗しました");

        let id = Uuid::new_v4().to_string();
        let username = format!("test_user_{}", id);
        let password_hash = "$argon2id$v=19$m=4096,t=3,p=1$some_salt$some_hash".to_string();

        let user = User {
            id: id.clone(),
            username: username.clone(),
            password_hash: password_hash.clone(),
            created_at: None,
            updated_at: None,
        };

        client.create_user(&user).await.expect("ユーザーの作成に失敗しました");

        let fetched_user = client.get_user_by_name(&username).await.expect("Selectクエリの実行に失敗しました");
        assert!(fetched_user.is_some(), "ユーザーが見つかりませんでした");

        let user = fetched_user.unwrap();
        assert_eq!(user.id, id, "取得したユーザーのIDが一致しません");
        assert_eq!(user.username, username, "取得したユーザーの名前が一致しません");
        assert_eq!(user.password_hash, password_hash, "取得したユーザーのパスワードハッシュが一致しません");
        assert!(user.created_at.is_some(), "ユーザーの作成日時が設定されていません");
        assert!(user.updated_at.is_some(), "ユーザーの更新日時が設定されていません");

    }
}