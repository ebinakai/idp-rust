use sqlx::{
    mysql::MySqlPoolOptions,
    MySqlPool
};
use chrono::{DateTime, Utc, NaiveDateTime};

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

pub struct RefreshToken {
    pub id: String,
    pub user_id: String,
    pub client_id: String,
    pub expires_at: NaiveDateTime,
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
    
    pub async fn get_valid_refresh_token(&self, token_id: &str) -> Result<Option<RefreshToken>, sqlx::Error> {
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
        sqlx::query!(
            "DELETE FROM users WHERE id = ?",
            user_id
        )
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    pub async fn delete_refresh_token(&self, token_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "DELETE FROM refresh_tokens WHERE id = ?",
            token_id
        )
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use uuid::Uuid;
    use super::*;

    #[sqlx::test(migrations = "../migrations")]
    async fn test_create_and_get_user(pool: MySqlPool) {
        let client = DbClient { pool };

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
        
        client.delete_user(&user.id).await.expect("ユーザーの削除に失敗しました");
        let deleted_user = client.get_user_by_name(&username).await.expect("削除後のユーザーの取得に失敗しました");
        assert!(deleted_user.is_none(), "削除されたユーザーが取得されました");
    }
    
    #[sqlx::test(migrations = "../migrations")]
    async fn test_get_valid_refresh_token(pool: MySqlPool) {
        let client = DbClient { pool };
        
        let user_id = Uuid::new_v4().to_string();
        let username = format!("test_user_{}", user_id);
        let password_hash = "$argon2id$v=19$m=4096,t=3,p=1$some_salt$some_hash".to_string();
        let user = User {
            id: user_id.clone(),
            username: username.clone(),
            password_hash: password_hash.clone(),
            created_at: None,
            updated_at: None,
        };
        client.create_user(&user).await.expect("テスト用ユーザーの作成に失敗しました");
        
        let token_id = Uuid::new_v4().to_string();
        let expires_at = (Utc::now() + Duration::days(30)).naive_utc();
        let token = RefreshToken {
            id: token_id.clone(),
            user_id: user_id.clone(),
            client_id: "test_client_app".to_string(),
            expires_at,
        };
        client.save_refresh_token(&token).await.expect("リフレッシュトークンの保存に失敗しました");
        
        let fetched_token = client.get_valid_refresh_token(&token_id).await.expect("トークンの取得に失敗しました");
        assert!(fetched_token.is_some(), "保存したトークンが見つかりません");
        
        let t = fetched_token.unwrap();
        assert_eq!(t.id, token_id, "トークンのIDが一致しません");
        assert_eq!(t.user_id, user_id, "ユーザーIDが一致しません");
        assert_eq!(t.client_id, "test_client_app", "クライアントIDが一致しません");
        
        let none_token = client.get_valid_refresh_token("non_existent_id").await.expect("クエリ実行に失敗");
        assert!(none_token.is_none(), "存在しないトークンが取得されました");
        
        client.delete_refresh_token(&token_id).await.expect("リフレッシュトークンの削除に失敗しました");
        let deleted_token = client.get_valid_refresh_token(&token_id).await.expect("削除後のトークンの取得に失敗しました");
        assert!(deleted_token.is_none(), "削除されたトークンが取得されました");
    }
}