#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use uuid::Uuid;
    use sqlx::MySqlPool;
    use db_client::*;
    
    #[sqlx::test(migrations = "../migrations")]
    async fn test_create_and_get_client(pool: MySqlPool) {
        let client = DbClient { pool };
        let client_id = Uuid::new_v4().to_string();
        let client_name = format!("test_client_{}", client_id);
        let client_secret = Uuid::new_v4().to_string();

        let new_client = OAuthClient {
            id: client_id.clone(),
            name: client_name,
            secret: Some(client_secret),
            redirect_uris: vec!["http://localhost:8080/callback".to_string(), "http://localhost:8080/".to_string()],
        };
        client.create_oauth_client(&new_client).await.expect("クライアントの作成に失敗しました");

        let fetched_client = client.get_oauth_client(&client_id).await.expect("Selectクエリの実行に失敗しました");
        assert!(fetched_client.is_some(), "クライアントが見つかりませんでした");
    }

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

        let fetched_user = client.get_user(&id).await.expect("Selectクエリの実行に失敗しました");
        assert!(fetched_user.is_some(), "ユーザーが見つかりませんでした");

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