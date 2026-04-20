#[cfg(test)]
mod tests {
    use crypto;
    use oauth_flow::*;

    #[test]
    fn test_auth_code_generation_and_validation() {
        let user_id = "test_user".to_string();
        let client_id = "client_123";

        let auth_code = AuthCode::new(&user_id, client_id);
        assert!(!auth_code.code.is_empty(), "認可コードが生成されていません");
        assert_eq!(auth_code.user_id, user_id, "ユーザーIDが一致しません");
        assert_eq!(
            auth_code.client_id, client_id,
            "クライアントIDが一致しません"
        );
        assert!(
            auth_code.is_valid(),
            "認可コードがすでに期限切れと判定されています"
        );
        assert_eq!(
            auth_code.code.len(),
            43,
            "Base64エンコードされた認可コードの長さが期待値と異なります"
        );
    }

    #[test]
    fn test_verify_pkce_plain() {
        let mut auth_code = AuthCode::new("test_user", "client_123");
        auth_code.challenge_method = Some("plain".to_string());

        let verifier = "test_verifier";
        auth_code.challenge = Some(verifier.to_string());
        assert!(
            auth_code.verify_pkce(verifier),
            "plain: PKCE検証に失敗しました"
        );

        let invalid_verifier = "invalid_verifier";
        assert!(
            !auth_code.verify_pkce(invalid_verifier),
            "plain: 不正なverifierで成功しました"
        );
    }

    #[test]
    fn test_verify_pkce_s256() {
        let mut auth_code = AuthCode::new("test_user", "client_123");
        auth_code.challenge_method = Some("S256".to_string());

        let verifier = "my_super_secret_verifier";
        let challenge = crypto::generate_pkce_challenge(verifier);
        auth_code.challenge = Some(challenge);

        assert!(
            auth_code.verify_pkce(verifier),
            "S256: PKCE検証に失敗しました"
        );
        assert!(
            !auth_code.verify_pkce("wrong_verifier"),
            "S256: 不正なverifierで成功しました"
        );
    }

    #[test]
    fn test_verify_pkce_unsupported_method() {
        let mut auth_code = AuthCode::new("test_user", "client_123");
        auth_code.challenge_method = Some("S512".to_string());

        auth_code.challenge = Some("test_verifier".to_string());
        assert!(
            !auth_code.verify_pkce("test_verifier"),
            "未知のメソッドは失敗する必要があります"
        );
    }

    #[test]
    fn test_verify_pkce_none_method() {
        let mut auth_code = AuthCode::new("test_user", "client_123");

        auth_code.challenge_method = None;
        auth_code.challenge = Some("test_verifier".to_string());
        assert!(
            !auth_code.verify_pkce("test_verifier"),
            "メソッドがNoneの場合は失敗する必要があります"
        );
    }

    #[test]
    fn test_verify_for_exchange() {
        let user_id = "test_user".to_string();
        let client_id = "client_123";
        let auth_code = AuthCode::new(&user_id, client_id);

        let valid_request = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: auth_code.code.clone(),
            client_id: client_id.to_string(),
        };
        let result = auth_code
            .verify_for_exchange(&valid_request)
            .expect("認可コードの検証に失敗しました");
        assert_eq!(result, "test_user", "検証後のユーザーIDが一致しません");

        let invalid_request = TokenRequest {
            grant_type: "password".to_string(),
            code: "invalid_code".to_string(),
            client_id: client_id.to_string(),
        };
        assert!(
            auth_code.verify_for_exchange(&invalid_request).is_err(),
            "無効なリクエストが検証に成功しました"
        );

        let malicious_request = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: "invalid_code".to_string(),
            client_id: "wrong_client".to_string(),
        };
        assert!(
            auth_code.verify_for_exchange(&malicious_request).is_err(),
            "不正なクライアントIDが検証に成功しました"
        );
    }

    #[test]
    fn test_refresh_token() {
        let refresh_token = RefreshTokenData::generate(30);
        assert_eq!(
            refresh_token.token.len(),
            36,
            "Refreshトークンの長さが期待値と異なります"
        );
        assert!(
            refresh_token.expires_at > chrono::Utc::now().naive_utc(),
            "Refreshトークンの有効期限が現在よりも前になっています"
        );
    }
}
