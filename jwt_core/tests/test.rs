#[cfg(test)]
mod tests {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
    use jwt_core::*;

    const TEST_PRIVATE_KEY: &[u8] = include_bytes!("../../keys/private_key.pem");
    const TEST_PUBLIC_KEY: &[u8] = include_bytes!("../../keys/public_key.pem");
    const TEST_KID: &str = "key-1";

    #[test]
    fn test_creat_and_verify_token() {
        let user_id = "user123";

        let token = create_token(user_id, TEST_PRIVATE_KEY, TEST_KID)
            .expect("トークンの作成に失敗しました");
        assert_eq!(
            token.split('.').count(),
            3,
            "トークンは3つの部分から構成されている必要があります"
        );

        let claims = verify_token(&token, TEST_PUBLIC_KEY).expect("トークンの検証に失敗しました");
        assert_eq!(
            claims, user_id,
            "クレームはユーザーIDと一致する必要があります"
        );
    }

    #[test]
    fn test_verify_token_with_wrong_secret() {
        let user_id = "user123";
        let mut token = create_token(user_id, TEST_PRIVATE_KEY, TEST_KID).unwrap();
        token.push_str("invalid_signature_data");

        let result = verify_token(&token, TEST_PUBLIC_KEY);
        assert!(
            result.is_err(),
            "改ざんされたトークンの検証は失敗する必要があります"
        );
    }

    #[test]
    fn test_create_and_verify_id_token() {
        let user_id = "user123";
        let client_id = "client123";
        let issuer = "http://localhost:3000";
        let token = create_id_token(user_id, client_id, issuer, TEST_PRIVATE_KEY, TEST_KID)
            .expect("IDトークンの作成に失敗しました");
        assert_eq!(
            token.split('.').count(),
            3,
            "IDトークンは3つの部分から構成されている必要があります"
        );

        let key = DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY).expect("公開鍵のパースに失敗しました");
        let mut validation = Validation::new(Algorithm::RS256);

        validation.set_audience(&[client_id]);
        validation.set_issuer(&[issuer]);

        let decoded = decode::<IdTokenClaims>(&token, &key, &validation)
            .expect("IDトークンの検証に失敗しました");

        let claims = decoded.claims;
        assert_eq!(claims.sub, user_id, "ユーザーIDが一致しません");
        assert_eq!(claims.aud, client_id, "クライアントIDが一致しません");
        assert_eq!(claims.iss, issuer, "発行者が一致しません");
        assert!(
            claims.exp > claims.iat,
            "expがiatよりも後である必要があります"
        );
        assert_eq!(
            claims.exp - claims.iat,
            3600,
            "有効期限が1時間ではありません"
        )
    }

    #[test]
    fn test_verify_id_token_with_wrong_secret() {
        let user_id = "user123";
        let client_id = "client123";
        let issuer = "http://localhost:3000";
        let mut token = create_id_token(user_id, client_id, issuer, TEST_PRIVATE_KEY, TEST_KID)
            .expect("IDトークンの作成に失敗しました");

        token.push_str("invalid_signature_data");
        let key = DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY).expect("公開鍵のパースに失敗しました");
        let mut validation = Validation::new(Algorithm::RS256);

        validation.set_audience(&[client_id]);
        validation.set_issuer(&[issuer]);

        let result = decode::<IdTokenClaims>(&token, &key, &validation);
        assert!(
            result.is_err(),
            "間違ったシークレットでの検証は失敗する必要があります"
        );
    }

    #[test]
    fn test_get_jwks_structure() {
        let jwks = get_jwks(std::str::from_utf8(TEST_PUBLIC_KEY).unwrap(), TEST_KID)
            .expect("JWKSの取得に失敗しました");
        assert!(jwks.is_object(), "JWKSはオブジェクトである必要があります");

        let keys = jwks["keys"]
            .as_array()
            .expect("keysは配列である必要があります");
        assert_eq!(keys.len(), 1);

        let key = &keys[0];
        assert_eq!(key["kty"], "RSA");
        assert_eq!(key["alg"], "RS256");
        assert_eq!(key["use"], "sig");
        assert_eq!(key["kid"], TEST_KID);
        assert!(!key["n"].as_str().unwrap().is_empty());
        assert!(!key["e"].as_str().unwrap().is_empty());
    }
}
