use crate::models::*;
use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::Redirect,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use rand::distr::{Alphanumeric, SampleString};
use sha2::{Digest, Sha256};
use tower_sessions::Session;

fn internal_err(err: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

async fn fetch_decoding_key(
    state: &AppState,
    kid: &str,
) -> Result<DecodingKey, (StatusCode, String)> {
    let mut target_jwk = {
        let cache = state.jwks_cache.read().await;
        cache.get(kid).cloned()
    };

    if target_jwk.is_none() {
        let jwks_url = format!("{}/.well-known/jwks.json", state.idp_base_url);
        let jwks_res = state
            .reqwest_client
            .get(jwks_url)
            .send()
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("JWKS取得エラー: {}", e)))?;

        if !jwks_res.status().is_success() {
            return Err((
                StatusCode::BAD_GATEWAY,
                "JWKSエンドポイントがエラーを返しました".to_string(),
            ));
        }

        let jwks: Jwks = jwks_res.json().await.map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("JWKS JSONパースエラー: {}", e),
            )
        })?;

        let mut cache = state.jwks_cache.write().await;
        for key in jwks.keys {
            if key.kid == kid {
                target_jwk = Some(key.clone());
            }
            cache.insert(key.kid.clone(), key);
        }
    }

    let target_key = target_jwk.ok_or((
        StatusCode::BAD_REQUEST,
        "対応する公開鍵が見つかりません".to_string(),
    ))?;

    DecodingKey::from_rsa_components(&target_key.n, &target_key.e)
        .map_err(|e| internal_err(format!("公開鍵の構築エラー: {}", e)))
}

async fn extract_access_token(
    headers: &HeaderMap,
    session: &Session,
) -> Result<String, (StatusCode, String)> {
    if let Some(auth_header) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            return Ok(token.to_string());
        }
        return Err((
            StatusCode::UNAUTHORIZED,
            "Authorizationヘッダーの形式が正しくありません".to_string(),
        ));
    }

    let tokens = session
        .get::<SessionTokens>("tokens")
        .await
        .map_err(internal_err)?
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "ログインセッションが見つかりません".to_string(),
        ))?;

    Ok(tokens.access_token)
}

pub async fn login(
    State(state): State<AppState>,
    session: Session,
) -> Result<Redirect, (StatusCode, String)> {
    let code_verifier = Alphanumeric.sample_string(&mut rand::rng(), 64);
    let state_val = Alphanumeric.sample_string(&mut rand::rng(), 32);
    let nonce = Alphanumeric.sample_string(&mut rand::rng(), 32);

    session
        .insert("code_verifier", &code_verifier)
        .await
        .map_err(internal_err)?;
    session
        .insert("oauth_state", &state_val)
        .await
        .map_err(internal_err)?;
    session
        .insert("oauth_nonce", &nonce)
        .await
        .map_err(internal_err)?;

    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let code_challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());

    let redirect_uri = format!("{}/callback", state.client_url);
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", &state.client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", "openid profile")
        .append_pair("state", &state_val)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &code_challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();

    let authorize_url = format!("{}/authorize?{}", state.idp_base_url, query);
    Ok(Redirect::to(&authorize_url))
}

pub async fn callback(
    State(state): State<AppState>,
    session: Session,
    Query(query): Query<CallbackQuery>,
) -> Result<Redirect, (StatusCode, String)> {
    if let Some(err) = query.error {
        let desc = query.error_description.unwrap_or_default();
        return Err((
            StatusCode::BAD_REQUEST,
            format!("認可が拒否されました: {} ({})", err, desc),
        ));
    }

    let expected_state = session
        .remove::<String>("oauth_state")
        .await
        .map_err(internal_err)?
        .ok_or((
            StatusCode::BAD_REQUEST,
            "stateセッションが見つかりません".to_string(),
        ))?;

    if query.state.as_deref() != Some(expected_state.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "stateが一致しません（CSRF検知）".to_string(),
        ));
    }

    let code_verifier = session
        .remove::<String>("code_verifier")
        .await
        .map_err(internal_err)?
        .ok_or((
            StatusCode::BAD_REQUEST,
            "PKCEセッションが見つかりません".to_string(),
        ))?;

    let expected_nonce = session
        .remove::<String>("oauth_nonce")
        .await
        .map_err(internal_err)?;

    let code = query.code.ok_or((
        StatusCode::BAD_REQUEST,
        "コードが提供されていません".to_string(),
    ))?;

    let redirect_uri = format!("{}/callback", state.client_url);
    let token_req = IdpTokenReq {
        grant_type: "authorization_code".to_string(),
        code,
        redirect_uri,
        code_verifier,
    };

    let token_url = format!("{}/token", state.idp_base_url);
    let token_res = state
        .reqwest_client
        .post(token_url)
        .basic_auth(&state.client_id, Some(&state.client_secret))
        .form(&token_req)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("トークンの交換に失敗しました: {}", e),
            )
        })?;

    if !token_res.status().is_success() {
        let msg = token_res.text().await.unwrap_or_default();
        return Err((
            StatusCode::BAD_REQUEST,
            format!("IdPがエラーを返しました: {}", msg),
        ));
    }

    let idp_token_data: IdpTokenRes = token_res.json().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("トークンの解析に失敗しました: {}", e),
        )
    })?;

    if let Some(ref id_token) = idp_token_data.id_token {
        let header = decode_header(id_token).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("IDトークンヘッダー解析エラー: {}", e),
            )
        })?;
        let kid = header.kid.ok_or((
            StatusCode::BAD_REQUEST,
            "IDトークンにkidが含まれていません".to_string(),
        ))?;
        let decoding_key = fetch_decoding_key(&state, &kid).await?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&state.idp_base_url]);
        validation.set_audience(&[&state.client_id]);

        let decoded =
            decode::<IdTokenClaims>(id_token, &decoding_key, &validation).map_err(|e| {
                (
                    StatusCode::UNAUTHORIZED,
                    format!("IDトークンの検証に失敗しました: {}", e),
                )
            })?;

        if decoded.claims.nonce.as_deref() != expected_nonce.as_deref() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "IDトークンのnonceが一致しません".to_string(),
            ));
        }
    }

    let tokens = SessionTokens {
        access_token: idp_token_data.access_token,
        id_token: idp_token_data.id_token,
        refresh_token: idp_token_data.refresh_token,
    };

    session
        .insert("tokens", tokens)
        .await
        .map_err(internal_err)?;
    session.cycle_id().await.map_err(internal_err)?;

    Ok(Redirect::to("/"))
}

pub async fn get_session(
    session: Session,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tokens = session
        .get::<SessionTokens>("tokens")
        .await
        .map_err(internal_err)?;

    match tokens {
        Some(t) => Ok(Json(serde_json::json!({
            "logged_in": true,
            "access_token": t.access_token,
            "id_token": t.id_token,
        }))),
        None => Ok(Json(serde_json::json!({
            "logged_in": false,
        }))),
    }
}

pub async fn get_userinfo(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let access_token = extract_access_token(&headers, &session).await?;

    let userinfo_url = format!("{}/userinfo", state.idp_base_url);
    let res = state
        .reqwest_client
        .get(userinfo_url)
        .bearer_auth(&access_token)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("IdP通信エラー: {}", e)))?;

    if !res.status().is_success() {
        return Err((res.status(), "ユーザー情報の取得に失敗しました".to_string()));
    }

    let data: serde_json::Value = res
        .json()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("JSONパースエラー: {}", e)))?;

    Ok(Json(data))
}

pub async fn verify_token(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let token = extract_access_token(&headers, &session).await?;

    let header = decode_header(&token).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("ヘッダー解析エラー: {}", e),
        )
    })?;
    let kid = header
        .kid
        .ok_or((StatusCode::BAD_REQUEST, "kidが含まれていません".to_string()))?;

    let decoding_key = fetch_decoding_key(&state, &kid).await?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[&state.idp_base_url]);
    validation.set_audience(&[&state.client_id]);

    let token_data = decode::<Claims>(&token, &decoding_key, &validation).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            format!("トークンの検証に失敗しました: {}", e),
        )
    })?;

    Ok(Json(serde_json::json!({
        "message": "ローカル検証に成功しました！",
        "claims": token_data.claims
    })))
}

pub async fn refresh(
    State(state): State<AppState>,
    session: Session,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut tokens = session
        .get::<SessionTokens>("tokens")
        .await
        .map_err(internal_err)?
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "ログインセッションが見つかりません".to_string(),
        ))?;

    let refresh_token = tokens.refresh_token.clone().ok_or((
        StatusCode::BAD_REQUEST,
        "リフレッシュトークンがありません".to_string(),
    ))?;

    let token_req = RefreshTokenReq {
        grant_type: "refresh_token".to_string(),
        refresh_token,
    };

    let token_url = format!("{}/token", state.idp_base_url);
    let res = state
        .reqwest_client
        .post(token_url)
        .basic_auth(&state.client_id, Some(&state.client_secret))
        .form(&token_req)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("IdP通信エラー: {}", e)))?;

    if !res.status().is_success() {
        let error_msg = res.text().await.unwrap_or_default();
        return Err((
            StatusCode::BAD_REQUEST,
            format!("トークンのリフレッシュに失敗しました: {}", error_msg),
        ));
    }

    let data: IdpTokenRes = res.json().await.map_err(internal_err)?;

    tokens.access_token = data.access_token.clone();
    if let Some(new_rt) = data.refresh_token {
        tokens.refresh_token = Some(new_rt);
    }
    if data.id_token.is_some() {
        tokens.id_token = data.id_token;
    }

    session
        .insert("tokens", tokens)
        .await
        .map_err(internal_err)?;

    Ok(Json(serde_json::json!({
        "access_token": data.access_token,
        "token_type": data.token_type,
        "expires_in": data.expires_in,
    })))
}

pub async fn logout(
    State(state): State<AppState>,
    session: Session,
) -> Result<StatusCode, (StatusCode, String)> {
    if let Some(tokens) = session
        .get::<SessionTokens>("tokens")
        .await
        .map_err(internal_err)?
    {
        if let Some(refresh_token) = tokens.refresh_token {
            let revoke_url = format!("{}/revoke", state.idp_base_url);
            let res = state
                .reqwest_client
                .post(revoke_url)
                .basic_auth(&state.client_id, Some(&state.client_secret))
                .form(&[
                    ("token", refresh_token.as_str()),
                    ("token_type_hint", "refresh_token"),
                ])
                .send()
                .await
                .map_err(|e| (StatusCode::BAD_GATEWAY, format!("IdP通信エラー: {}", e)))?;

            if !res.status().is_success() {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    "IdPでのログアウト処理に失敗しました".to_string(),
                ));
            }
        }
    }

    session.flush().await.map_err(internal_err)?;
    Ok(StatusCode::OK)
}
