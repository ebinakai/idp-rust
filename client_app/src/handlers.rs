use crate::models::*;
use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Redirect,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use rand::distr::{Alphanumeric, SampleString};
use serde_json::{self};
use sha2::{Digest, Sha256};
use tower_sessions;

pub async fn login(
    State(state): State<AppState>,
    session: tower_sessions::Session,
) -> Result<Redirect, (StatusCode, String)> {
    let code_verifier = Alphanumeric.sample_string(&mut rand::rng(), 64);
    session
        .insert("code_verifier", code_verifier.clone())
        .await
        .unwrap();

    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let code_challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());

    let redirect_uri = format!("{}/callback", state.client_url);
    let authorize_url = format!(
        "{}/authorize?client_id={}&redirect_uri={}&response_type=code&code_challenge={}&code_challenge_method=S256",
        state.idp_base_url, state.client_id, redirect_uri, code_challenge
    );
    Ok(Redirect::to(&authorize_url))
}

pub async fn callback(
    State(state): State<AppState>,
    session: tower_sessions::Session,
    Query(query): Query<CallbackQuery>,
) -> Result<Json<ClientRes>, (StatusCode, String)> {
    if query.error.is_some() {
        return Err((StatusCode::BAD_REQUEST, "認可が拒否されました".to_string()));
    }

    let code = query.code.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "コードが提供されていません".to_string(),
        )
    })?;

    let code_verifier = session
        .remove::<String>("code_verifier")
        .await
        .unwrap()
        .ok_or((
            StatusCode::BAD_REQUEST,
            "PKCEセッションが見つかりません".to_string(),
        ))?;
    let redirect_uri = format!("{}/callback", state.client_url);
    let token_req = IdpTokenReq {
        grant_type: "authorization_code".to_string(),
        code: code,
        client_id: state.client_id.to_string(),
        client_secret: state.client_secret.to_string(),
        scope: Some("openid".to_string()),
        redirect_uri: redirect_uri,
        code_verifier: code_verifier,
    };

    let token_url = format!("{}/token", state.idp_base_url);
    let token_res = state
        .reqwest_client
        .post(token_url)
        .json(&token_req)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("トークンの交換に失敗しました: {}", e),
            )
        })?;

    if !token_res.status().is_success() {
        return Err((
            StatusCode::BAD_REQUEST,
            "IdPがエラーを返しました".to_string(),
        ));
    }

    let idp_token_data: IdpTokenRes = token_res.json().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("トークンの解析に失敗しました: {}", e),
        )
    })?;

    Ok(Json(ClientRes {
        access_token: idp_token_data.access_token,
        id_token: idp_token_data.id_token,
        refresh_token: idp_token_data.refresh_token,
    }))
}

pub async fn get_userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "トークンが見つかりません".to_string(),
        ))?;

    let userinfo_url = format!("{}/userinfo", state.idp_base_url);
    let res = state
        .reqwest_client
        .get(userinfo_url)
        .header("Authorization", auth_header)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Idp通信エラー: {}", e),
            )
        })?;

    if !res.status().is_success() {
        return Err((
            res.status(),
            "ユーザーの情報の取得に失敗しいました".to_string(),
        ));
    }

    let data: serde_json::Value = res.json().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("JSONパースエラー: {}", e),
        )
    })?;

    Ok(Json(data))
}

pub async fn verify_token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "トークンが見つかりません".to_string(),
        ))?;

    let token = if auth_header.starts_with("Bearer ") {
        &auth_header[7..]
    } else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Authorizationヘッダーの形式が正しくありません".to_string(),
        ));
    };

    let header = decode_header(token).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("ヘッダー解析エラー: {}", e),
        )
    })?;
    let kid = header
        .kid
        .ok_or((StatusCode::BAD_REQUEST, "kidが含まれていません".to_string()))?;

    let mut target_jwk = None;
    {
        let cache = state.jwks_cache.read().await;
        if let Some(jwk) = cache.get(&kid) {
            target_jwk = Some(jwk.clone());
        }
    }

    if target_jwk.is_none() {
        println!("キャッシュミス: IdPからJWKSを取得します（kid: {}）", kid);
        let jwks_url = format!("{}/.well-known/jwks.json", state.idp_base_url);
        let jwks_res = state
            .reqwest_client
            .get(jwks_url)
            .send()
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("JWKS取得エラー: {}", e),
                )
            })?;

        let jwks: Jwks = jwks_res.json().await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("JWKS JSONパースエラー: {}", e),
            )
        })?;

        let mut cache = state.jwks_cache.write().await;
        for key in jwks.keys {
            cache.insert(key.kid.clone(), key.clone());
            if key.kid == kid {
                target_jwk = Some(key.clone());
            }
        }
    }

    let target_key = target_jwk.ok_or((
        StatusCode::BAD_REQUEST,
        "対応する公開鍵が見つかりません".to_string(),
    ))?;

    let decoding_key =
        DecodingKey::from_rsa_components(&target_key.n, &target_key.e).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("公開鍵の構築エラー: {}", e),
            )
        })?;

    let validation = Validation::new(Algorithm::RS256);
    let token_data = decode::<Claims>(token, &decoding_key, &validation).map_err(|e| {
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
    Json(payload): Json<RefreshReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let token_req = RefreshTokenReq {
        grant_type: "refresh_token".to_string(),
        refresh_token: payload.refresh_token,
        client_id: state.client_id.to_string(),
    };

    let token_url = format!("{}/token", state.idp_base_url);
    let res = state
        .reqwest_client
        .post(token_url)
        .json(&token_req)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("IdPとの通信エラー: {}", e),
            )
        })?;

    if res.status().is_success() {
        let data: serde_json::Value = res.json().await.unwrap();
        Ok(Json(data))
    } else {
        let error_msg = res.text().await.unwrap_or_default();
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("トークンのリフレッシュに失敗しました: {}", error_msg),
        ))
    }
}

pub async fn logout(
    State(state): State<AppState>,
    Json(payload): Json<LogoutReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let request_body = serde_json::json!({
        "token": payload.refresh_token,
    });

    let revoke_url = format!("{}/revoke", state.idp_base_url);
    let res = state
        .reqwest_client
        .post(revoke_url)
        .json(&request_body)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("IdPとの通信エラー: {}", e),
            )
        })?;

    if res.status().is_success() {
        Ok(StatusCode::OK)
    } else {
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "IdPでのログアウト処理に失敗しました".to_string(),
        ))
    }
}
