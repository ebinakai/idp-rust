use crate::{
    error::AppError,
    handlers::{authenticate_client, extract_client_credentials},
    models::*,
};
use axum::{
    Extension, Form, Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};

pub async fn get_openid_config(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "issuer": state.issuer,
        "authorization_endpoint": format!("{}/authorize", state.issuer),
        "token_endpoint": format!("{}/token", state.issuer),
        "userinfo_endpoint": format!("{}/userinfo", state.issuer),
        "revocation_endpoint": format!("{}/revoke", state.issuer),
        "jwks_uri": format!("{}/.well-known/jwks.json", state.issuer),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "nonce", "preferred_username", "name"],
        "code_challenge_methods_supported": ["S256", "plain"],
    }))
}

pub async fn get_jwks(State(state): State<AppState>) -> Result<Json<serde_json::Value>, AppError> {
    let jwks = jwt_core::get_jwks(&state.public_key, &state.kid).map_err(AppError::internal)?;
    Ok(Json(jwks))
}

pub async fn get_user_info(
    State(state): State<AppState>,
    Extension(claims): Extension<jwt_core::Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user = state
        .db
        .get_user(&claims.sub)
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| AppError::not_found("ユーザーが見つかりません"))?;

    Ok(Json(serde_json::json!({
        "sub": user.id,
        "preferred_username": user.username,
        "name": user.username,
    })))
}

pub async fn revoke_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(payload): Form<RevokeReq>,
) -> Result<StatusCode, AppError> {
    let (client_id, client_secret) = extract_client_credentials(
        &headers,
        payload.client_id.as_deref(),
        payload.client_secret.as_deref(),
    )?;
    let client = authenticate_client(&state.db, &client_id, client_secret.as_deref()).await?;

    if let Some(rt) = state
        .db
        .get_valid_refresh_token(&payload.token)
        .await
        .map_err(AppError::internal)?
    {
        if rt.client_id != client.id {
            return Err(AppError::invalid_client(
                "このトークンを無効化する権限がありません",
            ));
        }

        state
            .db
            .delete_refresh_token(&payload.token)
            .await
            .map_err(AppError::internal)?;
    }

    Ok(StatusCode::OK)
}
