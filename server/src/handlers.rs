use crate::models::*;
use askama::Template;
use axum::{
    Extension, Form, Json,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
};
use crypto;
use db_client::User;
use jwt_core;
use oauth_flow::{AuthCode, TokenRequest as OAuthTokenReq};
use serde_json;
use uuid::Uuid;

pub async fn health_check() -> &'static str {
    "IdP Server is running, and Database connection is healthy!"
}

pub async fn register_user(
    State(state): State<AppState>,
    Json(payload): Json<RegisterReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let password_hash = match crypto::hash_password(&payload.password) {
        Ok(hash) => hash,
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "パスワードのハッシュ化に失敗しました".to_string(),
            ));
        }
    };

    let user_id = Uuid::new_v4().to_string();
    let new_user = User {
        id: user_id,
        username: payload.username,
        password_hash,
        created_at: None,
        updated_at: None,
    };

    match state.db.create_user(&new_user).await {
        Ok(_) => Ok(StatusCode::CREATED),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("データベースへの保存に失敗しました: {:?}", e),
        )),
    }
}

pub async fn authorize(
    State(state): State<AppState>,
    session: tower_sessions::Session,
    Query(payload): Query<AuthorizeReq>,
) -> Result<Html<String>, (StatusCode, String)> {
    let client = match state.db.get_oauth_client(&payload.client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return Err((StatusCode::BAD_REQUEST, "無効な client_id です".to_string())),
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("クライアントの取得に失敗しました: {:?}", e),
            ));
        }
    };

    if !client.redirect_uris.contains(&payload.redirect_uri) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "リダイレクトURIが無効です".to_string(),
        ));
    }

    session
        .insert("pkce_challenge", payload.code_challenge)
        .await
        .unwrap();
    session
        .insert("pkce_challenge_method", payload.code_challenge_method)
        .await
        .unwrap();

    let template = LoginTemplate {
        client_id: client.id,
        client_name: client.name,
        redirect_uri: payload.redirect_uri,
    };

    let html_string = template.render().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("テンプレートエラー: {}", e),
        )
    })?;

    Ok(Html(html_string))
}

pub async fn login_user(
    State(state): State<AppState>,
    session: tower_sessions::Session,
    Form(payload): Form<LoginReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let client = match state.db.get_oauth_client(&payload.client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                "クライアントが見つかりません".to_string(),
            ));
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("クライアントの取得に失敗しました: {:?}", e),
            ));
        }
    };

    if !client.redirect_uris.contains(&payload.redirect_uri) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "リダイレクトURIが無効です".to_string(),
        ));
    }

    let user = match state.db.get_user_by_name(&payload.username).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                "ユーザー名またはパスワードが間違っています".to_string(),
            ));
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("データベースエラー: {:?}", e),
            ));
        }
    };

    match crypto::verify_password(&payload.password, &user.password_hash) {
        Ok(true) => {}
        Ok(false) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                "ユーザー名またはパスワードが間違っています".to_string(),
            ));
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("パスワードの検証に失敗しました: {:?}", e),
            ));
        }
    };

    if state
        .db
        .has_user_consent(&user.id, &payload.client_id)
        .await
        .expect("同意の確認に失敗しました")
    {
        let mut auth_code = AuthCode::new(&user.id, &payload.client_id);
        auth_code.challenge = session.remove::<String>("pkce_challenge").await.unwrap();
        auth_code.challenge_method = session
            .remove::<String>("pkce_challenge_method")
            .await
            .unwrap();
        state
            .auth_codes
            .lock()
            .unwrap()
            .insert(auth_code.code.clone(), auth_code.clone());

        let redirect_uri = format!("{}?code={}", payload.redirect_uri, auth_code.code);
        return Ok(Redirect::to(&redirect_uri).into_response());
    }

    session
        .insert("authenticated_user_id", &user.id)
        .await
        .unwrap();

    let template = ConsentTemplate {
        client_name: client.name.clone(),
        client_id: payload.client_id.clone(),
        redirect_uri: payload.redirect_uri.clone(),
        username: user.username.clone(),
    };

    let html_str = template.render().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("テンプレートエラー: {}", e),
        )
    })?;

    Ok(Html(html_str).into_response())
}

pub async fn consent(
    State(state): State<AppState>,
    session: tower_sessions::Session,
    Form(payload): Form<ConsentReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if payload.action == "deny" {
        let redirect_url = format!(
            "{}?error=access_denied&error_description=User+denied+access",
            payload.redirect_uri
        );
        return Ok(Redirect::to(&redirect_url));
    }

    if payload.action == "allow" {
        let user_id = session
            .get::<String>("authenticated_user_id")
            .await
            .unwrap()
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "セッションがタイムアウトしました再度ログインしてください。".to_string(),
            ))?;
        state
            .db
            .give_consent(&user_id, &payload.client_id)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("認可の保存に失敗しました: {}", e),
                )
            })?;

        let mut auth_code = AuthCode::new(&user_id, &payload.client_id);
        auth_code.challenge = session.remove::<String>("pkce_challenge").await.unwrap();
        auth_code.challenge_method = session
            .remove::<String>("pkce_challenge_method")
            .await
            .unwrap();

        state
            .auth_codes
            .lock()
            .unwrap()
            .insert(auth_code.code.clone(), auth_code.clone());

        let redirect_uri = format!("{}?code={}", payload.redirect_uri, auth_code.code);
        return Ok(Redirect::to(&redirect_uri));
    }

    Err((StatusCode::BAD_REQUEST, "actionが無効です".to_string()))
}

pub async fn exchange_token(
    State(state): State<AppState>,
    Json(payload): Json<TokenReq>,
) -> Result<Json<TokenRes>, (StatusCode, String)> {
    if payload.grant_type == "authorization_code" {
        let redirect_uri = payload.redirect_uri.ok_or((
            StatusCode::BAD_REQUEST,
            "redirect_uriが必要です".to_string(),
        ))?;
        let client = match state.db.get_oauth_client(&payload.client_id).await {
            Ok(Some(client)) => client,
            Ok(None) => {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "クライアントが見つかりません".to_string(),
                ));
            }
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("クライアントの取得に失敗しました: {:?}", e),
                ));
            }
        };

        if !client.redirect_uris.contains(&redirect_uri) {
            return Err((
                StatusCode::UNAUTHORIZED,
                "リダイレクトURIが無効です".to_string(),
            ));
        }

        let code = payload
            .code
            .ok_or((StatusCode::BAD_REQUEST, "codeが必要です".to_string()))?;
        let auth_code = match state.auth_codes.lock().unwrap().remove(&code) {
            Some(code) => code,
            None => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "無効な認可コード、または使用済みのコードです".to_string(),
                ));
            }
        };

        let verifier = payload.code_verifier.as_ref().ok_or((
            StatusCode::BAD_REQUEST,
            "PKCE code_verifier が必要です".to_string(),
        ))?;

        if !auth_code.verify_pkce(verifier) {
            return Err((
                StatusCode::BAD_REQUEST,
                "PKCEの検証に失敗しました".to_string(),
            ));
        }

        let oauth_req = OAuthTokenReq {
            grant_type: payload.grant_type,
            code: auth_code.code.clone(),
            client_id: payload.client_id.clone(),
        };

        let user_id = match auth_code.verify_for_exchange(&oauth_req) {
            Ok(id) => id,
            Err(e) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("認可コードの検証に失敗しました: {:?}", e),
                ));
            }
        };

        let jwt_string =
            match jwt_core::create_token(&user_id, state.private_key.as_bytes(), &state.kid) {
                Ok(token) => token,
                Err(e) => {
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("JWTの生成に失敗しました: {:?}", e),
                    ));
                }
            };

        let mut id_token = None;
        if let Some(scope) = payload.scope {
            if scope.contains("openid") {
                id_token = match jwt_core::create_id_token(
                    &user_id,
                    &payload.client_id,
                    &state.issuer,
                    state.private_key.as_bytes(),
                    &state.kid.as_str(),
                ) {
                    Ok(token) => Some(token),
                    Err(e) => {
                        println!("IDトークンの生成に失敗: {:?}", e);
                        None
                    }
                }
            }
        }

        let refresh_token = oauth_flow::RefreshTokenData::generate(state.refresh_token_ttl_days);
        let rt = db_client::RefreshToken {
            id: refresh_token.token.clone(),
            user_id: user_id.clone(),
            client_id: payload.client_id.clone(),
            expires_at: refresh_token.expires_at,
        };
        state.db.save_refresh_token(&rt).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("DBエラー: {}", e),
            )
        })?;

        return Ok(Json(TokenRes {
            access_token: jwt_string,
            token_type: "Bearer".to_string(),
            id_token,
            refresh_token: Some(refresh_token.token),
        }));
    } else if payload.grant_type == "refresh_token" {
        let refresh_token = payload.refresh_token.ok_or((
            StatusCode::BAD_REQUEST,
            "refresh_tokenが必要です".to_string(),
        ))?;

        let valid_token = state
            .db
            .get_valid_refresh_token(&refresh_token)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("DBエラー: {}", e),
                )
            })?
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "無効または期限切れのリフレッシュトークンです".to_string(),
            ))?;

        if valid_token.client_id != payload.client_id {
            return Err((
                StatusCode::UNAUTHORIZED,
                "不正なクライアントです".to_string(),
            ));
        }

        let new_access_token = jwt_core::create_token(
            &valid_token.user_id,
            state.private_key.as_bytes(),
            &state.kid,
        )
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("JWTエラー: {}", e),
            )
        })?;

        let new_refresh_token =
            oauth_flow::RefreshTokenData::generate(state.refresh_token_ttl_days);
        let rt = db_client::RefreshToken {
            id: new_refresh_token.token.clone(),
            user_id: valid_token.user_id,
            client_id: payload.client_id.clone(),
            expires_at: new_refresh_token.expires_at,
        };
        state.db.save_refresh_token(&rt).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("DBエラー: {}", e),
            )
        })?;
        state
            .db
            .delete_refresh_token(&refresh_token)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("DBエラー: {}", e),
                )
            })?;

        return Ok(Json(TokenRes {
            access_token: new_access_token,
            token_type: "Bearer".to_string(),
            id_token: None,
            refresh_token: Some(new_refresh_token.token),
        }));
    }

    Err((
        StatusCode::BAD_REQUEST,
        "サポートされていないgrant_typeです".to_string(),
    ))
}

pub async fn get_user_info(
    State(state): State<AppState>,
    Extension(user_id): Extension<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let user = state.db.get_user(&user_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("ユーザーの取得に失敗しました: {:?}", e),
        )
    })?;

    let user = match user {
        Some(user) => user,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                "ユーザーが見つかりません".to_string(),
            ));
        }
    };

    let user_profile = serde_json::json!({
        "message": "JWTの検証に成功しました。正答なアクセス権を確認しました。",
        "user_id": user_id,
        "username": user.username,
    });

    Ok(Json(user_profile))
}

pub async fn revoke_token(
    State(state): State<AppState>,
    Json(payload): Json<RevokeReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    match state.db.delete_refresh_token(&payload.token).await {
        Ok(_) => Ok(StatusCode::OK),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("トークンの無効化に失敗しました: {:?}", e),
        )),
    }
}

pub async fn get_jwks(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let jwks = jwt_core::get_jwks(&state.public_key, &state.kid)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(jwks))
}
