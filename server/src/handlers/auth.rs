use crate::{error::AppError, handlers::require_admin, models::*};
use axum::{
    Form, Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use db_client::{DbClient, OAuthClient, User};
use oauth_flow::{AuthCode, TokenRequest as OAuthTokenReq};
use std::path::Path;
use uuid::Uuid;

fn build_redirect_url(base: &str, params: &[(&str, &str)]) -> String {
    if params.is_empty() {
        return base.to_string();
    }
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (k, v) in params {
        serializer.append_pair(k, v);
    }
    let sep = if base.contains('?') { '&' } else { '?' };
    format!("{}{}{}", base, sep, serializer.finish())
}

fn decode_form_component(raw: &str) -> String {
    let query = format!("k={}", raw);
    form_urlencoded::parse(query.as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| raw.to_string())
}

fn format_scopes(scope: Option<&str>) -> Vec<String> {
    let Some(raw) = scope else {
        return vec!["基本プロフィール情報（ユーザーID・ユーザー名）".to_string()];
    };
    let list: Vec<String> = raw
        .split_whitespace()
        .map(|s| match s {
            "openid" => "openid: OpenID 認証（ユーザー識別子）".to_string(),
            "profile" => "profile: 基本プロフィール（ユーザー名）".to_string(),
            other => other.to_string(),
        })
        .collect();
    if list.is_empty() {
        vec!["基本プロフィール情報（ユーザーID・ユーザー名）".to_string()]
    } else {
        list
    }
}

fn token_response_headers() -> [(header::HeaderName, &'static str); 2] {
    [
        (header::CACHE_CONTROL, "no-store"),
        (header::PRAGMA, "no-cache"),
    ]
}

pub fn extract_client_credentials(
    headers: &HeaderMap,
    form_client_id: Option<&str>,
    form_client_secret: Option<&str>,
) -> Result<(String, Option<String>), AppError> {
    let form_id = form_client_id.filter(|s| !s.is_empty());
    let form_secret = form_client_secret.filter(|s| !s.is_empty());

    if let Some(auth_header) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if auth_header
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("Basic "))
        {
            if form_secret.is_some() {
                return Err(AppError::invalid_request(
                    "複数のクライアント認証方式を同時に使用できません",
                ));
            }

            let decoded_bytes = STANDARD
                .decode(auth_header[6..].trim())
                .map_err(|_| AppError::invalid_client("Authorization Basicヘッダーが不正です"))?;
            let decoded = String::from_utf8(decoded_bytes)
                .map_err(|_| AppError::invalid_client("Authorization Basicヘッダーが不正です"))?;
            let (raw_id, raw_secret) = decoded
                .split_once(':')
                .ok_or_else(|| AppError::invalid_client("Authorization Basicヘッダーが不正です"))?;

            let client_id = decode_form_component(raw_id);
            if client_id.is_empty() {
                return Err(AppError::invalid_client("client_idが必要です"));
            }
            if let Some(fid) = form_id
                && fid != client_id
            {
                return Err(AppError::invalid_request(
                    "Basic認証とフォームのclient_idが一致しません",
                ));
            }

            let decoded_secret = decode_form_component(raw_secret);
            let secret = if decoded_secret.is_empty() {
                None
            } else {
                Some(decoded_secret)
            };
            return Ok((client_id, secret));
        }
    }

    let client_id = form_id
        .ok_or_else(|| AppError::invalid_client("client_idが必要です"))?
        .to_string();
    Ok((client_id, form_secret.map(str::to_string)))
}

pub async fn authenticate_client(
    db: &DbClient,
    client_id: &str,
    provided_secret: Option<&str>,
) -> Result<OAuthClient, AppError> {
    let client = db
        .get_oauth_client(client_id)
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| AppError::invalid_client("クライアントが見つかりません"))?;

    if let Some(expected_secret) = client.secret.clone() {
        let provided = provided_secret
            .ok_or_else(|| AppError::invalid_client("このクライアントは client_secret が必要です"))?
            .to_string();

        let valid =
            tokio::task::spawn_blocking(move || crypto::verify_secret(&provided, &expected_secret))
                .await
                .map_err(AppError::internal)?
                .unwrap_or(false);

        if !valid {
            return Err(AppError::invalid_client("client_secret が不正です"));
        }
    }

    Ok(client)
}

fn issue_auth_code_url(
    state: &AppState,
    user_id: &str,
    pending: PendingAuth,
) -> Result<String, AppError> {
    let mut auth_code = AuthCode::new(user_id, &pending.client_id, &pending.redirect_uri);
    auth_code.scope = pending.scope;
    auth_code.nonce = pending.nonce;
    auth_code.challenge = pending.code_challenge;
    auth_code.challenge_method = pending.code_challenge_method;

    {
        let mut codes = state
            .auth_codes
            .lock()
            .map_err(|_| AppError::internal("auth_codes mutex poisoned"))?;
        codes.retain(|_, v| v.is_valid());
        codes.insert(auth_code.code.clone(), auth_code.clone());
    }

    let mut params: Vec<(&str, &str)> = vec![("code", &auth_code.code)];
    if let Some(ref st) = pending.state {
        params.push(("state", st));
    }

    Ok(build_redirect_url(&pending.redirect_uri, &params))
}

pub async fn register_user(
    State(state): State<AppState>,
    session: tower_sessions::Session,
    Json(payload): Json<RegisterReq>,
) -> Result<StatusCode, AppError> {
    if payload.username.trim().is_empty() || payload.password.is_empty() {
        return Err(AppError::invalid_request("username と password が必要です"));
    }

    let user_count = state.db.count_users().await.map_err(AppError::internal)?;

    let (grant_admin, auto_login) = if user_count == 0 {
        (true, true)
    } else if state.allow_self_register {
        let caller_is_admin = require_admin(&state, &session).await.is_ok();
        (caller_is_admin && payload.is_admin, false)
    } else {
        require_admin(&state, &session).await?;
        (payload.is_admin, false)
    };

    let password = payload.password;
    let password_hash = tokio::task::spawn_blocking(move || crypto::hash_secret(&password))
        .await
        .map_err(AppError::internal)?
        .map_err(|e| AppError::internal(format!("パスワードのハッシュ化に失敗しました: {}", e)))?;

    let new_user = User {
        id: Uuid::new_v4().to_string(),
        username: payload.username.trim().to_string(),
        password_hash,
        is_admin: grant_admin,
        created_at: None,
        updated_at: None,
    };

    state
        .db
        .create_user(&new_user)
        .await
        .map_err(AppError::internal)?;

    if auto_login {
        session.cycle_id().await.map_err(AppError::internal)?;
        session
            .insert("account_user_id", &new_user.id)
            .await
            .map_err(AppError::internal)?;
    }

    Ok(StatusCode::CREATED)
}

pub async fn authorize(
    State(state): State<AppState>,
    session: tower_sessions::Session,
    Query(payload): Query<AuthorizeReq>,
) -> Result<Html<String>, AppError> {
    let client = state
        .db
        .get_oauth_client(&payload.client_id)
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| AppError::invalid_request("無効な client_id です"))?;

    if !client.redirect_uris.contains(&payload.redirect_uri) {
        return Err(AppError::invalid_request("リダイレクトURIが無効です"));
    }

    if payload.response_type != "code" {
        return Err(AppError::invalid_request(
            "response_type は code のみサポートしています",
        ));
    }

    if client.secret.is_none() && payload.code_challenge.is_none() {
        return Err(AppError::invalid_request(
            "パブリッククライアントは PKCE (code_challenge) が必須です",
        ));
    }

    let normalized_method = if let Some(ref challenge) = payload.code_challenge {
        if challenge.is_empty() {
            return Err(AppError::invalid_request("code_challenge が空です"));
        }
        match payload.code_challenge_method.as_deref() {
            None => Some("plain".to_string()),
            Some(m) if m.eq_ignore_ascii_case("S256") => Some("S256".to_string()),
            Some(m) if m.eq_ignore_ascii_case("plain") => Some("plain".to_string()),
            Some(_) => {
                return Err(AppError::invalid_request(
                    "サポートされていない code_challenge_method です",
                ));
            }
        }
    } else {
        None
    };

    let pending = PendingAuth {
        client_id: client.id,
        redirect_uri: payload.redirect_uri,
        scope: payload.scope.filter(|s| !s.trim().is_empty()),
        state: payload.state.filter(|s| !s.is_empty()),
        nonce: payload.nonce.filter(|s| !s.is_empty()),
        code_challenge: payload.code_challenge,
        code_challenge_method: normalized_method,
    };

    session
        .insert("pending_auth", pending)
        .await
        .map_err(AppError::internal)?;

    let index_path = Path::new(&state.frontend_dir).join("index.html");
    let html = tokio::fs::read_to_string(&index_path)
        .await
        .map_err(AppError::internal)?;

    Ok(Html(html))
}

pub async fn get_auth_context(
    State(state): State<AppState>,
    session: tower_sessions::Session,
) -> Result<Json<AuthContextRes>, AppError> {
    let pending = session
        .get::<PendingAuth>("pending_auth")
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| {
            AppError::invalid_request(
                "認可セッションが見つかりません。クライアントアプリからやり直してください",
            )
        })?;

    let client = state
        .db
        .get_oauth_client(&pending.client_id)
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| AppError::invalid_client("クライアントが見つかりません"))?;

    Ok(Json(AuthContextRes {
        client_id: client.id,
        client_name: client.name,
        scopes: format_scopes(pending.scope.as_deref()),
    }))
}

pub async fn complete_authorize_login(
    state: &AppState,
    session: &tower_sessions::Session,
    user: &User,
) -> Result<AuthActionRes, AppError> {
    let pending = session
        .get::<PendingAuth>("pending_auth")
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| {
            AppError::invalid_request("認可セッションが見つかりません。最初からやり直してください")
        })?;

    let client = state
        .db
        .get_oauth_client(&pending.client_id)
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| AppError::invalid_client("クライアントが見つかりません"))?;

    if !client.redirect_uris.contains(&pending.redirect_uri) {
        return Err(AppError::invalid_request("リダイレクトURIが無効です"));
    }

    session.cycle_id().await.map_err(AppError::internal)?;
    session
        .insert("account_user_id", &user.id)
        .await
        .map_err(AppError::internal)?;

    if state
        .db
        .has_user_consent(&user.id, &pending.client_id)
        .await
        .map_err(AppError::internal)?
    {
        session
            .remove::<PendingAuth>("pending_auth")
            .await
            .map_err(AppError::internal)?;
        let redirect_uri = issue_auth_code_url(state, &user.id, pending)?;
        return Ok(AuthActionRes::Redirect { redirect_uri });
    }

    session
        .insert("authenticated_user_id", &user.id)
        .await
        .map_err(AppError::internal)?;

    Ok(AuthActionRes::Consent {
        client_name: client.name,
        username: user.username.clone(),
        scopes: format_scopes(pending.scope.as_deref()),
    })
}

pub async fn login_user(
    State(state): State<AppState>,
    session: tower_sessions::Session,
    Json(payload): Json<LoginReq>,
) -> Result<Json<AuthActionRes>, AppError> {
    let user = state
        .db
        .get_user_by_name(&payload.username)
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| AppError::unauthorized("ユーザー名またはパスワードが間違っています"))?;

    let password = payload.password;
    let password_hash = user.password_hash.clone();
    let is_valid =
        tokio::task::spawn_blocking(move || crypto::verify_secret(&password, &password_hash))
            .await
            .map_err(AppError::internal)?
            .map_err(AppError::internal)?;

    if !is_valid {
        return Err(AppError::unauthorized(
            "ユーザー名またはパスワードが間違っています",
        ));
    }

    let action = complete_authorize_login(&state, &session, &user).await?;
    Ok(Json(action))
}

pub async fn consent(
    State(state): State<AppState>,
    session: tower_sessions::Session,
    Json(payload): Json<ConsentReq>,
) -> Result<Json<AuthActionRes>, AppError> {
    let pending = session
        .remove::<PendingAuth>("pending_auth")
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| {
            AppError::invalid_request("認可セッションが期限切れです。最初からやり直してください")
        })?;

    let client = state
        .db
        .get_oauth_client(&pending.client_id)
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| AppError::invalid_client("クライアントが見つかりません"))?;

    if !client.redirect_uris.contains(&pending.redirect_uri) {
        return Err(AppError::invalid_request("リダイレクトURIが無効です"));
    }

    if payload.action == "deny" {
        let _ = session.remove::<String>("authenticated_user_id").await;
        let mut params: Vec<(&str, &str)> = vec![
            ("error", "access_denied"),
            ("error_description", "User denied access"),
        ];
        if let Some(ref st) = pending.state {
            params.push(("state", st));
        }
        return Ok(Json(AuthActionRes::Redirect {
            redirect_uri: build_redirect_url(&pending.redirect_uri, &params),
        }));
    }

    if payload.action == "allow" {
        let user_id = session
            .remove::<String>("authenticated_user_id")
            .await
            .map_err(AppError::internal)?
            .ok_or_else(|| {
                AppError::unauthorized("セッションがタイムアウトしました。再度ログインしてください")
            })?;

        state
            .db
            .give_consent(&user_id, &pending.client_id)
            .await
            .map_err(AppError::internal)?;

        let redirect_uri = issue_auth_code_url(&state, &user_id, pending)?;
        return Ok(Json(AuthActionRes::Redirect { redirect_uri }));
    }

    Err(AppError::invalid_request("actionが無効です"))
}

pub async fn exchange_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(payload): Form<TokenReq>,
) -> Result<impl IntoResponse, AppError> {
    let (client_id, client_secret) = extract_client_credentials(
        &headers,
        payload.client_id.as_deref(),
        payload.client_secret.as_deref(),
    )?;
    let client = authenticate_client(&state.db, &client_id, client_secret.as_deref()).await?;

    if payload.grant_type == "authorization_code" {
        let redirect_uri = payload
            .redirect_uri
            .ok_or_else(|| AppError::invalid_request("redirect_uriが必要です"))?;

        if !client.redirect_uris.contains(&redirect_uri) {
            return Err(AppError::invalid_grant("リダイレクトURIが無効です"));
        }

        let code = payload
            .code
            .ok_or_else(|| AppError::invalid_request("codeが必要です"))?;

        let auth_code = {
            let mut codes = state
                .auth_codes
                .lock()
                .map_err(|_| AppError::internal("auth_codes mutex poisoned"))?;
            codes.remove(&code)
        }
        .ok_or_else(|| AppError::invalid_grant("無効な認可コード、または使用済みのコードです"))?;

        if !auth_code.verify_pkce(payload.code_verifier.as_deref()) {
            return Err(AppError::invalid_grant("PKCEの検証に失敗しました"));
        }

        let oauth_req = OAuthTokenReq {
            grant_type: payload.grant_type,
            code: code.clone(),
            client_id: client.id.clone(),
            redirect_uri,
        };

        let user_id = auth_code
            .verify_for_exchange(&oauth_req)
            .map_err(AppError::invalid_grant)?;

        let access_token = jwt_core::create_token(
            &user_id,
            &client.id,
            &state.issuer,
            auth_code.scope.as_deref(),
            state.private_key.as_bytes(),
            &state.kid,
        )
        .map_err(AppError::internal)?;

        let has_openid = auth_code
            .scope
            .as_deref()
            .is_some_and(|s| s.split_whitespace().any(|part| part == "openid"));

        let id_token = if has_openid {
            let user = state
                .db
                .get_user(&user_id)
                .await
                .map_err(AppError::internal)?
                .ok_or_else(|| AppError::invalid_grant("ユーザーが見つかりません"))?;
            Some(
                jwt_core::create_id_token(
                    &user_id,
                    &client.id,
                    &state.issuer,
                    auth_code.nonce.as_deref(),
                    Some(user.username.as_str()),
                    state.private_key.as_bytes(),
                    &state.kid,
                )
                .map_err(AppError::internal)?,
            )
        } else {
            None
        };

        let refresh_token = oauth_flow::RefreshTokenData::generate(state.refresh_token_ttl_days);
        let rt = db_client::RefreshToken {
            id: refresh_token.token.clone(),
            user_id,
            client_id: client.id,
            expires_at: refresh_token.expires_at,
        };
        state
            .db
            .save_refresh_token(&rt)
            .await
            .map_err(AppError::internal)?;

        return Ok((
            token_response_headers(),
            Json(TokenRes {
                access_token,
                token_type: "Bearer".to_string(),
                expires_in: jwt_core::ACCESS_TOKEN_TTL_SECS,
                scope: auth_code.scope,
                id_token,
                refresh_token: Some(refresh_token.token),
            }),
        ));
    }

    if payload.grant_type == "refresh_token" {
        let refresh_token = payload
            .refresh_token
            .ok_or_else(|| AppError::invalid_request("refresh_tokenが必要です"))?;

        let valid_token = state
            .db
            .get_valid_refresh_token(&refresh_token)
            .await
            .map_err(AppError::internal)?
            .ok_or_else(|| {
                AppError::invalid_grant("無効または期限切れのリフレッシュトークンです")
            })?;

        if valid_token.client_id != client.id {
            return Err(AppError::invalid_grant("不正なクライアントです"));
        }

        let new_access_token = jwt_core::create_token(
            &valid_token.user_id,
            &client.id,
            &state.issuer,
            None,
            state.private_key.as_bytes(),
            &state.kid,
        )
        .map_err(AppError::internal)?;

        let new_refresh_token =
            oauth_flow::RefreshTokenData::generate(state.refresh_token_ttl_days);
        let rt = db_client::RefreshToken {
            id: new_refresh_token.token.clone(),
            user_id: valid_token.user_id,
            client_id: client.id,
            expires_at: new_refresh_token.expires_at,
        };
        state
            .db
            .save_refresh_token(&rt)
            .await
            .map_err(AppError::internal)?;
        state
            .db
            .delete_refresh_token(&refresh_token)
            .await
            .map_err(AppError::internal)?;

        return Ok((
            token_response_headers(),
            Json(TokenRes {
                access_token: new_access_token,
                token_type: "Bearer".to_string(),
                expires_in: jwt_core::ACCESS_TOKEN_TTL_SECS,
                scope: None,
                id_token: None,
                refresh_token: Some(new_refresh_token.token),
            }),
        ));
    }

    Err(AppError::unsupported_grant_type(
        "サポートされていないgrant_typeです",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_build_redirect_url() {
        assert_eq!(
            build_redirect_url(
                "http://localhost:4000/callback",
                &[("code", "abc"), ("state", "x y&z")]
            ),
            "http://localhost:4000/callback?code=abc&state=x+y%26z"
        );
        assert_eq!(
            build_redirect_url(
                "http://localhost:4000/callback?existing=1",
                &[("code", "abc")]
            ),
            "http://localhost:4000/callback?existing=1&code=abc"
        );
    }

    #[test]
    fn test_extract_client_credentials_basic_and_form() {
        let mut headers = HeaderMap::new();
        let creds = STANDARD.encode("my%20client:sec%3Dret");
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", creds)).unwrap(),
        );

        let (id, secret) = extract_client_credentials(&headers, None, None).unwrap();
        assert_eq!(id, "my client");
        assert_eq!(secret.as_deref(), Some("sec=ret"));

        // フォームシークレットとの併用は拒否
        assert!(extract_client_credentials(&headers, None, Some("other")).is_err());

        // フォーム認証のみ
        let empty = HeaderMap::new();
        let (id, secret) = extract_client_credentials(&empty, Some("pub_client"), None).unwrap();
        assert_eq!(id, "pub_client");
        assert_eq!(secret, None);
    }
}
