use crate::{error::AppError, handlers::complete_authorize_login, models::AppState};
use axum::{
    Json,
    extract::{Path as AxumPath, State},
    http::StatusCode,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use db_client::{PasskeyRecord, UserConsentRecord};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use webauthn_rs::prelude::{
    CreationChallengeResponse, CredentialID, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse,
    Uuid as WebauthnUuid,
};

#[derive(Serialize)]
pub struct UserSummary {
    pub id: String,
    pub username: String,
}

#[derive(Serialize)]
pub struct PasskeySummary {
    pub id: String,
    pub label: String,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct MeRes {
    pub logged_in: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserSummary>,
    pub passkeys: Vec<PasskeySummary>,
    pub consents: Vec<UserConsentRecord>,
}

#[derive(Deserialize)]
pub struct AccountLoginReq {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct PasskeyRegStartReq {
    pub label: Option<String>,
}

#[derive(Deserialize)]
pub struct PasskeyAuthStartReq {
    pub username: String,
}

#[derive(Deserialize)]
pub struct PasskeyAuthFinishReq {
    pub credential: PublicKeyCredential,
    pub mode: Option<String>,
}

async fn require_account_user_id(session: &Session) -> Result<String, AppError> {
    session
        .get::<String>("account_user_id")
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| AppError::unauthorized("ログインが必要です"))
}

pub async fn get_me(
    State(state): State<AppState>,
    session: Session,
) -> Result<Json<MeRes>, AppError> {
    let Some(user_id) = session
        .get::<String>("account_user_id")
        .await
        .map_err(AppError::internal)?
    else {
        return Ok(Json(MeRes {
            logged_in: false,
            user: None,
            passkeys: vec![],
            consents: vec![],
        }));
    };

    let Some(user) = state
        .db
        .get_user(&user_id)
        .await
        .map_err(AppError::internal)?
    else {
        let _ = session.remove::<String>("account_user_id").await;
        return Ok(Json(MeRes {
            logged_in: false,
            user: None,
            passkeys: vec![],
            consents: vec![],
        }));
    };

    let passkeys = state
        .db
        .list_passkeys_by_user(&user.id)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .map(|p| PasskeySummary {
            id: p.id,
            label: p.label,
            created_at: p.created_at,
        })
        .collect();

    let consents = state
        .db
        .list_user_consents(&user.id)
        .await
        .map_err(AppError::internal)?;

    Ok(Json(MeRes {
        logged_in: true,
        user: Some(UserSummary {
            id: user.id,
            username: user.username,
        }),
        passkeys,
        consents,
    }))
}

pub async fn account_login(
    State(state): State<AppState>,
    session: Session,
    Json(payload): Json<AccountLoginReq>,
) -> Result<StatusCode, AppError> {
    if payload.username.trim().is_empty() || payload.password.is_empty() {
        return Err(AppError::invalid_request(
            "ユーザー名とパスワードを入力してください",
        ));
    }

    let user = state
        .db
        .get_user_by_name(payload.username.trim())
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

    session.cycle_id().await.map_err(AppError::internal)?;
    session
        .insert("account_user_id", &user.id)
        .await
        .map_err(AppError::internal)?;

    Ok(StatusCode::OK)
}

pub async fn account_logout(session: Session) -> Result<StatusCode, AppError> {
    session
        .remove::<String>("account_user_id")
        .await
        .map_err(AppError::internal)?;
    Ok(StatusCode::OK)
}

pub async fn revoke_my_consent(
    State(state): State<AppState>,
    session: Session,
    AxumPath(client_id): AxumPath<String>,
) -> Result<StatusCode, AppError> {
    let user_id = require_account_user_id(&session).await?;
    let removed = state
        .db
        .revoke_user_consent(&user_id, &client_id)
        .await
        .map_err(AppError::internal)?;

    if !removed {
        return Err(AppError::not_found("指定された連携アプリが見つかりません"));
    }

    Ok(StatusCode::NO_CONTENT)
}

pub async fn start_passkey_register(
    State(state): State<AppState>,
    session: Session,
    Json(payload): Json<PasskeyRegStartReq>,
) -> Result<Json<CreationChallengeResponse>, AppError> {
    let user_id = require_account_user_id(&session).await?;
    let user = state
        .db
        .get_user(&user_id)
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| AppError::unauthorized("ユーザーが見つかりません"))?;

    let existing = state
        .db
        .list_passkeys_by_user(&user.id)
        .await
        .map_err(AppError::internal)?;

    let exclude_ids: Vec<CredentialID> = existing
        .iter()
        .filter_map(|r| serde_json::from_str::<Passkey>(&r.passkey_json).ok())
        .map(|pk| pk.cred_id().clone())
        .collect();
    let exclude_opt = if exclude_ids.is_empty() {
        None
    } else {
        Some(exclude_ids)
    };

    let user_uuid = WebauthnUuid::parse_str(&user.id).map_err(AppError::internal)?;
    let (ccr, skr) = state
        .webauthn
        .start_passkey_registration(user_uuid, &user.username, &user.username, exclude_opt)
        .map_err(AppError::internal)?;

    let label = payload
        .label
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "パスキー".to_string());

    session
        .insert("passkey_reg_state", (skr, label))
        .await
        .map_err(AppError::internal)?;

    Ok(Json(ccr))
}

pub async fn finish_passkey_register(
    State(state): State<AppState>,
    session: Session,
    Json(reg): Json<RegisterPublicKeyCredential>,
) -> Result<(StatusCode, Json<PasskeySummary>), AppError> {
    let user_id = require_account_user_id(&session).await?;
    let (skr, label) = session
        .remove::<(PasskeyRegistration, String)>("passkey_reg_state")
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| AppError::invalid_request("パスキー登録セッションが見つかりません"))?;

    let passkey = state
        .webauthn
        .finish_passkey_registration(&reg, &skr)
        .map_err(|e| AppError::invalid_request(format!("パスキーの検証に失敗しました: {}", e)))?;

    let credential_id = URL_SAFE_NO_PAD.encode(passkey.cred_id());
    let passkey_json = serde_json::to_string(&passkey).map_err(AppError::internal)?;
    let record = PasskeyRecord {
        id: uuid::Uuid::new_v4().to_string(),
        user_id,
        credential_id,
        label: label.clone(),
        passkey_json,
        created_at: None,
    };

    state
        .db
        .save_passkey(&record)
        .await
        .map_err(AppError::internal)?;

    Ok((
        StatusCode::CREATED,
        Json(PasskeySummary {
            id: record.id,
            label,
            created_at: Some(Utc::now()),
        }),
    ))
}

pub async fn delete_my_passkey(
    State(state): State<AppState>,
    session: Session,
    AxumPath(id): AxumPath<String>,
) -> Result<StatusCode, AppError> {
    let user_id = require_account_user_id(&session).await?;
    let deleted = state
        .db
        .delete_passkey(&id, &user_id)
        .await
        .map_err(AppError::internal)?;

    if !deleted {
        return Err(AppError::not_found("指定されたパスキーが見つかりません"));
    }

    Ok(StatusCode::NO_CONTENT)
}

pub async fn start_passkey_auth(
    State(state): State<AppState>,
    session: Session,
    Json(payload): Json<PasskeyAuthStartReq>,
) -> Result<Json<RequestChallengeResponse>, AppError> {
    let username = payload.username.trim();
    if username.is_empty() {
        return Err(AppError::invalid_request("ユーザー名を入力してください"));
    }

    let user = state
        .db
        .get_user_by_name(username)
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| AppError::unauthorized("ユーザーが見つかりません"))?;

    let records = state
        .db
        .list_passkeys_by_user(&user.id)
        .await
        .map_err(AppError::internal)?;

    if records.is_empty() {
        return Err(AppError::invalid_request(
            "このユーザーにはパスキーが登録されていません",
        ));
    }

    let passkeys: Vec<Passkey> = records
        .iter()
        .map(|r| serde_json::from_str(&r.passkey_json))
        .collect::<Result<Vec<_>, _>>()
        .map_err(AppError::internal)?;

    let (rcr, auth_state) = state
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(AppError::internal)?;

    session
        .insert("passkey_auth_state", (auth_state, user.id))
        .await
        .map_err(AppError::internal)?;

    Ok(Json(rcr))
}

pub async fn finish_passkey_auth(
    State(state): State<AppState>,
    session: Session,
    Json(req): Json<PasskeyAuthFinishReq>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (auth_state, user_id) = session
        .remove::<(PasskeyAuthentication, String)>("passkey_auth_state")
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| AppError::invalid_request("パスキー認証セッションが見つかりません"))?;

    let auth_result = state
        .webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)
        .map_err(|e| AppError::unauthorized(format!("パスキー認証に失敗しました: {}", e)))?;

    let records = state
        .db
        .list_passkeys_by_user(&user_id)
        .await
        .map_err(AppError::internal)?;

    for record in records {
        if let Ok(mut passkey) = serde_json::from_str::<Passkey>(&record.passkey_json)
            && passkey.cred_id() == auth_result.cred_id()
        {
            passkey.update_credential(&auth_result);
            let updated_json = serde_json::to_string(&passkey).map_err(AppError::internal)?;
            state
                .db
                .update_passkey_json(&record.credential_id, &updated_json)
                .await
                .map_err(AppError::internal)?;
            break;
        }
    }

    let user = state
        .db
        .get_user(&user_id)
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| AppError::not_found("ユーザーが見つかりません"))?;

    if req.mode.as_deref() == Some("authorize") {
        let action = complete_authorize_login(&state, &session, &user).await?;
        let val = serde_json::to_value(action).map_err(AppError::internal)?;
        return Ok(Json(val));
    }

    session.cycle_id().await.map_err(AppError::internal)?;
    session
        .insert("account_user_id", &user.id)
        .await
        .map_err(AppError::internal)?;

    Ok(Json(serde_json::json!({ "status": "ok" })))
}
