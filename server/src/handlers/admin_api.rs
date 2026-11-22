use crate::{
    error::AppError,
    handlers::require_admin,
    models::{AppState, ClientRes, CreateClientReq},
};
use axum::{Json, extract::State, http::StatusCode};
use db_client::OAuthClient;
use rand::distr::{Alphanumeric, SampleString};
use tower_sessions::Session;
use uuid::Uuid;

pub async fn list_clients(
    State(state): State<AppState>,
    session: Session,
) -> Result<Json<Vec<ClientRes>>, AppError> {
    require_admin(&state, &session).await?;

    let clients = state
        .db
        .list_oauth_clients()
        .await
        .map_err(AppError::internal)?;

    let res = clients
        .into_iter()
        .map(|c| ClientRes {
            id: c.id,
            name: c.name,
            redirect_uris: c.redirect_uris,
            client_secret: None,
        })
        .collect();

    Ok(Json(res))
}

pub async fn create_client(
    State(state): State<AppState>,
    session: Session,
    Json(req): Json<CreateClientReq>,
) -> Result<(StatusCode, Json<ClientRes>), AppError> {
    require_admin(&state, &session).await?;

    if req.name.trim().is_empty() {
        return Err(AppError::invalid_request("クライアント名が必要です"));
    }
    if req.redirect_uris.is_empty() || req.redirect_uris.iter().any(|u| u.trim().is_empty()) {
        return Err(AppError::invalid_request(
            "1つ以上の有効なredirect_uriが必要です",
        ));
    }

    let client_id = Uuid::new_v4().to_string();
    let plain_secret = if req.is_confidential {
        Some(Alphanumeric.sample_string(&mut rand::rng(), 32))
    } else {
        None
    };

    let hashed_secret = if let Some(ref secret) = plain_secret {
        let secret_owned = secret.clone();
        let hashed = tokio::task::spawn_blocking(move || crypto::hash_secret(&secret_owned))
            .await
            .map_err(AppError::internal)?
            .map_err(|e| AppError::internal(format!("client_secretのハッシュ化失敗: {}", e)))?;
        Some(hashed)
    } else {
        None
    };

    let client = OAuthClient {
        id: client_id.clone(),
        name: req.name.clone(),
        secret: hashed_secret,
        redirect_uris: req.redirect_uris.clone(),
    };

    state
        .db
        .create_oauth_client(&client)
        .await
        .map_err(AppError::internal)?;

    Ok((
        StatusCode::CREATED,
        Json(ClientRes {
            id: client_id,
            name: req.name,
            redirect_uris: req.redirect_uris,
            client_secret: plain_secret,
        }),
    ))
}
