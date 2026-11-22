use crate::{error::AppError, models::AppState};
use axum::{
    extract::{Request, State},
    http::header,
    middleware::Next,
    response::Response,
};

pub async fn auth_guard(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .filter(|h| h.starts_with("Bearer "))
        .map(|s| &s[7..])
        .ok_or_else(|| AppError::unauthorized("Authorizationヘッダーの形式が正しくありません"))?;

    let claims = jwt_core::verify_token(token, state.public_key.as_bytes(), &state.issuer)
        .map_err(|e| AppError::unauthorized(format!("無効または期限切れのトークンです: {}", e)))?;

    req.extensions_mut().insert(claims);

    Ok(next.run(req).await)
}
