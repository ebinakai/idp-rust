use crate::models::AppState;
use axum::{
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::Response,
};

pub async fn auth_guard(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .filter(|h| h.starts_with("Bearer "))
        .map(|s| &s[7..])
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "Authorizationヘッダーの形式が正しくありません".to_string(),
        ))?;

    let user_id = match jwt_core::verify_token(token, state.public_key.as_bytes()) {
        Ok(id) => id,
        Err(e) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                format!("無効または期限切れのトークンです: {}", e),
            ));
        }
    };

    req.extensions_mut().insert(user_id);

    Ok(next.run(req).await)
}
