use axum::{
    extract::State,
    http::{StatusCode, HeaderMap},
    Json,
};
use crypto;
use db_client::{User};
use jwt_core;
use serde_json;
use uuid::Uuid;
use oauth_flow::{
    AuthCode,
    TokenRequest as OAuthTokenReq,
};
use crate::models::*;

pub async fn health_check() -> &'static str {
    "IdP Server is running, and Database connection is healthy!"
}

pub async fn register_user(
    State(state): State<AppState>,
    Json(payload): Json<RegisterReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let password_hash = match crypto::hash_password(&payload.password) {
        Ok (hash) => hash,
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "パスワードのハッシュ化に失敗しました".to_string(),
            ))
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
        ))
    }
}

pub async fn login_user(
    State(state): State<AppState>,
    Json(payload): Json<LoginReq>,
) -> Result<Json<LoginRes>, (StatusCode, String)> {
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
        Ok(true) => {},
        Ok(false) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                "ユーザー名またはパスワードが間違っています".to_string(),
            ))
        },
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("パスワードの検証に失敗しました: {:?}", e),
            ))
        },
    };

    let auth_code = AuthCode::new(&user.id, &payload.client_id);
    state.auth_codes.lock().unwrap().insert(auth_code.code.clone(), auth_code.clone());

    Ok(Json(LoginRes {
        auth_code: auth_code.code,
    }))

}

pub async fn exchange_token(
    State(state): State<AppState>,
    Json(payload): Json<TokenReq>,
) -> Result<Json<TokenRes>, (StatusCode, String)> {
    if payload.grant_type == "authorization_code" {
        let code = payload.code.ok_or((StatusCode::BAD_REQUEST, "codeが必要です".to_string()))?;
        let auth_code = match state.auth_codes.lock().unwrap().remove(&code) {
            Some(code) => code,
            None => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "無効な認可コード、または使用済みのコードです".to_string(),
                ))
            }
        };
    
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
                ))
            }
        };
    
        let jwt_string = match jwt_core::create_token(&user_id, state.private_key.as_bytes(), &state.kid) {
            Ok(token) => token,
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("JWTの生成に失敗しました: {:?}", e),
                ))
            }
        };
        
        let mut id_token = None;
        if let Some(scope) = payload.scope {
            if scope.contains("openid") {
                let issuer = "http://localhost:3000";
                
                id_token = match jwt_core::create_id_token(
                    &user_id, 
                    &payload.client_id,
                    issuer,
                    state.private_key.as_bytes(),
                    &state.kid.as_str()
                ) {
                    Ok(token) => Some(token),
                    Err(e) => {
                        println!("IDトークンの生成に失敗: {:?}", e);
                        None
                    },
                }
            }
        }
        
        let refresh_token = oauth_flow::RefreshTokenData::generate(30);
        let rt = db_client::RefreshToken {
            id: refresh_token.token.clone(),
            user_id: user_id.clone(),
            client_id: payload.client_id.clone(),
            expires_at: refresh_token.expires_at,
        };
        state.db.save_refresh_token(&rt).await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DBエラー: {}", e)))?;
        
        return Ok(Json(TokenRes {
            access_token: jwt_string,
            token_type: "Bearer".to_string(),
            id_token,
            refresh_token: Some(refresh_token.token),
        }));
    } else if payload.grant_type == "refresh_token" {
        let refresh_token = payload.refresh_token
            .ok_or((StatusCode::BAD_REQUEST, "refresh_tokenが必要です".to_string()))?;
        
        let valid_token = state.db.get_valid_refresh_token(&refresh_token)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DBエラー: {}", e)))?
            .ok_or((StatusCode::UNAUTHORIZED, "無効または期限切れのリフレッシュトークンです".to_string()))?;
        
        if valid_token.client_id != payload.client_id {
            return Err((StatusCode::UNAUTHORIZED, "不正なクライアントです".to_string()));
        }
        
        let new_access_token = jwt_core::create_token(&valid_token.user_id, state.private_key.as_bytes(), &state.kid)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("JWTエラー: {}", e)))?;
        
        return Ok(Json(TokenRes {
            access_token: new_access_token,
            token_type: "Bearer".to_string(),
            id_token: None,
            refresh_token: None,
        }));
    }
    
    Err((StatusCode::BAD_REQUEST, "サポートされていないgrant_typeです".to_string()))
}

pub async fn get_user_info(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let auth_header = headers
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "Authorizationヘッダーが存在ません".to_string(),
        ))?;
    
    if !auth_header.starts_with("Bearer ") {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Authorizationヘッダーの形式が正しくありません".to_string(),
        ));
    }
    
    let token = &auth_header[7..];
    let user_id = match jwt_core::verify_token(token, state.public_key.as_bytes()) {
        Ok(id) => id,
        Err(e) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                format!("無効または期限切れのトークンです: {}", e),
            ));
        }
    };
    
    let response = serde_json::json!({
        "message": "JWTの検証に成功しました。正答なアクセス権を確認しました。",
        "user_id": user_id,
    });

    Ok(Json(response))
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

pub async fn get_jwks(State(state): State<AppState>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let jwks = jwt_core::get_jwks(&state.public_key, &state.kid)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(jwks))
}