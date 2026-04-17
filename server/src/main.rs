use axum::{
    extract::State,
    http::{StatusCode, HeaderMap},
    routing::{get, post},
    Json, Router,
};
use crypto;
use db_client::{DbClient, User};
use jwt_core;
use serde::{Deserialize, Serialize};
use serde_json;
use tokio::net::TcpListener;
use uuid::Uuid;
use oauth_flow::{
    AuthCode,
    TokenRequest as OAuthTokenRequest,
};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct AppState {
    pub db: DbClient,
    pub auth_codes: Arc<Mutex<HashMap<String, AuthCode>>>,
    pub jwt_secret: String,
}

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
    client_id: String,
}

#[derive(Serialize)]
struct LoginResponse {
    auth_code: String,
}

#[derive(Deserialize)]
struct ExchangePayload {
    pub grant_type: String,
    pub code: String,
    pub client_id: String,
}

#[derive(Serialize)]
struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
}

#[tokio::main]
async fn main() {

    dotenvy::dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URLが設定されていません");
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRETが設定されていません");

    let db = DbClient::new(&database_url)
        .await
        .expect("データベースへの接続に失敗しました");

    let state = AppState { 
        db,
        auth_codes: Arc::new(Mutex::new(HashMap::new())),
        jwt_secret,
    };

    let app = Router::new()
        .route("/", get(health_check))
        .route("/register", post(register_user))
        .route("/login", post(login_user))
        .route("/token", post(exchange_token))
        .route("/userinfo", get(get_user_info))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("3000番ポートへのバインドが失敗しました");
    println!("Server is running on http://127.0.0.1:3000");

    axum::serve(listener, app)
        .await
        .expect("サーバーの起動に失敗しました");
}

async fn health_check() -> &'static str {
    "IdP Server is running, and Database connection is healthy!"
}

async fn register_user(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
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

async fn login_user(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
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

    Ok(Json(LoginResponse {
        auth_code: auth_code.code,
    }))

}

async fn exchange_token(
    State(state): State<AppState>,
    Json(payload): Json<ExchangePayload>,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    let auth_code = match state.auth_codes.lock().unwrap().remove(&payload.code) {
        Some(code) => code,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                "無効な認可コード、または使用済みのコードです".to_string(),
            ))
        }
    };

    let oauth_req = OAuthTokenRequest {
        grant_type: payload.grant_type,
        code: auth_code.code.clone(),
        client_id: payload.client_id,
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

    let jwt_string = match jwt_core::create_token(&user_id, state.jwt_secret.as_bytes()) {
        Ok(token) => token,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("JWTの生成に失敗しました: {:?}", e),
            ))
        }
    };

    let response = TokenResponse {
        access_token: jwt_string,
        token_type: "Bearer".to_string(),
    };

    Ok(Json(response))
}

async fn get_user_info(
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
    let user_id = match jwt_core::verify_token(token, state.jwt_secret.as_bytes()) {
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
