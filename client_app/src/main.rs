use axum::{
    extract::State,
    http::{StatusCode, HeaderMap},
    routing::{get, post},
    Json, Router,
};
use jsonwebtoken::{
    decode, decode_header,
    DecodingKey,
    Validation, Algorithm,
};
use serde::{Deserialize, Serialize};
use serde_json::{self, de};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tower_http::services::ServeDir;

type JwksCache = Arc<RwLock<HashMap<String, Jwk>>>;

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize, Clone)]
struct Jwk {
    pub kid: String,
    pub n: String,
    pub e: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Clone)]
struct AppState {
    reqwest_client: reqwest::Client,
    jwks_cache: JwksCache,
    client_id: String,
}

#[derive(Deserialize)]
struct LoginPayload {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct IdpLoginReq {
    username: String,
    password: String,
    client_id: String,
}

#[derive(Deserialize)]
struct IdpLoginRes {
    auth_code: String,
}

#[derive(Serialize)]
struct IdpTokenReq {
    grant_type: String,
    code: String,
    client_id: String,
}

#[derive(Deserialize)]
struct IdpTokenRes {
    access_token: String,
    refresh_token: Option<String>,
    _token_type: Option<String>,
}

#[derive(Serialize)]
struct ClientRes {
    access_token: String,
    refresh_token: Option<String>,
}

#[derive(serde::Deserialize)]
struct RefreshReq {
    refresh_token: String,
}

#[derive(Serialize)]
struct RefreshTokenReq {
    grant_type: String,
    refresh_token: String,
    client_id: String,
}

#[tokio::main]
async fn main() {
    let state = AppState { 
        reqwest_client: reqwest::Client::new(),
        jwks_cache: Arc::new(RwLock::new(HashMap::new())),
        client_id: "test_client_app".to_string(),
    };

    let app = Router::new()
        .route("/api/login", post(login_handler))
        .route("/api/userinfo", get(get_userinfo_handler))
        .route("/api/verify", get(verify_handler))
        .route("/api/refresh", post(refresh_handler))
        .fallback_service(ServeDir::new("static"))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:4000")
        .await
        .expect("ポート4000番へのバインドに失敗しました");
    println!("サーバーが http://127.0.0.1:4000 で起動しました");

    axum::serve(listener, app)
        .await
        .expect("サーバーの起動に失敗しました");
}

async fn login_handler(
    State(state): State<AppState>,
    Json(payload): Json<LoginPayload>,
) -> Result<Json<ClientRes>, (StatusCode, String)> {
    
    let login_req = IdpLoginReq {
        username: payload.username,
        password: payload.password,
        client_id: state.client_id.to_string()
    };
    
    let login_res =  state.reqwest_client
        .post("http:///localhost:3000/login")
        .json(&login_req)
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Idp通信エラー: {}", e)))?;
    
    if !login_res.status().is_success() {
        return Err((StatusCode::UNAUTHORIZED, "Idpでの認証に失敗しました".to_string()));
    }
    
    let idp_login_data: IdpLoginRes = login_res
        .json()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Idpレスポンス解析エラー: {}", e)))?;
    
    let token_req = IdpTokenReq {
        grant_type: "authorization_code".to_string(),
        code: idp_login_data.auth_code,
        client_id: state.client_id.to_string(),
    };
    
    let token_res = state.reqwest_client
        .post("http://localhost:3000/token")
        .json(&token_req)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("トークン交換に失敗しました: {}", e)))?;
    
    let idp_token_data: IdpTokenRes = token_res
        .json()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("JSONパースエラー: {}", e)))?;
    
    Ok(Json(ClientRes { 
        access_token: idp_token_data.access_token,
        refresh_token: idp_token_data.refresh_token,
    }))
}

async fn get_userinfo_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "トークンが見つかりません".to_string()))?;
    
    let res = state.reqwest_client
        .get("http://localhost:3000/userinfo")
        .header("Authorization", auth_header)
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Idp通信エラー: {}", e)))?;
    
    if !res.status().is_success() {
        return Err((res.status(), "ユーザーの情報の取得に失敗しいました".to_string()));
    }
    
    let data:serde_json::Value = res
        .json()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("JSONパースエラー: {}", e)))?;
    
    Ok(Json(data))
}

async fn verify_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "トークンが見つかりません".to_string()))?;
    
    let token = if auth_header.starts_with("Bearer ") {
        &auth_header[7..]
    } else {
        return Err((StatusCode::UNAUTHORIZED, "Authorizationヘッダーの形式が正しくありません".to_string()));
    };
    
    let header = decode_header(token)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("ヘッダー解析エラー: {}", e)))?;
    let kid = header.kid.ok_or((StatusCode::BAD_REQUEST, "kidが含まれていません".to_string()))?;
    
    let mut target_jwk = None;
    {
        let cache = state.jwks_cache.read().await;
        if let Some(jwk) = cache.get(&kid) {
            target_jwk = Some(jwk.clone());
        }
    }
    
    if target_jwk.is_none() {
        println!("キャッシュミス: IdPからJWKSを取得します（kid: {}）", kid);
        let jwks_res = state.reqwest_client
            .get("http://localhost:3000/.well-known/jwks.json")
            .send()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("JWKS取得エラー: {}", e)))?;
        
        let jwks: Jwks = jwks_res
            .json()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("JWKS JSONパースエラー: {}", e)))?;
        
        let mut cache = state.jwks_cache.write().await;
        for key in jwks.keys {
            cache.insert(key.kid.clone(), key.clone());
            if key.kid == kid {
                target_jwk = Some(key.clone());
            }
        }
    }
    
    let target_key = target_jwk.ok_or((StatusCode::BAD_REQUEST, "対応する公開鍵が見つかりません".to_string()))?;
    
    let decoding_key = DecodingKey::from_rsa_components(&target_key.n, &target_key.e)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("公開鍵の構築エラー: {}", e)))?;
    
    let validation = Validation::new(Algorithm::RS256);
    let token_data = decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("トークンの検証に失敗しました: {}", e)))?;
    
    Ok(Json(serde_json::json!({
        "message": "ローカル検証に成功しました！",
        "claims": token_data.claims
    })))
}

async fn refresh_handler(
    State(state): State<AppState>,
    Json(payload): Json<RefreshReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    
    let token_req = RefreshTokenReq {
        grant_type: "refresh_token".to_string(),
        refresh_token: payload.refresh_token,
        client_id: state.client_id.to_string(),
    };

    let res = state.reqwest_client
        .post("http://localhost:3000/token")
        .json(&token_req)
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("IdPとの通信エラー: {}", e)))?;
    
    if res.status().is_success() {
        let data: serde_json::Value = res.json().await.unwrap();
        Ok(Json(data))
    } else {
        let error_msg = res.text().await.unwrap_or_default();
        Err((StatusCode::INTERNAL_SERVER_ERROR, format!("トークンのリフレッシュに失敗しました: {}", error_msg)))
    }
}
