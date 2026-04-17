use axum::{
    extract::State,
    http::StatusCode,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tower_http::services::ServeDir;

#[derive(Clone)]
struct AppState {
    reqwest_client: reqwest::Client,
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
    _token_type: Option<String>,
}

#[derive(Serialize)]
struct ClientRes {
    access_token: String,
}

#[tokio::main]
async fn main() {
    let reqwest_client = reqwest::Client::new();
    let state = AppState { reqwest_client };

    let app = Router::new()
        .route("/api/login", post(login_handler))
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
    let client_id = "test_client_id".to_string();
    
    let login_req = IdpLoginReq {
        username: payload.username,
        password: payload.password,
        client_id: client_id.clone(),
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
        client_id: client_id,
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
    }))
}
