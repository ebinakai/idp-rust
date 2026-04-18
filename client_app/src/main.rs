mod models;
mod handlers;

use axum::{
    routing::{get, post},
    Router,
};
use dotenvy::dotenv;
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tower_http::services::ServeDir;

use models::{AppState};
use handlers::{
    login, get_userinfo, verify_token, 
    refresh, logout
};

#[tokio::main]
async fn main() {
    dotenv().ok();
    let idp_base_url = env::var("IDP_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:3000".to_string());
    
    let state = AppState { 
        reqwest_client: reqwest::Client::new(),
        jwks_cache: Arc::new(RwLock::new(HashMap::new())),
        client_id: "test_client_app".to_string(),
        idp_base_url: idp_base_url,
    };

    let app = Router::new()
        .route("/api/login", post(login))
        .route("/api/userinfo", get(get_userinfo))
        .route("/api/verify", get(verify_token))
        .route("/api/refresh", post(refresh))
        .route("/api/logout", post(logout))
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
