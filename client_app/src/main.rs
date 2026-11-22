mod handlers;
mod models;

use axum::{
    Router,
    routing::{get, post},
};
use dotenvy::dotenv;
use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tower_http::services::ServeDir;
use tower_sessions::{MemoryStore, SessionManagerLayer};

#[tokio::main]
async fn main() {
    dotenv().ok();
    let idp_base_url =
        env::var("IDP_BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let idp_internal_url = env::var("IDP_INTERNAL_URL").unwrap_or_else(|_| idp_base_url.clone());
    let client_url = env::var("CLIENT_URL").unwrap_or_else(|_| "http://localhost:4000".to_string());
    let client_id = env::var("CLIENT_ID").unwrap_or_else(|_| "test_client_app".to_string());
    let client_secret =
        env::var("CLIENT_SECRET").unwrap_or_else(|_| "test_client_secret".to_string());

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_name("client_app_session_id");

    let state = models::AppState {
        reqwest_client: reqwest::Client::new(),
        jwks_cache: Arc::new(RwLock::new(HashMap::new())),
        client_id,
        client_secret,
        idp_base_url,
        idp_internal_url,
        client_url,
    };

    let static_dir = env::var("STATIC_DIR").unwrap_or_else(|_| {
        ["static", "client_app/static"]
            .into_iter()
            .find(|p| Path::new(p).exists())
            .unwrap_or("static")
            .to_string()
    });

    let app = Router::new()
        .route("/login", get(handlers::login))
        .route("/callback", get(handlers::callback))
        .route("/api/session", get(handlers::get_session))
        .route("/api/userinfo", get(handlers::get_userinfo))
        .route("/api/verify", get(handlers::verify_token))
        .route("/api/refresh", post(handlers::refresh))
        .route("/api/logout", post(handlers::logout))
        .fallback_service(ServeDir::new(static_dir))
        .layer(session_layer)
        .with_state(state);

    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:4000".to_string());
    let listener = TcpListener::bind(&bind_addr)
        .await
        .unwrap_or_else(|e| panic!("{} へのバインドが失敗しました: {}", bind_addr, e));
    println!("サーバーが http://{} で起動しました", bind_addr);

    axum::serve(listener, app)
        .await
        .expect("サーバーの起動に失敗しました");
}
