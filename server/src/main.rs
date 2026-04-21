mod handlers;
mod middleware;
mod models;

use axum::{
    Router,
    routing::{get, post},
};
use db_client::DbClient;
use dotenvy::dotenv;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::{env, fs};
use tokio::net::TcpListener;
use tower_http::services::ServeDir;
use tower_sessions::{MemoryStore, SessionManagerLayer};

#[tokio::main]
async fn main() {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URLが設定されていません");
    let private_key =
        fs::read_to_string("../keys/private_key.pem").expect("private_key.pem が見つかりません");
    let public_key =
        fs::read_to_string("../keys/public_key.pem").expect("public_key.pem が見つかりません");
    let issuer = env::var("ISSUER").expect("ISSUERが設定されていません");
    let refresh_token_ttl_days = env::var("REFRESH_TOKEN_TTL_DAYS")
        .unwrap_or("30".to_string())
        .parse::<i64>()
        .unwrap_or(30);

    let db = DbClient::new(&database_url)
        .await
        .expect("データベースへの接続に失敗しました");

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store).with_secure(false);

    let state = models::AppState {
        db,
        auth_codes: Arc::new(Mutex::new(HashMap::new())),
        private_key,
        public_key,
        kid: "key-2026-04".to_string(),
        issuer,
        refresh_token_ttl_days,
    };

    let protected_routes = Router::new()
        .route("/userinfo", get(handlers::get_user_info))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_guard,
        ));

    let app = Router::new()
        .route("/", get(handlers::health_check))
        .route(
            "/.well-known/openid-configuration",
            get(handlers::get_openid_config),
        )
        .route("/.well-known/jwks.json", get(handlers::get_jwks))
        .route("/register", post(handlers::register_user))
        .route("/authorize", get(handlers::authorize))
        .route("/login", post(handlers::login_user))
        .route("/consent", post(handlers::consent))
        .route("/token", post(handlers::exchange_token))
        .route("/revoke", post(handlers::revoke_token))
        .nest_service("/static", ServeDir::new("static"))
        .merge(protected_routes)
        .layer(session_layer)
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("3000番ポートへのバインドが失敗しました");
    println!("Server is running on http://127.0.0.1:3000");

    axum::serve(listener, app)
        .await
        .expect("サーバーの起動に失敗しました");
}
