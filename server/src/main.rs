mod error;
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
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::{env, fs};
use tokio::net::TcpListener;
use tower_http::services::ServeDir;
use tower_sessions::{MemoryStore, SessionManagerLayer};

fn read_key_file(env_name: &str, candidates: &[&str]) -> String {
    if let Ok(path) = env::var(env_name) {
        return fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} ({}) の読み込みに失敗しました: {}", env_name, path, e));
    }
    for path in candidates {
        if Path::new(path).exists() {
            return fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("{} の読み込みに失敗しました: {}", path, e));
        }
    }
    panic!("鍵ファイルが見つかりません ({:?})", candidates);
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URLが設定されていません");
    let private_key = read_key_file(
        "PRIVATE_KEY_PATH",
        &["keys/private_key.pem", "../keys/private_key.pem"],
    );
    let public_key = read_key_file(
        "PUBLIC_KEY_PATH",
        &["keys/public_key.pem", "../keys/public_key.pem"],
    );
    let issuer = env::var("ISSUER").expect("ISSUERが設定されていません");
    let refresh_token_ttl_days = env::var("REFRESH_TOKEN_TTL_DAYS")
        .unwrap_or_else(|_| "30".to_string())
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

    let static_dir = if Path::new("static").exists() {
        "static"
    } else {
        "server/static"
    };

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
        .route(
            "/api/admin/clients",
            get(handlers::list_clients).post(handlers::create_client),
        )
        .nest_service("/static", ServeDir::new(static_dir))
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
