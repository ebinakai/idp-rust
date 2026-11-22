mod error;
mod handlers;
mod middleware;
mod models;

use axum::{
    Router,
    routing::{delete, get, post},
};
use db_client::DbClient;
use dotenvy::dotenv;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::{env, fs};
use tokio::net::TcpListener;
use tower_http::services::{ServeDir, ServeFile};
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
    db.migrate()
        .await
        .expect("データベースのマイグレーションに失敗しました");

    if let Ok(admin_name) = env::var("ADMIN_USERNAME") {
        let admin_name = admin_name.trim();
        if !admin_name.is_empty() {
            match db.set_user_admin_by_name(admin_name, true).await {
                Ok(true) => println!("管理者権限を付与しました: {}", admin_name),
                Ok(false) => println!("ADMIN_USERNAME が見つかりません: {}", admin_name),
                Err(e) => eprintln!("ADMIN_USERNAME の更新に失敗しました: {}", e),
            }
        }
    }

    let allow_self_register = env::var("ALLOW_SELF_REGISTER")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1"))
        .unwrap_or(false);

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store).with_secure(false);

    let frontend_dir = env::var("FRONTEND_DIR").unwrap_or_else(|_| {
        ["frontend/dist", "server/frontend/dist"]
            .into_iter()
            .find(|p| Path::new(p).exists())
            .unwrap_or("frontend/dist")
            .to_string()
    });

    let rp_origin_str = env::var("WEBAUTHN_RP_ORIGIN").unwrap_or_else(|_| issuer.clone());
    let rp_origin = webauthn_rs::prelude::Url::parse(&rp_origin_str)
        .expect("WEBAUTHN_RP_ORIGIN / ISSUER が有効なURLではありません");
    let rp_id = env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| {
        rp_origin
            .host_str()
            .expect("WEBAUTHN_RP_ORIGIN にホスト名が含まれていません")
            .to_string()
    });
    let webauthn = Arc::new(
        webauthn_rs::WebauthnBuilder::new(&rp_id, &rp_origin)
            .expect("WebauthnBuilder の初期化に失敗しました")
            .rp_name("Rust IdP")
            .build()
            .expect("Webauthn の構築に失敗しました"),
    );

    let state = models::AppState {
        db,
        auth_codes: Arc::new(Mutex::new(HashMap::new())),
        private_key,
        public_key,
        kid: "key-2026-04".to_string(),
        issuer,
        refresh_token_ttl_days,
        frontend_dir: frontend_dir.clone(),
        webauthn,
        allow_self_register,
    };

    let protected_routes = Router::new()
        .route("/userinfo", get(handlers::get_user_info))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_guard,
        ));

    let index_file = Path::new(&frontend_dir).join("index.html");

    let app = Router::new()
        .route("/health", get(handlers::health_check))
        .route(
            "/.well-known/openid-configuration",
            get(handlers::get_openid_config),
        )
        .route("/.well-known/jwks.json", get(handlers::get_jwks))
        .route("/register", post(handlers::register_user))
        .route("/authorize", get(handlers::authorize))
        .route("/api/auth/context", get(handlers::get_auth_context))
        .route("/login", post(handlers::login_user))
        .route("/consent", post(handlers::consent))
        .route("/token", post(handlers::exchange_token))
        .route("/revoke", post(handlers::revoke_token))
        .route(
            "/api/admin/clients",
            get(handlers::list_clients).post(handlers::create_client),
        )
        .route("/api/me", get(handlers::get_me))
        .route("/api/me/login", post(handlers::account_login))
        .route("/api/me/logout", post(handlers::account_logout))
        .route("/api/me/password", post(handlers::change_my_password))
        .route(
            "/api/me/consents/{client_id}",
            delete(handlers::revoke_my_consent),
        )
        .route(
            "/api/me/passkeys/register/start",
            post(handlers::start_passkey_register),
        )
        .route(
            "/api/me/passkeys/register/finish",
            post(handlers::finish_passkey_register),
        )
        .route("/api/me/passkeys/{id}", delete(handlers::delete_my_passkey))
        .route(
            "/api/passkey/auth/start",
            post(handlers::start_passkey_auth),
        )
        .route(
            "/api/passkey/auth/finish",
            post(handlers::finish_passkey_auth),
        )
        .merge(protected_routes)
        .fallback_service(
            ServeDir::new(&frontend_dir).not_found_service(ServeFile::new(index_file)),
        )
        .layer(session_layer)
        .with_state(state);

    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let listener = TcpListener::bind(&bind_addr)
        .await
        .unwrap_or_else(|e| panic!("{} へのバインドが失敗しました: {}", bind_addr, e));
    println!("Server is running on http://{}", bind_addr);

    axum::serve(listener, app)
        .await
        .expect("サーバーの起動に失敗しました");
}
