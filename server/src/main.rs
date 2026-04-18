mod models;
mod handlers;

use axum::{
    routing::{get, post},
    Router,
};
use db_client::{DbClient};
use dotenvy::dotenv;
use tokio::net::TcpListener;
use std::{env, fs};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use models::AppState;
use handlers::{
    health_check, register_user, login_user,
    exchange_token, get_user_info, revoke_token,
    get_jwks,
};

#[tokio::main]
async fn main() {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URLが設定されていません");
    let private_key = fs::read_to_string("../keys/private_key.pem").expect("private_key.pem が見つかりません");
    let public_key = fs::read_to_string("../keys/public_key.pem").expect("public_key.pem が見つかりません");

    let db = DbClient::new(&database_url)
        .await
        .expect("データベースへの接続に失敗しました");

    let state = AppState { 
        db,
        auth_codes: Arc::new(Mutex::new(HashMap::new())),
        private_key,
        public_key,
        kid: "key-2026-04".to_string(),
    };

    let app = Router::new()
        .route("/", get(health_check))
        .route("/register", post(register_user))
        .route("/login", post(login_user))
        .route("/token", post(exchange_token))
        .route("/userinfo", get(get_user_info))
        .route("/revoke", post(revoke_token))
        .route("/.well-known/jwks.json", get(get_jwks))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("3000番ポートへのバインドが失敗しました");
    println!("Server is running on http://127.0.0.1:3000");

    axum::serve(listener, app)
        .await
        .expect("サーバーの起動に失敗しました");
}
