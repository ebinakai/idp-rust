pub mod admin_api;
pub mod auth;
pub mod oidc;

pub use admin_api::*;
pub use auth::*;
pub use oidc::*;

pub async fn health_check() -> &'static str {
    "IdP Server is running, and Database connection is healthy!"
}
