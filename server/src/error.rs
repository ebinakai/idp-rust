use axum::{
    Json,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::fmt::Display;

#[derive(Debug)]
pub enum AppError {
    OAuth {
        status: StatusCode,
        error: &'static str,
        description: String,
    },
    Internal(String),
}

impl AppError {
    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self::OAuth {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_request",
            description: description.into(),
        }
    }

    pub fn invalid_client(description: impl Into<String>) -> Self {
        Self::OAuth {
            status: StatusCode::UNAUTHORIZED,
            error: "invalid_client",
            description: description.into(),
        }
    }

    pub fn invalid_grant(description: impl Into<String>) -> Self {
        Self::OAuth {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_grant",
            description: description.into(),
        }
    }

    pub fn unsupported_grant_type(description: impl Into<String>) -> Self {
        Self::OAuth {
            status: StatusCode::BAD_REQUEST,
            error: "unsupported_grant_type",
            description: description.into(),
        }
    }

    pub fn unauthorized(description: impl Into<String>) -> Self {
        Self::OAuth {
            status: StatusCode::UNAUTHORIZED,
            error: "unauthorized",
            description: description.into(),
        }
    }

    pub fn forbidden(description: impl Into<String>) -> Self {
        Self::OAuth {
            status: StatusCode::FORBIDDEN,
            error: "access_denied",
            description: description.into(),
        }
    }

    pub fn not_found(description: impl Into<String>) -> Self {
        Self::OAuth {
            status: StatusCode::NOT_FOUND,
            error: "not_found",
            description: description.into(),
        }
    }

    pub fn internal(err: impl Display) -> Self {
        Self::Internal(err.to_string())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            Self::OAuth {
                status,
                error,
                description,
            } => {
                let mut res = (
                    status,
                    Json(json!({
                        "error": error,
                        "error_description": description,
                    })),
                )
                    .into_response();

                if status == StatusCode::UNAUTHORIZED && error == "invalid_client" {
                    res.headers_mut().insert(
                        header::WWW_AUTHENTICATE,
                        header::HeaderValue::from_static("Basic realm=\"idp\""),
                    );
                }

                res
            }
            Self::Internal(detail) => {
                eprintln!("[server error] {}", detail);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "server_error",
                        "error_description": "サーバー内部エラーが発生しました",
                    })),
                )
                    .into_response()
            }
        }
    }
}
