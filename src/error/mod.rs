use std::io;

use {
    grafton_server::axum::{
        body::Body,
        http::{Response as HttpResponse, StatusCode},
        response::{IntoResponse, Response},
    },
    oauth2::{basic::BasicRequestTokenError, reqwest::AsyncHttpClientError},
    sqlx::migrate::MigrateError,
    thiserror::Error,
    tokio_rustls::rustls::Error as RustlsError,
    url::ParseError,
};

#[cfg(feature = "rbac")]
use {
    oso::{Oso, OsoError},
    std::{sync::MutexGuard, sync::PoisonError},
};

#[cfg(feature = "grpc")]
use tonic::{transport::Error as TonicTransportError, Status};

#[derive(Debug, Error)]
pub enum Error {
    #[cfg(feature = "grpc")]
    #[error("gRPC error: {0}")]
    Grpc(#[from] Status),

    #[cfg(feature = "rbac")]
    #[error("Oso error: {0}")]
    OsoError(#[from] OsoError),

    #[error("Path error: {0}")]
    PathError(String),

    #[cfg(feature = "grpc")]
    #[error("Tonic transport error: {0}")]
    TonicTransport(#[from] TonicTransportError),

    #[cfg(feature = "rbac")]
    #[error("Mutex lock error: {0}")]
    MutexLockError(String),

    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    #[error("Client configuration not found: {0}")]
    ClientConfigNotFound(String),

    #[error("SQLx error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("SQLx migrate error: {0}")]
    SqlxMigrate(#[from] MigrateError),

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("OAuth2 error: {0}")]
    OAuth2(#[from] BasicRequestTokenError<AsyncHttpClientError>),

    #[error("OAuth2 generic error: {0}")]
    OAuth2Generic(String),

    #[error("Error formatting URL with protocol '{protocol}', hostname '{hostname}', port {port}, cause {cause}, inner {inner}")]
    UrlFormatError {
        protocol: String,
        hostname: String,
        port: u16,
        inner: ParseError,
        cause: String,
    },

    #[error("Cannot parse URL")]
    ParseError(#[from] ParseError),

    #[error("Invalid HTTP header value: {0}")]
    InvalidHttpHeaderValue(#[from] reqwest::header::InvalidHeaderValue),

    #[error("TLS configuration error: {0}")]
    TlsConfigError(#[from] RustlsError),

    #[error("Session state error: {0}")]
    SessionStateError(String),

    #[error("Missing CSRF state in the session")]
    MissingCSRFState,

    #[error("Invalid CSRF state")]
    InvalidCSRFState,

    #[error("Authentication error: {0}")]
    AuthenticationError(String),

    #[error("Provider not found: {0}")]
    ProviderNotFoundError(String),

    #[error("Login error: {0}")]
    LoginError(String),

    #[error("Session error: {0}")]
    SessionError(String),

    #[error("Failed to serialize session data: {0}")]
    SerializationError(String),

    #[error("Failed to generate authorization URL: {0}")]
    AuthorizationUrlError(String),

    #[error("Configuration error: {0}")]
    ConfigError(#[from] grafton_config::Error),

    #[error("Failed to parse scope: {0}")]
    ParseScopeError(#[from] oxide_auth::primitives::scope::ParseScopeErr),

    #[error("Registrar information missing")]
    MissingRegistrar,

    #[error("Invalid 'next' URL parameter: {0}")]
    InvalidNextUrl(String),
}

#[cfg(feature = "rbac")]
impl From<PoisonError<MutexGuard<'_, Oso>>> for Error {
    fn from(err: PoisonError<MutexGuard<'_, Oso>>) -> Self {
        Self::MutexLockError(format!("Failed to acquire mutex lock: {err}"))
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            Self::SerializationError(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to serialize session data: {msg}"),
            ),
            Self::AuthorizationUrlError(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to generate authorization URL: {msg}"),
            ),
            Self::ProviderNotFoundError(msg) => (
                StatusCode::NOT_FOUND,
                format!("OAuth provider not found: {msg}"),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "An unexpected error occurred".to_string(),
            ),
        };

        let full_message = format!("{status}: {error_message}");
        let body = Body::from(full_message);

        HttpResponse::builder().status(status).body(body).unwrap() // Safe unwrap since we're constructing a valid response
    }
}
