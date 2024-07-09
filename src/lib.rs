#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]

mod app;
mod error;
pub mod model;
mod oauth2;
mod util;
mod web;

use grafton_config::TokenExpandingConfig;
use oauth2::backend::Backend;

#[cfg(feature = "rbac")]
mod rbac;

pub use {app::Builder, error::Error, util::Config};

pub type AuthSession = axum_login::AuthSession<Backend>;

pub trait AuthConfigProvider: TokenExpandingConfig {
    fn get_auth_config(&self) -> &Config;
}
