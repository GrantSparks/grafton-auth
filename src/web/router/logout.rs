use crate::{axum::routing::get, core::AxumRouter, ServerConfigProvider};

pub fn router<C>(login_page: &str) -> AxumRouter<C>
where
    C: ServerConfigProvider,
{
    AxumRouter::new().route(login_page, get(self::get::logout))
}

mod get {

    use crate::{
        axum::{
            http::StatusCode,
            response::{IntoResponse, Redirect},
        },
        AuthSession,
    };

    pub async fn logout(mut auth_session: AuthSession) -> impl IntoResponse {
        match auth_session.logout().await {
            Ok(_) => Redirect::to("/").into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}
