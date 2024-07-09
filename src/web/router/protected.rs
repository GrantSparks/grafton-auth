use askama::Template;

use grafton_server::{
    axum::{routing::get, Router},
    GraftonRouter, ServerConfigProvider,
};

#[derive(Template)]
#[template(path = "protected.html")]
struct ProtectedTemplate<'a> {
    username: &'a str,
}

pub fn router<C>(protected_home: &str) -> GraftonRouter<C>
where
    C: ServerConfigProvider,
{
    Router::new().route(protected_home, get(self::get::protected))
}

mod get {

    use grafton_server::axum::response::IntoResponse;
    use hyper::StatusCode;

    use crate::AuthSession;

    use super::ProtectedTemplate;

    pub async fn protected(auth_session: AuthSession) -> impl IntoResponse {
        match auth_session.user {
            Some(user) => ProtectedTemplate {
                username: &user.username,
            }
            .into_response(),

            None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}
