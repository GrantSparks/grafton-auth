use std::marker::PhantomData;

use {
    askama::Template,
    axum_login::tower_sessions::Session,
    hyper::HeaderMap,
    oxide_auth::{
        endpoint::WebRequest,
        frontends::simple::endpoint::Vacant,
        primitives::{
            authorizer::AuthMap, generator::RandomGenerator, issuer::TokenMap, prelude::*,
        },
    },
    serde_json::json,
    sqlx::SqlitePool,
    typed_builder::TypedBuilder,
    url::Url,
};

use grafton_server::{
    axum::{
        extract::{Form, Path, Query},
        response::{IntoResponse, Json, Redirect},
        routing::{get, post},
        Router,
    },
    tracing::{debug, error, warn},
    GraftonRouter, ServerConfigProvider,
};

use crate::{
    oauth2::{
        AuthzReq, AuthzResp, Credentials, NextOrAuthzReq, NextUrl, OpenAiAuthParams,
        CSRF_STATE_KEY, NEXT_URL_KEY,
    },
    AuthSession, Config, Error,
};

#[derive(TypedBuilder)]
#[allow(dead_code)]
pub struct AccessTokenEndpointBuilder<R: WebRequest> {
    #[builder(default = None, setter(skip))]
    authorizer: Option<AuthMap<RandomGenerator>>,
    #[builder(default = None, setter(skip))]
    registrar: Option<ClientMap>,
    #[builder(default = None, setter(skip))]
    issuer: Option<TokenMap<RandomGenerator>>,
    #[builder(default = None, setter(skip))]
    scopes: Option<Vacant>,
    #[builder(default = None, setter(skip))]
    solicitor: Option<Vacant>,
    #[builder(default = None, setter(skip))]
    response: Option<Vacant>,
    #[builder(default, setter(skip))]
    _marker: PhantomData<R>,
}

#[allow(dead_code)]
impl<R: WebRequest> AccessTokenEndpointBuilder<R>
where
    R::Response: Default,
{
    pub fn with_registrar_from_config(mut self, config: &Config) -> Result<Self, Error> {
        let client_map: ClientMap = config.clone().try_into()?;
        self.registrar = Some(client_map);
        Ok(self)
    }
}

#[derive(Template)]
#[template(path = "provider.html")]
pub struct ProviderTemplate {
    pub message: Option<String>,
    pub next: String,
    pub providers: Vec<String>,
}

pub struct Auth<C>
where
    C: ServerConfigProvider,
{
    config: Config,
    db: SqlitePool,
    _marker: PhantomData<C>,
}

impl<C> Auth<C>
where
    C: ServerConfigProvider,
{
    pub const fn new(config: Config, db: SqlitePool) -> Self {
        Self {
            config,
            db,
            _marker: PhantomData,
        }
    }

    pub fn oauth_auth(&self, Query(next_or_authz): Query<NextOrAuthzReq>) -> ProviderTemplate {
        let providers = self
            .config
            .oauth_providers
            .values()
            .map(|client| client.display_name.clone())
            .collect();

        let next = match next_or_authz {
            NextOrAuthzReq::NextUrl(NextUrl { next }) => next,
            NextOrAuthzReq::AuthzReq(AuthzReq {
                redirect_uri,
                state,
                ..
            }) => {
                let separator = if redirect_uri.contains('?') { '&' } else { '?' };
                format!("{}{}state={}", redirect_uri, separator, state.secret())
            }
        };

        ProviderTemplate {
            message: None,
            next,
            providers,
        }
    }

    pub async fn get_access_token(
        &self,
        mut auth_session: AuthSession,
        Form(OpenAiAuthParams {
            grant_type: _,
            client_id: _,
            client_secret: _,
            code,
            redirect_uri: _,
        }): Form<OpenAiAuthParams>,
    ) -> Result<impl IntoResponse, Error> {
        let provider: String = sqlx::query_scalar(
            r"
            SELECT provider
            FROM downstream_clients
            WHERE code = ?
            ",
        )
        .bind(&code)
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            error!("Failed to retrieve provider for code {}: {}", code, e);
            Error::Sqlx(e)
        })?;

        let oauth_client = self
            .config
            .oauth_providers
            .get(&provider)
            .ok_or_else(|| Error::ProviderNotFoundError(provider.clone()))?;
        let userinfo_uri = oauth_client
            .extra
            .get("userinfo_uri")
            .and_then(|uri| uri.as_str())
            .ok_or_else(|| Error::ClientConfigNotFound("userinfo_uri".to_string()))?;

        let creds = Credentials {
            code: code.clone(),
            provider,
            userinfo_uri: userinfo_uri.to_string(),
        };

        let user = match auth_session.authenticate(creds).await {
            Ok(Some(user)) => {
                debug!("User authenticated successfully");
                user
            }
            Ok(None) => {
                warn!("Authentication succeeded but no user was found");
                return Err(Error::AuthenticationError("User not found".to_string()));
            }
            Err(e) => {
                error!("Internal error during authentication: {:?}", e);
                return Err(Error::AuthenticationError(e.to_string()));
            }
        };

        auth_session.login(&user).await.map_err(|e| {
            error!("Error logging in the user: {:?}", e);
            Error::LoginError("Error logging in the user".to_string())
        })?;

        let response_body = json!({
            "access_token": user.access_token,
            "token_type": "bearer",
            "refresh_token": user.refresh_token,
            "expires_in": user.expires_in,
        });

        Ok(Json(response_body))
    }

    pub async fn callback(
        &self,
        session: Session,
        Path(provider): Path<String>,
        Query(AuthzResp {
            code,
            state: new_state,
        }): Query<AuthzResp>,
    ) -> Result<impl IntoResponse, impl IntoResponse> {
        debug!("OAuth callback for provider: {}", provider);

        let old_state: Option<String> = session
            .get(CSRF_STATE_KEY)
            .await
            .map_err(|_| Error::SessionStateError("Failed to retrieve CSRF state".to_string()))?
            .ok_or(Error::MissingCSRFState)?;

        if old_state != Some(new_state.secret().to_string()) {
            return Err(Error::InvalidCSRFState);
        }

        match session.remove::<String>(NEXT_URL_KEY).await {
            Ok(Some(next)) if !next.is_empty() => {
                let mut url = Url::parse(&next).map_err(|_| {
                    error!("Invalid URL in session: {}", next);
                    Error::InvalidNextUrl(next)
                })?;

                sqlx::query(
                    r"
                        INSERT INTO downstream_clients (code, provider)
                        VALUES (?, ?)
                        ON CONFLICT(code) DO UPDATE
                        SET provider = excluded.provider
                    ",
                )
                .bind(&code)
                .bind(&provider)
                .execute(&self.db)
                .await
                .map_err(|e| {
                    error!("Failed to insert downstream client: {}", e);
                    Error::Sqlx(e)
                })?;

                url.query_pairs_mut().append_pair("code", &code);
                let url_str = url.to_string();
                Ok(Redirect::to(&url_str).into_response())
            }
            _ => Ok(Redirect::to(&self.config.routes.with_root().public_login).into_response()),
        }
    }

    // Remove when completed
    #[allow(clippy::unnecessary_wraps, clippy::unused_self)]
    pub fn refresh_token(&self, headers: &HeaderMap) -> Result<impl IntoResponse, Error> {
        debug!("refresh_token headers:");
        for (key, value) in headers {
            debug!("{}: {:?}", key, value);
        }

        let new_access_token = "new_access_token";
        let new_refresh_token = "new_refresh_token";

        let response_body = json!({
            "access_token": new_access_token,
            "token_type": "bearer",
            "refresh_token": new_refresh_token,
            "expires_in": 1, // TODO: Set appropriate expiration time
        });

        Ok(Json(response_body))
    }

    pub fn router(self) -> GraftonRouter<C> {
        let this = std::sync::Arc::new(self);
        Router::new()
            .route(
                "/oauth/auth",
                get({
                    let this = this.clone();
                    move |query| {
                        let this = this.clone();
                        async move { this.oauth_auth(query) }
                    }
                }),
            )
            .route(
                "/oauth/token",
                post({
                    let this = this.clone();
                    move |auth_session, form| {
                        let this = this.clone();
                        async move { this.get_access_token(auth_session, form).await }
                    }
                }),
            )
            .route(
                "/oauth/token/refresh",
                post({
                    let this = this.clone();
                    move |headers| {
                        let this = this.clone();
                        async move { this.refresh_token(&headers) }
                    }
                }),
            )
            .route(
                "/oauth/:provider/callback",
                get({
                    move |session, path, query| {
                        let this = this.clone();
                        async move { this.callback(session, path, query).await }
                    }
                }),
            )
    }
}
