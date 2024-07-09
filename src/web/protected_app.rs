use std::{collections::HashMap, sync::Arc};

use {
    askama_axum::IntoResponse,
    axum_login::{
        tower_sessions::{MemoryStore, SessionManagerLayer},
        url_with_redirect_query, AuthManagerLayerBuilder,
    },
    hyper::Uri,
    oauth2::{basic::BasicClient, AuthUrl, RedirectUrl, TokenUrl},
    sqlx::SqlitePool,
};

use grafton_server::{
    axum::{
        body::Body,
        extract::OriginalUri,
        http::{HeaderMap, StatusCode},
        middleware::{from_fn, Next},
        response::Redirect,
    },
    tracing::{debug, error, info},
    Context, GraftonRouter, ServerConfigProvider,
};

use crate::{
    error::Error,
    oauth2::backend::Backend,
    web::router::{auth, create_login_route, protected},
    AuthConfigProvider, AuthSession, Config,
};

pub struct ProtectedApp<C>
where
    C: AuthConfigProvider + ServerConfigProvider,
{
    db: SqlitePool,
    oauth_providers: HashMap<String, BasicClient>,
    session_layer: SessionManagerLayer<MemoryStore>,
    login_url: String,
    protected_router: Option<GraftonRouter<C>>,
    protected_route: String,
    config: Config,
}

impl<C> ProtectedApp<C>
where
    C: AuthConfigProvider + ServerConfigProvider,
{
    pub async fn new(
        app_ctx: Arc<Context<C>>,
        session_layer: SessionManagerLayer<MemoryStore>,
        protected_router: Option<GraftonRouter<C>>,
    ) -> Result<Self, Error> {
        let mut oauth_providers = HashMap::new();

        for (client_name, client_config) in &app_ctx.config.get_auth_config().oauth_providers {
            debug!("Configuring oauth client: {}", client_name);
            let client_id = client_config.client_id.clone();
            let client_secret = client_config.client_secret.clone();

            let auth_url = AuthUrl::new(client_config.auth_uri.clone())?;
            let token_url = TokenUrl::new(client_config.token_uri.clone())?;

            let normalised_url = app_ctx
                .config
                .get_server_config()
                .website
                .format_public_server_url(&format!("/oauth/{client_name}/callback"));

            let redirect_url = RedirectUrl::new(normalised_url)?;

            let client =
                BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
                    .set_redirect_uri(redirect_url);

            oauth_providers.insert(client_name.clone(), client);
            debug!("OAuth client configured: {}", client_name);
        }

        let db = SqlitePool::connect(":memory:").await?;

        debug!("Running database migrations");
        sqlx::migrate!().run(&db).await?;

        info!("App successfully initialized");

        Ok(Self {
            db,
            oauth_providers,
            session_layer,
            login_url: app_ctx
                .config
                .get_auth_config()
                .routes
                .with_root()
                .public_login,
            protected_router,
            protected_route: app_ctx
                .config
                .get_auth_config()
                .routes
                .with_root()
                .protected_home,
            config: app_ctx.config.get_auth_config().clone(),
        })
    }

    #[allow(clippy::cognitive_complexity)]
    pub fn create_auth_router(self) -> GraftonRouter<C> {
        debug!("Creating auth router");
        // Auth service.
        //
        // This combines the session layer with our backend to establish the auth
        // service which will provide the auth session as a request extension.
        let backend = Backend::new(self.db.clone(), self.oauth_providers.clone());
        let auth_layer = AuthManagerLayerBuilder::new(backend, self.session_layer).build();

        let login_url = Arc::new(self.login_url);
        let auth_middleware = from_fn(
            move |mut auth_session: AuthSession,
                  OriginalUri(original_uri): OriginalUri,
                  headers: HeaderMap,
                  req,
                  next: Next| {
                let login_url_clone = login_url.clone();
                async move {
                    if auth_session.user.is_some() {
                        debug!("Authenticated user in session, continuing");
                        next.run(req).await
                    } else {
                        let token = headers
                            .get("authorization")
                            .and_then(|header| header.to_str().ok())
                            .and_then(|header| header.strip_prefix("Bearer "))
                            .map(std::string::ToString::to_string);

                        if let Some(token) = token {
                            let user_result =
                                auth_session.backend.get_user_by_access_token(&token).await;

                            match user_result {
                                Ok(Some(user)) => match auth_session.login(&user).await {
                                    Ok(()) => {
                                        debug!("User authenticated by access token, continuing");
                                        next.run(req).await
                                    }
                                    Err(err) => {
                                        error!(err = %err);
                                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                                    }
                                },
                                Ok(None) => {
                                    debug!("No user found for bearer token");
                                    redirect_to_login(&login_url_clone, &original_uri)
                                }
                                Err(err) => {
                                    error!(err = %err);
                                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                                }
                            }
                        } else {
                            debug!("User not authenticated, redirecting to login");
                            redirect_to_login(&login_url_clone, &original_uri)
                        }
                    }
                }
            },
        );
        info!("Auth middleware created");

        let router = if let Some(router) = self.protected_router {
            debug!("Using provided protected_router");
            router
        } else {
            debug!(
                "No protected_router provided, using default protected::router() at route: {}",
                self.protected_route
            );
            protected::router(&self.protected_route)
        };

        let auth_router = auth::Auth::new(self.config.clone(), self.db);

        router
            .route_layer(auth_middleware)
            .merge(create_login_route())
            .merge(auth_router.router())
            .layer(auth_layer)
    }
}

fn redirect_to_login(login_url: &Arc<String>, original_uri: &Uri) -> hyper::Response<Body> {
    match url_with_redirect_query(login_url, "next", original_uri.clone()) {
        Ok(login_url) => {
            debug!(
                "Redirecting to login url: {} with next param {:?}",
                login_url, original_uri
            );
            Redirect::temporary(&login_url.to_string()).into_response()
        }
        Err(err) => {
            error!(err = %err);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
