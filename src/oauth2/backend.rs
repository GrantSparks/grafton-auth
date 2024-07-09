use std::collections::HashMap;

use {
    axum_login::{AuthnBackend, UserId},
    oauth2::{
        basic::{BasicClient, BasicRequestTokenError},
        reqwest::async_http_client,
        url::Url,
        AuthorizationCode, CsrfToken, Scope, TokenResponse,
    },
    reqwest::header::{HeaderName as ReqwestHeaderName, HeaderValue},
    serde::Deserialize,
    sqlx::SqlitePool,
};

use grafton_server::axum::async_trait;

use crate::{model::User, Error};

use super::Credentials;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct UserInfo {
    login: Option<String>,
    email: Option<String>,
    username: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Backend {
    db: SqlitePool,
    oauth_providers: HashMap<String, BasicClient>,
}

impl Backend {
    pub const fn new(db: SqlitePool, oauth_providers: HashMap<String, BasicClient>) -> Self {
        Self {
            db,
            oauth_providers,
        }
    }

    pub fn authorize_url(&self, provider: String) -> Result<(Url, CsrfToken), Error> {
        self.oauth_providers.get(&provider).map_or_else(
            || Err(Error::ClientConfigNotFound(provider)),
            |oauth_client| {
                let csrf_token = CsrfToken::new_random();

                let scopes: Vec<Scope> = vec![
                    "openid".to_string(),
                    "profile".to_string(),
                    "email".to_string(),
                ]
                .into_iter()
                .map(Scope::new)
                .collect();

                Ok(oauth_client
                    .clone()
                    .authorize_url(|| csrf_token.clone())
                    .add_scopes(scopes)
                    .url())
            },
        )
    }

    pub async fn get_user_by_access_token(
        &self,
        access_token: &str,
    ) -> Result<Option<User>, Error> {
        let query = sqlx::query_as::<_, User>("select * from users where access_token = ?")
            .bind(access_token);

        query.fetch_optional(&self.db).await.map_err(Error::Sqlx)
    }
}

#[async_trait]
impl AuthnBackend for Backend {
    type User = User;
    type Credentials = Credentials;
    type Error = Error;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        if let Some(oauth_client) = self.oauth_providers.get(&creds.provider) {
            let token_res = oauth_client
                .exchange_code(AuthorizationCode::new(creds.code))
                .request_async(async_http_client)
                .await
                .map_err(Self::Error::OAuth2)?;

            let user_agent_header = ReqwestHeaderName::from_static("user-agent");
            let authorization_header = ReqwestHeaderName::from_static("authorization");

            let user_agent_value = HeaderValue::from_static("axum-login");
            let authorization_value =
                HeaderValue::from_str(&format!("Bearer {}", token_res.access_token().secret()))
                    .map_err(Error::InvalidHttpHeaderValue)?;

            let response = reqwest::Client::new()
                .get(creds.userinfo_uri)
                .header(user_agent_header, user_agent_value)
                .header(authorization_header, authorization_value)
                .send()
                .await
                .map_err(Self::Error::Reqwest)?;

            let user_info = response
                .json::<UserInfo>()
                .await
                .map_err(Self::Error::Reqwest)?;

            let login_id: String;
            match creds.provider.as_str() {
                "github" => match user_info.login {
                    Some(login) => login_id = login,
                    None => {
                        return Err(Error::OAuth2Generic(
                            "Login not found in response from GitHub.".to_string(),
                        ))
                    }
                },
                "google" => match user_info.email {
                    Some(email) => login_id = email,
                    None => {
                        return Err(Error::OAuth2Generic(
                            "Email not found in response from Google.".to_string(),
                        ))
                    }
                },
                _ => {
                    return Err(Error::OAuth2(BasicRequestTokenError::Other(format!(
                        "Unsupported provider `{}`.",
                        creds.provider
                    ))))
                }
            }

            let expires_in_seconds = token_res.expires_in().map(|d| {
                let secs = d.as_secs();
                i64::try_from(secs).unwrap_or(i64::MAX)
            });

            let user = sqlx::query_as(
                r"
                insert into users (username, access_token, refresh_token, expires_in)
                values (?, ?, ?, ?)
                on conflict(username) do update
                set access_token = excluded.access_token,
                    refresh_token = excluded.refresh_token,
                    expires_in = excluded.expires_in
                returning *
                ",
            )
            .bind(login_id)
            .bind(token_res.access_token().secret())
            .bind(token_res.refresh_token().map(oauth2::RefreshToken::secret))
            .bind(expires_in_seconds)
            .fetch_one(&self.db)
            .await
            .map_err(Self::Error::Sqlx)?;

            Ok(Some(user))
        } else {
            return Err(Error::ClientConfigNotFound(creds.provider));
        }
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        Ok(sqlx::query_as("select * from users where id = ?")
            .bind(user_id)
            .fetch_optional(&self.db)
            .await
            .map_err(Self::Error::Sqlx)?)
    }
}
