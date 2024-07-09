use {
    oauth2::CsrfToken,
    serde::{Deserialize, Serialize},
};

pub mod backend;

pub const CSRF_STATE_KEY: &str = "oauth.csrf-state";

#[derive(Debug, Clone, Deserialize)]
pub struct AuthzResp {
    pub code: String,
    pub state: CsrfToken,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthzReq {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: CsrfToken,
    pub scope: String,
}

impl std::fmt::Display for AuthzReq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "response_type={}&client_id={}&redirect_uri={}&state={:?}&scope={}",
            self.response_type, self.client_id, self.redirect_uri, self.state, self.scope
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Credentials {
    pub code: String,
    pub provider: String,
    pub userinfo_uri: String,
}

pub const NEXT_URL_KEY: &str = "auth.next-url";

#[derive(Debug, Deserialize)]
pub struct NextUrl {
    pub next: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum NextOrAuthzReq {
    NextUrl(NextUrl),
    AuthzReq(AuthzReq),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OpenAiAuthParams {
    pub grant_type: String,
    pub client_id: String,
    pub client_secret: String,
    pub code: String,
    pub redirect_uri: String,
}
