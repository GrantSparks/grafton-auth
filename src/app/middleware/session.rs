use {
    axum_login::tower_sessions::{cookie::SameSite, Expiry, MemoryStore, SessionManagerLayer},
    time::Duration,
};

use grafton_server::tracing::debug;

pub fn create_session_layer() -> SessionManagerLayer<MemoryStore> {
    debug!("Creating session layer");

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_same_site(SameSite::Lax)
        .with_expiry(Expiry::OnInactivity(Duration::days(1)));

    debug!("Session layer created");
    session_layer
}
