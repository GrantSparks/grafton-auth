use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use tower_http::services::{ServeDir, ServeFile};

use grafton_server::{
    model::Context,
    tracing::{debug, error},
    ServerConfigProvider,
};

use crate::{AuthConfigProvider, Config, Error};

fn get_fallback_file(config: &Config) -> Result<PathBuf, Error> {
    let web_root_path = Path::new(&config.web_root);
    if !web_root_path.exists() {
        error!(path = %web_root_path.display(), "Web root path does not exist.");
        return Err(Error::PathError(format!(
            "Web root path '{}' does not exist.",
            web_root_path.display()
        )));
    }

    let fallback_file_path = web_root_path.join(&config.index_page);
    if !fallback_file_path.exists() {
        error!(path = %fallback_file_path.display(), "Fallback file does not exist.");
        return Err(Error::PathError(format!(
            "Fallback file '{}' does not exist.",
            fallback_file_path.display()
        )));
    }

    debug!(fallback_file_path = %fallback_file_path.display(), "Successfully found fallback file");
    Ok(fallback_file_path)
}

pub fn create_file_service<C>(app_ctx: &Arc<Context<C>>) -> Result<ServeDir<ServeFile>, Error>
where
    C: ServerConfigProvider + AuthConfigProvider,
{
    let fallback_file_path = get_fallback_file(app_ctx.config.get_auth_config())?;
    Ok(ServeDir::new(&app_ctx.config.get_auth_config().web_root)
        .fallback(ServeFile::new(fallback_file_path)))
}
