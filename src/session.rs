use crate::config::{load_vault, Config};
use anyhow::Result;
use syncloom_core::client::Client;

/// Reconnect with the saved device token and the vault keys from the keychain.
pub async fn connect(cfg: &Config) -> Result<Client> {
    let vault = load_vault(&cfg.server, &cfg.username)?;
    Ok(Client::with_vault(&cfg.server, &cfg.token, vault).await?)
}
