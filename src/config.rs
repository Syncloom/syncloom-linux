use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use syncloom_core::vault::Vault;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: String,
    pub username: String,
    /// Device token (revocable on the server). Not a secret that decrypts data.
    pub token: String,
    pub sync_dir: PathBuf,
    pub device: String,
}

/// `$SYNCLOOM_CONFIG_DIR`, else `$XDG_CONFIG_HOME/syncloom`, else `~/.config/syncloom`.
pub fn config_dir() -> PathBuf {
    if let Ok(d) = std::env::var("SYNCLOOM_CONFIG_DIR") {
        return d.into();
    }
    dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("syncloom")
}

pub fn state_db_path() -> PathBuf {
    config_dir().join("state.db")
}

pub fn default_sync_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join("Syncloom")
}

pub fn default_device_name() -> String {
    hostname::get().ok().and_then(|h| h.into_string().ok()).unwrap_or_else(|| "linux".into())
}

fn write_private(path: &PathBuf, data: &[u8]) -> Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(data)?;
    Ok(())
}

impl Config {
    fn path() -> PathBuf {
        config_dir().join("config.json")
    }
    pub fn load() -> Result<Config> {
        let p = Self::path();
        let data = std::fs::read(&p).with_context(|| format!("not logged in (no {}); run `syncloom login`", p.display()))?;
        Ok(serde_json::from_slice(&data)?)
    }
    pub fn exists() -> bool {
        Self::path().exists()
    }
    pub fn save(&self) -> Result<()> {
        write_private(&Self::path(), &serde_json::to_vec_pretty(self)?)
    }
    pub fn delete() -> Result<()> {
        let _ = std::fs::remove_file(Self::path());
        let _ = std::fs::remove_file(state_db_path());
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct Secrets {
    master: String,
    private: String,
}

fn keyring_entry(cfg_server: &str, user: &str) -> Result<keyring::Entry> {
    Ok(keyring::Entry::new("syncloom", &format!("{user}@{cfg_server}"))?)
}

fn secrets_file() -> PathBuf {
    config_dir().join("vault.json")
}

/// Keep the unlocked vault keys in the OS keychain (Secret Service on Linux). If no keychain is
/// available (headless server, container) they go to a 0600 file instead; the returned flag says which.
pub fn store_vault(server: &str, user: &str, vault: &Vault) -> Result<bool> {
    let (master, private) = vault.export_secrets();
    let json = serde_json::to_string(&Secrets { master: B64.encode(master), private: B64.encode(private) })?;
    let use_file = std::env::var("SYNCLOOM_NO_KEYRING").is_ok();
    if !use_file {
        if let Ok(e) = keyring_entry(server, user) {
            if e.set_password(&json).is_ok() {
                let _ = std::fs::remove_file(secrets_file());
                return Ok(true);
            }
        }
    }
    write_private(&secrets_file(), json.as_bytes())?;
    Ok(false)
}

pub fn load_vault(server: &str, user: &str) -> Result<Vault> {
    let json = std::env::var("SYNCLOOM_NO_KEYRING")
        .ok()
        .and_then(|_| std::fs::read_to_string(secrets_file()).ok())
        .or_else(|| keyring_entry(server, user).ok().and_then(|e| e.get_password().ok()))
        .or_else(|| std::fs::read_to_string(secrets_file()).ok())
        .ok_or_else(|| anyhow!("vault keys not found; run `syncloom login` again"))?;
    let s: Secrets = serde_json::from_str(&json)?;
    let to_key = |v: &str| -> Result<[u8; 32]> { B64.decode(v)?.try_into().map_err(|_| anyhow!("corrupt vault secrets")) };
    Ok(Vault::from_secrets(to_key(&s.master)?, to_key(&s.private)?))
}

pub fn delete_vault(server: &str, user: &str) {
    if let Ok(e) = keyring_entry(server, user) {
        let _ = e.delete_credential();
    }
    let _ = std::fs::remove_file(secrets_file());
}
