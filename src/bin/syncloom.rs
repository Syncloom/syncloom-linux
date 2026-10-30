use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use syncloom_core::client::{Auth, Client, LoginOutcome};
use syncloom_core::state::StateDb;
use syncloom_core::sync::{SyncConfig, SyncEngine, SyncReport};
use syncloom_linux::config::{self, Config};
use syncloom_linux::session;

#[derive(Parser)]
#[command(name = "syncloom", version, about = "Syncloom: end-to-end encrypted file sync and key/value storage")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create an account (first user becomes admin; everyone else needs an invite)
    Register { server: String, username: String, #[arg(long)] invite: Option<String>, #[arg(long)] dir: Option<PathBuf> },
    /// Sign in on this device
    Login { server: String, username: String, #[arg(long)] dir: Option<PathBuf> },
    /// Sign out and forget the keys on this device
    Logout,
    /// Show account and sync folder
    Status,
    /// Synchronise the folder once
    Sync,
    /// Keep the folder in sync (reacts to server pushes, rescans periodically)
    Daemon { #[arg(long, default_value_t = 30)] interval: u64 },
    /// List a remote folder
    Ls { path: Option<String> },
    /// Manage second factors (any single one is enough to sign in)
    #[command(subcommand)]
    Mfa(MfaCmd),
    /// List signed-in devices
    Devices,
    /// Share a file or folder with another user
    Share { path: String, user: String, #[arg(long)] read_only: bool },
    /// Create a public link. The key stays in the URL fragment and never reaches the server.
    Link { path: String, #[arg(long)] password: Option<String>, #[arg(long)] days: Option<i64>, #[arg(long)] max_downloads: Option<i64> },
    /// Key/value store
    #[command(subcommand)]
    Kv(KvCmd),
    /// Print the current code for an authenticator secret (base32)
    Totp { secret: String, /// Shift by whole 30-second steps (a code is single-use per step)
        #[arg(long, default_value_t = 0, allow_hyphen_values = true)] offset: i64 },
}

#[derive(Subcommand)]
enum MfaCmd {
    List,
    /// Add another authenticator app
    AddTotp { #[arg(long, default_value = "Authenticator app")] name: String },
    Rename { id: String, name: String },
    Remove { id: String },
    /// Replace all recovery codes
    RecoveryCodes,
}

#[derive(Subcommand)]
enum KvCmd {
    Create { name: String },
    Put { ns: String, key: String, value: String, #[arg(long)] if_version: Option<i64> },
    Get { ns: String, key: String },
    List { ns: String, #[arg(default_value = "")] prefix: String },
    Delete { ns: String, key: String },
}

fn prompt(label: &str) -> Result<String> {
    eprint!("{label}");
    std::io::stderr().flush()?;
    let mut s = String::new();
    std::io::stdin().lock().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

fn password(label: &str) -> Result<String> {
    if let Ok(p) = std::env::var("SYNCLOOM_PASSWORD") {
        return Ok(p);
    }
    Ok(rpassword::prompt_password(label)?)
}

fn code(label: &str) -> Result<String> {
    if let Ok(c) = std::env::var("SYNCLOOM_TOTP") {
        return Ok(c);
    }
    prompt(label)
}

fn totp_now(secret_or_url: &str, offset_steps: i64) -> Result<String> {
    use totp_rs::{Algorithm, Secret, TOTP};
    let t = if secret_or_url.starts_with("otpauth://") {
        TOTP::from_url_unchecked(secret_or_url).map_err(|e| anyhow!("{e}"))?
    } else {
        let bytes = Secret::Encoded(secret_or_url.replace(' ', "").to_uppercase()).to_bytes().map_err(|e| anyhow!("{e:?}"))?;
        TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, bytes, None, String::new())
    };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64;
    Ok(t.generate((now + offset_steps * 30) as u64))
}

/// Resolve `a/b/c` against the remote tree.
async fn resolve(client: &Client, path: &str) -> Result<syncloom_core::client::Node> {
    let mut parent: Option<String> = None;
    let mut found = None;
    for part in path.split('/').filter(|p| !p.is_empty()) {
        let list = client.list(parent.as_deref()).await?;
        let n = list.into_iter().find(|n| n.name == part).ok_or_else(|| anyhow!("{path}: no such file or folder"))?;
        parent = Some(n.id.clone());
        found = Some(n);
    }
    found.ok_or_else(|| anyhow!("give a path"))
}

fn print_report(r: &SyncReport) {
    for p in &r.uploaded {
        println!("  ↑ {p}");
    }
    for p in &r.downloaded {
        println!("  ↓ {p}");
    }
    for p in &r.moved {
        println!("  → {p}");
    }
    for p in &r.merged {
        println!("  ⇄ merged {p}");
    }
    for p in &r.conflicts {
        println!("  ! conflict copy {p}");
    }
    for p in &r.trashed_remote {
        println!("  ✕ removed on server: {p}");
    }
    for p in &r.deleted_local {
        println!("  ✕ removed here: {p}");
    }
    for (p, why) in &r.skipped {
        eprintln!("  skipped {p}: {why}");
    }
    for e in &r.errors {
        eprintln!("  error: {e}");
    }
}

async fn finish_login(auth: &Auth, outcome: LoginOutcome, device: &str) -> Result<String> {
    match outcome {
        LoginOutcome::Ok { token } => Ok(token),
        LoginOutcome::MfaRequired { token, methods } => {
            if methods.iter().all(|m| m == "webauthn" || m == "recovery") && !methods.contains(&"totp".to_string()) {
                eprintln!("Your account only has security keys. This client cannot use them; enter a recovery code, or sign in through the web app.");
            }
            let c = code("Authentication code (or a recovery code like xxxx-xxxx-xxxx): ")?;
            let method = if c.contains('-') { "recovery" } else { "totp" };
            Ok(auth.mfa_verify(&token, method, &c, device).await?)
        }
        LoginOutcome::EnrollRequired { token } => {
            eprintln!("\nThis account needs a second factor. Add an authenticator app (you can add more, including security keys, later in the web app).");
            let setup = auth.totp_setup(&token, &format!("{device} authenticator")).await?;
            eprintln!("Secret:  {}\nOr open: {}\n", setup.secret, setup.otpauth_url);
            let c = code("Enter the 6-digit code from the app: ")?;
            let done = auth.totp_confirm(&token, &setup.id, &c, device).await?;
            if !done.recovery_codes.is_empty() {
                eprintln!("\nRECOVERY CODES (each works once, store them safely):");
                for rc in &done.recovery_codes {
                    eprintln!("  {rc}");
                }
                eprintln!();
            }
            Ok(done.token)
        }
    }
}

async fn save_session(server: &str, username: &str, pw: &str, token: String, dir: Option<PathBuf>, device: String) -> Result<()> {
    let client = Client::connect(server, &token, pw).await.context("could not unlock your vault")?;
    let in_keyring = config::store_vault(server, username, client.vault())?;
    let sync_dir = dir.unwrap_or_else(config::default_sync_dir);
    Config { server: server.trim_end_matches('/').into(), username: username.to_lowercase(), token, sync_dir: sync_dir.clone(), device }.save()?;
    println!("Signed in as {username}. Sync folder: {}", sync_dir.display());
    if !in_keyring {
        eprintln!("note: no OS keychain available; the vault keys are stored in {} (mode 0600)", config::config_dir().join("vault.json").display());
    }
    Ok(())
}

async fn connect() -> Result<(Config, Client)> {
    let cfg = Config::load()?;
    let client = session::connect(&cfg).await?;
    Ok((cfg, client))
}

fn engine(cfg: &Config, client: Client) -> Result<SyncEngine> {
    Ok(SyncEngine::new(Arc::new(client), SyncConfig { root: cfg.sync_dir.clone(), device: cfg.device.clone() }, StateDb::open(&config::state_db_path())?)?)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Totp { secret, offset } => println!("{}", totp_now(&secret, offset)?),
        Cmd::Register { server, username, invite, dir } => {
            let device = config::default_device_name();
            let auth = Auth::new(&server);
            let pw = password("Choose a password: ")?;
            if std::env::var("SYNCLOOM_PASSWORD").is_err() && pw != password("Repeat the password: ")? {
                bail!("passwords do not match");
            }
            let reg = auth.register(&username, &pw, invite.as_deref(), &device).await?;
            eprintln!("\nRECOVERY KEY (shown once). Without it AND your password your data cannot be recovered:\n\n  {}\n", reg.recovery_key);
            let token = finish_login(&auth, reg.outcome, &device).await?;
            save_session(&server, &username, &pw, token, dir, device).await?;
        }
        Cmd::Login { server, username, dir } => {
            let device = config::default_device_name();
            let auth = Auth::new(&server);
            let pw = password("Password: ")?;
            let outcome = auth.login(&username, &pw, &device).await?;
            let token = finish_login(&auth, outcome, &device).await?;
            save_session(&server, &username, &pw, token, dir, device).await?;
        }
        Cmd::Logout => {
            if let Ok(cfg) = Config::load() {
                if let Ok(c) = session::connect(&cfg).await {
                    let _ = c.logout().await;
                }
                config::delete_vault(&cfg.server, &cfg.username);
            }
            Config::delete()?;
            println!("Signed out. Files in the sync folder were left untouched.");
        }
        Cmd::Status => {
            let (cfg, client) = connect().await?;
            let me = client.me().await?;
            println!("Server:   {}\nAccount:  {} ({})\nFolder:   {}\nDevice:   {}", cfg.server, me.user.username, me.user.role, cfg.sync_dir.display(), cfg.device);
            let quota = me.user.quota_bytes.map(|q| format!(" of {q} bytes")).unwrap_or_default();
            println!("Storage:  {} bytes{quota}\n2FA:      {}", me.user.used_bytes, me.user.mfa_methods.join(", "));
        }
        Cmd::Sync => {
            let (cfg, client) = connect().await?;
            let mut e = engine(&cfg, client)?;
            let r = e.sync_once().await?;
            print_report(&r);
            if r.is_empty() && r.errors.is_empty() {
                println!("Everything is up to date.");
            }
            if !r.errors.is_empty() {
                std::process::exit(1);
            }
        }
        Cmd::Daemon { interval } => {
            let (cfg, client) = connect().await?;
            let mut e = engine(&cfg, client)?;
            let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                let _ = stop_tx.send(true);
            });
            println!("Syncing {} (Ctrl-C to stop)", cfg.sync_dir.display());
            e.run(stop_rx, Duration::from_secs(interval), print_report).await?;
        }
        Cmd::Ls { path } => {
            let (_, client) = connect().await?;
            let parent = match path.as_deref().filter(|p| !p.trim_matches('/').is_empty()) {
                Some(p) => Some(resolve(&client, p).await?.id),
                None => None,
            };
            for n in client.list(parent.as_deref()).await? {
                let suffix = if n.is_folder() { "/" } else { "" };
                println!("{:>10}  {}{suffix}", if n.is_folder() { "-".to_string() } else { n.size.to_string() }, n.name);
            }
        }
        Cmd::Mfa(m) => {
            let (_, client) = connect().await?;
            match m {
                MfaCmd::List => {
                    for x in client.mfa_methods().await? {
                        println!("{}  {:<9} {}", x.id, x.kind, x.name);
                    }
                }
                MfaCmd::AddTotp { name } => {
                    let s = client.add_totp(&name).await?;
                    println!("Secret: {}\nURL:    {}", s.secret, s.otpauth_url);
                    client.confirm_totp(&s.id, &code("Enter the 6-digit code to confirm: ")?).await?;
                    println!("Added.");
                }
                MfaCmd::Rename { id, name } => client.rename_mfa(&id, &name).await?,
                MfaCmd::Remove { id } => client.remove_mfa(&id).await?,
                MfaCmd::RecoveryCodes => {
                    for c in client.new_recovery_codes().await? {
                        println!("{c}");
                    }
                }
            }
        }
        Cmd::Devices => {
            let (_, client) = connect().await?;
            for d in client.devices().await? {
                println!("{} {}  {}", if d.current { "*" } else { " " }, d.id, d.name);
            }
        }
        Cmd::Share { path, user, read_only } => {
            let (_, client) = connect().await?;
            let n = resolve(&client, &path).await?;
            client.share(&n.id, &user, if read_only { "ro" } else { "rw" }).await?;
            println!("Shared {path} with {user} ({}).", if read_only { "read-only" } else { "read-write" });
        }
        Cmd::Link { path, password, days, max_downloads } => {
            let (cfg, client) = connect().await?;
            let n = resolve(&client, &path).await?;
            let expires = days.map(|d| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64 + d * 86_400_000);
            let l = client.create_link(&n.id, password.as_deref(), expires, max_downloads).await?;
            println!("{}/s/{}#k={}", cfg.server, l.token, l.link_key);
        }
        Cmd::Kv(k) => {
            let (_, client) = connect().await?;
            match k {
                KvCmd::Create { name } => println!("{}", client.kv_create_namespace(None, &name).await?.id),
                KvCmd::Put { ns, key, value, if_version } => println!("version {}", client.kv_put(&ns, &key, value.as_bytes(), if_version).await?.version),
                KvCmd::Get { ns, key } => match client.kv_get(&ns, &key).await? {
                    Some(e) => println!("{}", String::from_utf8_lossy(&e.value)),
                    None => bail!("no such key"),
                },
                KvCmd::List { ns, prefix } => {
                    for e in client.kv_list(&ns, &prefix).await? {
                        println!("{}\t{}", e.key, String::from_utf8_lossy(&e.value));
                    }
                }
                KvCmd::Delete { ns, key } => client.kv_delete(&ns, &key, None).await?,
            }
        }
    }
    Ok(())
}
