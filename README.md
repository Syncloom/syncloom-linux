# syncloom-linux

The Linux client: a sync daemon, a command-line client (`syncloom`) and a GTK4/libadwaita app. The synced folder uses an inotify watcher. FUSE on-demand files are not implemented yet.

Part of [Syncloom](https://github.com/Syncloom), a self-hosted, end-to-end encrypted file sync and key/value store. Status: **public preview (0.1)**.

```bash
cargo install --git https://github.com/Syncloom/syncloom-linux syncloom
syncloom login https://your-domain you
syncloom daemon
```
Needs `../syncloom-core` when building from a checkout.

## Working with the other repositories

The Syncloom repositories reference each other by relative path. Clone the ones you need **side by side in one folder**, for example `syncloom-core`, `syncloom-server` and `syncloom-web` next to each other.

## License

Apache License 2.0, see [LICENSE](LICENSE).
