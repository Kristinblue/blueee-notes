# Blueee Notes

Sync selected Obsidian notes, attachments, and community plugin settings across devices. A Blueee Notes account and a registration invite from the operator are required.

Chinese documentation: [README.zh.md](README.zh.md)

## Installation

1. Open Obsidian → Settings → Community plugins.
2. Turn off Restricted mode if prompted.
3. Browse → search "Blueee Notes" → Install → Enable.
4. Manual installation: copy `main.js`, `manifest.json`, and `styles.css` into `<vault>/.obsidian/plugins/simple-note-sync/`, then enable the plugin.

## Usage

1. Open Settings → Blueee Notes.
2. Enter the registration invite and click Verify.
3. New account: Register. Existing account: Log in and connect an existing vault.
4. Enter account, password, and remote vault name (lowercase letters/digits/`-`/`_`, 3–40 characters, unique per account).
5. First device for a vault: "Create a new remote vault". Other devices: "Log in and connect an existing vault" with the same remote name.
6. Notes: Settings → Blueee Notes → Note sync → Open sync panel; choose Pull only / Push only / Two-way and a scope.
7. Plugins: open Plugin sync to upload the plugin list and `data.json` settings; on another device click "Sync to this device", install missing plugins from the community store, then enable or reload them manually.
8. Device verification: the first login from an Obsidian profile requires an email code; later logins in the same profile do not.

## Sync behavior

- The server stores encrypted paths, hashes, and file contents. Clients fetch the encrypted manifest and only upload/download files in the selected scope.
- Pull only downloads remote changes. Push only uploads local changes. Two-way does both. Small Markdown files with a common base are merged with diff3; conflicts are saved to `Sync conflicts` and the local file is kept.
- Deletions are changes. A remote deletion moves an unmodified local file to the trash; a modified local file becomes a conflict copy.
- The server keeps the latest encrypted version of every file. Old versions are kept for at least 7 days and are cleaned after all devices seen in the last 30 days acknowledge a newer revision.
- Per-file limit: 40 MiB. Oversized files are skipped. Auto sync only handles Markdown; PDFs and images require a manual scope.

## Plugin sync

- Upload the installed plugin list plus each plugin's `data.json` settings, encrypted in the same remote vault.
- "Sync to this device" applies settings for installed plugins with the same version. It does not enable or disable plugins automatically; enable or reload them manually.
- Missing plugins are linked to the Obsidian community store. Plugin binaries are never transferred through the sync server.
- Only `data.json` is synced; `localStorage`/`IndexedDB` and large settings are skipped.

## Privacy

- Notes, paths, plugin lists, and plugin settings are encrypted on the device. The server stores encrypted data and an encrypted vault key; it never receives the account password.
- The operator can see account names, emails, remote vault names, file counts/sizes/times, and device names, but not note contents or file paths.
- Do not share one account between people. Each person should register their own account. There is no password reset; keep the password safe.

## Development

```sh
npm ci
npm run build
npm test
```

## License

MIT. See [LICENSE](LICENSE) and [LICENSE-node-diff3.md](LICENSE-node-diff3.md).
