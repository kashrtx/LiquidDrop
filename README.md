<p align="center">
  <img src="https://em-content.zobj.net/source/apple/391/droplet_1f4a7.png" width="80">
  <br>
  <strong style="font-size:32px">LiquidDrop</strong>
  <br>
  <em>Move files between your phone and computer. Nothing else.</em>
  <br><br>
  <img src="https://img.shields.io/badge/built%20with-Rust-orange?style=flat-square&logo=rust&logoColor=white">
  <img src="https://img.shields.io/badge/install-none-green?style=flat-square">
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-lightgrey?style=flat-square">
  <img src="https://img.shields.io/badge/license-Apache%202.0-purple?style=flat-square">
</p>

---

One file. Nothing to install. No accounts. No cloud. No app on the receiving device. Double-click it, scan the QR (or enter the PIN), transfer files.

## Demo Screenshots

<p align="center">
  <img src="https://github.com/user-attachments/assets/aa3bd22d-b983-4443-8324-5eda9e7235d5" alt="LiquidDrop desktop host view" width="78%">
  <br>
  <em>The Desktop Host View</em>
  <br>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/385b8aaa-ea5d-4802-afba-ba23b1ce65f9" alt="LiquidDrop mobile view" width="32%">
  <br>
  <em>The Mobile View (scrolled down)</em>
  <br>
</p>

## Why

Every other file transfer tool wants you to install an app on both devices. LiquidDrop doesn't. Someone walks up to your desk, scans a QR code with their phone camera, and they're sending files. Done.

## Download and run

Grab the file for your computer below (or from the [Releases](../../releases/latest) page) and open it. That's it — no Python, no pip, no installer.

| OS | Download | First launch |
|---|---|---|
| Windows | [LiquidDrop-windows-x64.zip](../../releases/latest/download/LiquidDrop-windows-x64.zip) → `LiquidDrop.exe` | SmartScreen may say "unrecognized app": **More info → Run anyway**. Allow it on **Private networks** when the firewall asks (phones can't connect otherwise). |
| macOS | [LiquidDrop-macos-universal.zip](../../releases/latest/download/LiquidDrop-macos-universal.zip) → `LiquidDrop.app` (Intel + Apple Silicon) | Right-click → **Open** the first time (the app isn't notarized). Allow "find devices on your local network". |
| Linux | [LiquidDrop-linux-x64.tar.gz](../../releases/latest/download/LiquidDrop-linux-x64.tar.gz) → `liquiddrop` | `./liquiddrop` (static binary, any distro). |

Your browser opens to the host view and LiquidDrop moves into the **system tray** (Windows) or **menu bar** (macOS). The tray menu shows the phone link, PIN and connected devices, and has **Open LiquidDrop**, **Copy phone link**, **Open shared folder** and **Quit**. Hover the icon to see live transfer speed. On Linux it runs in the terminal (the Linux build stays a single static file with no GUI libraries).

Started from a terminal, LiquidDrop keeps printing the QR code and log there as well. Use `--no-tray` to skip the icon.

```bash
liquiddrop              # standard mode
liquiddrop --secure     # HTTPS with a self-signed certificate
liquiddrop --port 8888  # custom port
liquiddrop --new-token  # new URL (invalidates old bookmarks)
liquiddrop --dir D:\Shared --no-browser --no-tray --verbose
```
**Secure mode (HTTPS):** run in terminal `LiquidDrop.exe --secure` (Windows), `open -a LiquidDrop --args --secure` (Mac) or `./liquiddrop --secure` (Linux), or add ` --secure` to a shortcut's Target, then accept the one-time certificate warning on your phone.

### Connect your phone

**QR code:** point the camera at it, tap the link.
**PIN:** open `http://<your-ip>:7777` (or `http://liquiddrop.local:7777` on iPhone/Mac/Windows) and enter the 4-digit PIN.
**Home screen:** Safari → Share → Add to Home Screen. The URL is stable across restarts.

## What's new in v5

v5 is a rewrite in Rust. The speed you'll actually feel comes from a new transfer design:

- **Parallel, resumable uploads.** Files go up two at a time in bounded chunks. If the phone sleeps or Wi-Fi drops, the upload continues where it stopped. Unfinished files never show up half-written in the list.
- **Instant updates.** One live connection per device replaces the old polling every 2–3 seconds. New files appear immediately and phones use less battery.
- **Real "download selected".** The computer streams one zip directly (no compression, so it starts instantly). Nothing is buffered in the phone's memory, ZIP64 handles files over 4 GB, and the progress bar is real because the size is known up front.
- **"Zip & Send" without the memory crash.** Files upload normally and the computer bundles them afterwards.
- **Resume and seek.** Downloads support byte ranges, so interrupted downloads resume and videos seek properly in the preview player (iPhone Safari needs this).
- **Thumbnails.** The file list loads small server-made thumbnails (rotated correctly) instead of every full-size photo.
- **Smarter networking.** Works offline and on hotspots, ignores VPN/Docker adapters, follows you when the laptop changes networks, and the host can pick the network from a menu. The QR updates live.
- **Lives in the tray.** Double-click and it tucks into the system tray / menu bar with live status, a copy-link button and a clean Quit.
- **Single file, starts instantly.** UI, add-ons and pdf.js are built into the executable. Secure mode needs no extra libraries.

### Fixes from v4

- Downloading files with non-Latin names (Chinese, Arabic, emoji…) crashed the request.
- Interrupted uploads left truncated files that looked complete.
- Two uploads with the same name at the same moment could overwrite each other.
- JSZip and pdf.js came from CDNs, so zipping and PDF preview failed without internet.
- With no internet the QR code pointed at `127.0.0.1`.
- Uploaded HTML/SVG files previewed inline could run scripts with host privileges; previews are now sandboxed.
- The server spoke HTTP/1.0, so every request opened a new connection.

### Upgrading from v4

Nothing to migrate. v5 uses the same `~/LiquidDrop` folder, `.token`, port, URL layout, extension folders, settings and certificates, so bookmarks, home-screen shortcuts and add-ons keep working. The Python version is kept in [`legacy/`](legacy/) as a fallback.

## Security

| Standard mode | Secure mode (`--secure`) |
|---|---|
| Secret URL token (persisted) | Everything on the left, plus |
| 4-digit PIN with lockout after 5 wrong tries | HTTPS (TLS 1.2+, HTTP/2) |
| LAN only, no external calls | ECDSA P-256 self-signed cert, generated locally, valid 1 year |
| Files sandboxed to `~/LiquidDrop` (no traversal, no hidden files, no symlink escapes) | Fingerprint shown in terminal and web UI |
| Previews sandboxed, `nosniff`, `no-referrer` | Typing `http://` redirects to `https://` |

The only optional outside request is the weather widget in the Status Strip add-on (Open-Meteo), which you can turn off.

## Extensions

Open the **Extensions** tab on the host to create, install, toggle and configure add-ons. User add-ons live in `~/LiquidDrop/extensions/<id>/`. See [assets/readme/EXTENSIONS.md](assets/readme/EXTENSIONS.md).

v5 adds live events to the add-on API (existing add-ons keep working unchanged):

```js
const api = window.LiquidDropExtensions;
api.on('files', list => {});        // file list changed
api.on('status', s => {});          // devices + speed, every 2s
api.on('settings', ({id}) => {});   // host changed an add-on's settings
api.on('state', ({id}) => {});      // shared state changed
api.on('live', ({connected}) => {});
await api.uploadFiles(fileList);    // uses the resumable engine
api.downloadUrl(name); api.previewUrl(name); api.thumbnailUrl(name);
```

## Building from source

Install Rust from <https://rustup.rs>, then:

```bash
./scripts/fetch-vendor.sh      # optional: bundle pdf.js for offline PDF preview (Windows: scripts\fetch-vendor.ps1)
cargo build --release          # → target/release/liquiddrop(.exe)
cargo test --release           # unit + end-to-end tests
```

Optional features (on by default): `mdns` (liquiddrop.local), `thumbnails`, and `tray` (Windows and macOS only). Build without them using `cargo build --release --no-default-features`.

The upload regression suite also runs with Node:

```bash
node tests/ui/upload-stall.test.js ui/app.js
SCENARIO=1 QUIET_DELAY=250 GUARD_MS=90000 node tests/ui/upload-stall.test.js ui/app.js
```

An optional real Chromium suite exercises the actual file picker and server,
including lost replies after files are saved. Install `playwright` outside the
checkout, set `LD_PLAYWRIGHT` to its module directory, then run
`node tests/ui/browser-upload.test.js target/release/liquiddrop`.
`LD_CHROMIUM` can override the default `/usr/bin/chromium` executable.

To publish downloads, push a tag such as `v5.0.2`. GitHub Actions (`.github/workflows/release.yml`) builds Windows, macOS (universal `.app`) and Linux, then attaches them to a release.

## Project structure

```
src/            Rust app (server, uploads, zip streaming, extensions, TLS, ...)
ui/             web UI (embedded into the binary at build time)
assets/extensions/  bundled add-ons (also embedded)
packaging/      app icons, macOS Info.plist
tests/          end-to-end tests
legacy/         v4.1 (Python), kept as a fallback
```

## License

Apache 2.0. See the LICENSE file for details.

---

<p align="center">
  <strong>💧 LiquidDrop</strong>
  <br>
  <em>For people who just want to move a file.</em>
</p>
