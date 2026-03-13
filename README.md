<p align="center">
  <img src="https://em-content.zobj.net/source/apple/391/droplet_1f4a7.png" width="80">
  <br>
  <strong style="font-size:32px">LiquidDrop</strong>
  <br>
  <em>Move files between your phone and computer. Nothing else.</em>
  <br><br>
  <img src="https://img.shields.io/badge/python-3.7+-blue?style=flat-square&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/dependencies-auto--installed-green?style=flat-square">
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-lightgrey?style=flat-square">
  <img src="https://img.shields.io/badge/license-MIT-purple?style=flat-square">
</p>

---

One Python file. No accounts. No cloud. No install on the receiving device. Run it, scan the QR (or enter the PIN), transfer files.

## Why

Every other file transfer tool wants you to install an app on both devices. LiquidDrop doesn't. Someone walks up to your desk, scans a QR code with their phone camera, and they're sending files. Done.

## Features

- Single command to start, browser opens automatically
- QR code in your terminal and in the web UI
- **PIN code join** — 4-digit PIN as a fallback when QR scanning isn't convenient
- **Stable URLs** — bookmarks and iPhone home screen shortcuts survive server restarts
- Works both ways: phone to desktop, desktop to phone
- Drag and drop on desktop, tap to pick on mobile
- 3+ files? Offers to zip them into one bundle
- Live upload speed and ETA
- Streams files in 256KB chunks, so a 10GB file uses the same memory as a 10KB file
- Threaded server handles multiple connections at once
- Handles any file type, no size limit
- Pin it to your iPhone home screen for app-like access
- Files auto-appear on both devices within seconds
- **Zero-fail dependency install** — auto-installs everything, even if pip is missing

## Quick Start

### 1. Clone

```bash
git clone https://github.com/YOUR_USERNAME/liquiddrop.git
cd liquiddrop
```

### 2. Run

```bash
python3 liquiddrop.py              # standard mode, no warnings
python3 liquiddrop.py --secure     # HTTPS mode, full TLS encryption
python3 liquiddrop.py --port 8888  # custom port
python3 liquiddrop.py --new-token  # regenerate URL (invalidates old bookmarks)
```
Or open `Run LiquidDrop.bat` on Windows.



### 3. Connect your phone

**Option A — QR Code:** Point your camera at the QR code in the terminal. Tap the link. You're in.

**Option B — PIN Code:** Open `http://<your-ip>:7777` on any device. Enter the 4-digit PIN shown in the terminal. You're in.

**Optional:** In Safari, tap Share > Add to Home Screen to make it feel like a native app. The URL is stable — it will work even after restarting the server.

### Requirements

- Python 3.7+
- `qrcode` library (auto-installs on first run, or `pip install qrcode[pil]`)
- `cryptography` library if using `--secure` (also auto-installs)

All dependencies auto-install on first run. If pip itself is missing, LiquidDrop will bootstrap it automatically.

## How It Works

```
┌──────────────┐         WiFi          ┌──────────────┐
│   Desktop    │ <--- same network --> │   iPhone     │
│              │                       │              │
│  python3     │   http://10.x.x.x     │  Safari /    │
│  liquiddrop  │   :7777/token         │  Home Screen │
│  .py         │ <------------------>  │              │
│              │                       │  Or enter    │
│ ~/LiquidDrop/|  <-- files land here  │  PIN: 1234   │
└──────────────┘                       └──────────────┘
```

**Phone to Desktop:** Tap "Send Files", pick from your camera roll or files. They show up in `~/LiquidDrop/`.

**Desktop to Phone:** Drag files onto the browser page. Download them on your phone.

## Security

Two modes depending on where you are.

### Standard (default)

For home and office WiFi. No browser warnings, totally seamless.

| What | How |
|---|---|
| Secret URL token | Random token persisted across restarts. Can't be guessed. |
| PIN entry | 4-digit PIN derived from the token. Shown in terminal and web UI. |
| LAN only | Never touches the internet. |
| WiFi encryption | Your router's WPA2/WPA3 already encrypts local traffic. |
| Sandboxed | All files locked to `~/LiquidDrop/`. Path traversal blocked. |
| Regenerate | Run `--new-token` to invalidate old URLs and start fresh. |

### Secure (`--secure` flag)

For shared or untrusted networks like dorms, coworking spaces, coffee shops.

| What | How |
|---|---|
| Everything above | Plus... |
| HTTPS/TLS 1.2+ | All traffic encrypted between your browser and the server. |
| ECDSA P-256 cert | Auto-generated locally on first run. Valid for 1 year. |
| Fingerprint shown | In terminal and web UI so you can verify the connection. |
| Key file locked | Private key set to owner-only permissions. |

The `--secure` flag will show a one-time browser warning because the cert is self-signed. Tap Advanced > Proceed. This is normal.

No accounts. No analytics. No telemetry. No external calls.

## Config

Edit the top of `liquiddrop.py`:

```python
PORT = 7777                  # change the port
UPLOAD_DIR = "~/LiquidDrop"  # change where files go
```

## Project Structure

```
liquiddrop/
├── liquiddrop.py    # everything
├── README.md
└── LICENSE
```

One file. That's the point.

## License

MIT. Do whatever you want with it.

---

<p align="center">
  <strong>💧 LiquidDrop</strong>
  <br>
  <em>For people who just want to move a file.</em>
</p>
