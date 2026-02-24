<p align="center">
  <img src="https://em-content.zobj.net/source/apple/391/droplet_1f4a7.png" width="80">
  <br>
  <strong style="font-size:32px">LiquidDrop</strong>
  <br>
  <em>Beautiful local file transfer between your devices.</em>
  <br><br>
  <img src="https://img.shields.io/badge/python-3.7+-blue?style=flat-square&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/dependencies-1-green?style=flat-square">
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-lightgrey?style=flat-square">
  <img src="https://img.shields.io/badge/license-MIT-purple?style=flat-square">
</p>

---

Drop files between your phone and computer in seconds. No accounts, no cloud, no config. Just run it and scan.

<p align="center">
  <strong>🖥️ Terminal QR</strong> → scan with your phone camera → done.
</p>

## ✨ Features

- **Zero config** — one command, instant file sharing
- **QR code** — printed in terminal + web UI, just scan to connect
- **Auto-launches browser** — opens the UI on your desktop automatically
- **Streaming engine** — 256KB chunk streaming, flat memory usage regardless of file size
- **10GB+ files** — handles massive files without breaking a sweat on any hardware
- **Live speed readout** — real-time MB/s speed and ETA during uploads
- **Smart zip** — sending 3+ files? One tap to bundle them into a single zip
- **Threaded server** — handles multiple simultaneous connections
- **Liquid glass UI** — gorgeous dark glassmorphism design, feels native on iPhone
- **Drag & drop** — drop files on desktop, tap to pick on mobile
- **Real-time progress** — animated upload bar with percentage
- **Works both ways** — phone → desktop and desktop → phone
- **Add to Home Screen** — pin it on your iPhone for app-like access
- **Handles any file type** — photos, videos, PDFs, ZIPs, no size limit

## 🔒 Security

LiquidDrop is designed for **trusted local networks** (your home/office WiFi):

| Layer | How |
|---|---|
| **Secret URL token** | Every launch generates a random token so nobody can access the server without the exact URL |
| **LAN only** | Binds to your local IP, never touches the internet |
| **Path traversal protection** | All file operations are sandboxed to `~/LiquidDrop/` |
| **No data collection** | Zero analytics, zero telemetry, zero external calls |
| **Ephemeral** | Token changes every restart — old links stop working |

> ⚠️ **Note:** Traffic is unencrypted HTTP within your local network. Don't use this on public/untrusted WiFi. For home and office networks, the random token provides strong access control.

## 🚀 Quick Start

### 1. Clone

```bash
git clone https://github.com/YOUR_USERNAME/liquiddrop.git
cd liquiddrop
```

### 2. Run

```bash
python3 liquiddrop.py            # Standard mode — seamless, no warnings
python3 liquiddrop.py --secure   # HTTPS mode — full TLS encryption
python3 liquiddrop.py --port 8888  # Custom port
```

### 3. Connect your phone

Point your iPhone/Android camera at the terminal QR code → tap the link → you're in.

**Optional:** In Safari, tap **Share → Add to Home Screen** to pin it like a native app.

### Requirements

- **Python 3.7+** (pre-installed on macOS/Linux)
- **qrcode** + **cryptography** — auto-install on first run, or manually:
  ```bash
  pip install qrcode[pil] cryptography
  ```

## 📱 How It Works

```
┌──────────────┐         WiFi          ┌──────────────┐
│              │  ◄──── Same LAN ────► │              │
│   Desktop    │                       │   iPhone     │
│              │   http://10.x.x.x     │              │
│  python3     │   :7777/token         │  Safari /    │
│  liquiddrop  │ ◄──────────────────── │  Home Screen │
│  .py         │ ────────────────────► │  app         │
│              │                       │              │
│  ~/LiquidDrop/  ← files land here   │              │
└──────────────┘                       └──────────────┘
```

**Phone → Desktop:** Tap "Send Files" → pick from camera roll / files → uploaded to `~/LiquidDrop/`

**Desktop → Phone:** Drag files onto the browser page → tap to download on your phone

## ⚙️ Configuration

Edit the top of `liquiddrop.py`:

```python
PORT = 7777                # Change the port
UPLOAD_DIR = "~/LiquidDrop"  # Change where files are saved
```

## 🗂️ Project Structure

```
liquiddrop/
├── liquiddrop.py    # Everything — server, UI, QR generator
├── README.md
└── LICENSE
```

Yes, it's a single file. That's the point.

## 📄 License

MIT — do whatever you want with it.

---

<p align="center">
  <strong>💧 LiquidDrop</strong>
  <br>
  <em>Built with 🖤 for people who just want to move a file.</em>
</p>
