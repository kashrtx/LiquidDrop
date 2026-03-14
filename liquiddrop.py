#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════╗
║          💧 LiquidDrop v3.1                  ║
║   Beautiful Local File Transfer              ║
║                                              ║
║   python3 liquiddrop.py              (HTTP)  ║
║   python3 liquiddrop.py --secure     (HTTPS) ║
║                                              ║
║   Scan the QR code or enter the PIN!         ║
╚══════════════════════════════════════════════╝
"""

import http.server, socketserver, os, sys, socket, json, secrets
import urllib.parse, mimetypes, shutil, signal, subprocess, io
import webbrowser, threading, ssl, hashlib, argparse, time
from pathlib import Path
from datetime import datetime, timedelta, timezone

PORT = 7777
UPLOAD_DIR = os.path.join(os.path.expanduser("~"), "LiquidDrop")
CERT_DIR = os.path.join(UPLOAD_DIR, ".certs")
TOKEN_FILE = os.path.join(UPLOAD_DIR, ".token")
CHUNK = 256 * 1024
SECURE = False
PIN_CODE = ""

# PIN brute-force protection
_pin_fails = {}          # ip -> (fail_count, last_fail_time)
_PIN_MAX_FAILS = 5
_PIN_LOCKOUT_SECS = 60

os.makedirs(UPLOAD_DIR, exist_ok=True)


def load_or_create_token(force_new=False):
    """Load saved token from disk, or create a new one. Survives restarts."""
    if not force_new and os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, "r") as f:
                token = f.read().strip()
            if token and len(token) >= 8:
                return token
        except Exception:
            pass
    token = secrets.token_urlsafe(8)
    try:
        with open(TOKEN_FILE, "w") as f:
            f.write(token)
    except Exception:
        pass
    return token


def generate_pin(token):
    """Derive a stable 4-digit PIN from the token."""
    h = hashlib.sha256(token.encode()).hexdigest()
    return str(int(h[:8], 16) % 10000).zfill(4)


TOKEN = load_or_create_token()


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


LOCAL_IP = get_local_ip()

# ── Dependency helper ────────────────────────────────────────────────────


def _ensure_pip():
    """Make sure pip is available; bootstrap it if missing."""
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "--version"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    print("  \033[33m📦 Bootstrapping pip (one-time)...\033[0m")
    try:
        import ensurepip
        ensurepip.bootstrap(upgrade=True, default_pip=True)
        return True
    except Exception:
        pass
    try:
        subprocess.check_call(
            [sys.executable, "-m", "ensurepip", "--upgrade"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return True
    except Exception:
        return False


def pip_install(pkg, import_name=None):
    name = import_name or pkg
    try:
        return __import__(name)
    except ImportError:
        pass
    _ensure_pip()
    strategies = [
        [sys.executable, "-m", "pip", "install", pkg],
        [sys.executable, "-m", "pip", "install", "--user", pkg],
    ]
    last_err = None
    for cmd in strategies:
        for attempt in range(2):
            try:
                label = "(retry) " if attempt else ""
                print(f"  \033[33m📦 Installing {pkg} {label}(one-time)...\033[0m")
                subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return __import__(name)
            except subprocess.CalledProcessError as e:
                last_err = e
            except Exception as e:
                last_err = e
                break
    print(f"  \033[31m❌ Could not install {pkg}.\033[0m")
    print(f"  \033[31m   Please run manually: pip install {pkg}\033[0m")
    if last_err:
        print(f"  \033[90m   Error: {last_err}\033[0m")
    sys.exit(1)


# ── TLS Certificate (only used with --secure) ────────────────────────────

CERT_FILE = os.path.join(CERT_DIR, "cert.pem")
KEY_FILE = os.path.join(CERT_DIR, "key.pem")
CERT_FINGERPRINT = ""


def generate_certificate():
    global CERT_FINGERPRINT
    os.makedirs(CERT_DIR, exist_ok=True)

    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        try:
            with open(CERT_FILE, "rb") as f:
                cert_data = f.read()
            from cryptography import x509
            cert = x509.load_pem_x509_certificate(cert_data)
            if cert.not_valid_after_utc > datetime.now(timezone.utc):
                CERT_FINGERPRINT = format_fingerprint(cert_data)
                print("  \033[32m🔒 Reusing existing TLS certificate\033[0m")
                return
        except Exception:
            pass

    print("  \033[33m🔐 Generating TLS certificate...\033[0m")
    cryptography = pip_install("cryptography")

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    import ipaddress

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "LiquidDrop"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LiquidDrop Local Transfer"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address(LOCAL_IP)),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]), critical=False)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    with open(CERT_FILE, "wb") as f:
        f.write(cert_pem)
    with open(KEY_FILE, "wb") as f:
        f.write(key_pem)
    try:
        os.chmod(KEY_FILE, 0o600)
    except Exception:
        pass

    CERT_FINGERPRINT = format_fingerprint(cert_pem)
    print("  \033[32m🔒 TLS certificate generated (valid 1 year)\033[0m")


def format_fingerprint(cert_pem):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    cert = x509.load_pem_x509_certificate(cert_pem)
    der = cert.public_bytes(serialization.Encoding.DER)
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


# ── QR Code ──────────────────────────────────────────────────────────────

BASE_URL = ""
QR_PNG_BYTES = None


def generate_qr():
    global QR_PNG_BYTES
    qrcode = pip_install("qrcode[pil]", "qrcode")
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=3,
    )
    qr.add_data(BASE_URL)
    qr.make(fit=True)
    try:
        from PIL import Image as PILImage
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        QR_PNG_BYTES = buf.getvalue()
    except ImportError:
        QR_PNG_BYTES = matrix_to_png(qr.get_matrix())
    return qr


def matrix_to_png(matrix):
    import struct, zlib
    scale, border = 10, 30
    n = len(matrix)
    w = h = n * scale + border * 2
    raw = bytearray()
    for y in range(h):
        raw.append(0)
        for x in range(w):
            mx, my = (x - border) // scale, (y - border) // scale
            raw.append(
                0 if 0 <= mx < n and 0 <= my < n and matrix[my][mx] else 255
            )

    def chunk(ct, d):
        c = ct + d
        return (
            struct.pack(">I", len(d))
            + c
            + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)
        )

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 0, 0, 0, 0)
    return (
        sig
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )


def print_terminal_qr(qr):
    try:
        matrix = qr.get_matrix()
        padded = list(matrix)
        if len(padded) % 2:
            padded.append([False] * len(matrix[0]))
        for r in range(0, len(padded), 2):
            line = "  "
            for c in range(len(padded[0])):
                top = padded[r][c]
                bot = padded[r + 1][c] if r + 1 < len(padded) else False
                if top and bot:
                    line += "█"
                elif top:
                    line += "▀"
                elif bot:
                    line += "▄"
                else:
                    line += " "
            print(f"\033[97m{line}\033[0m")
    except Exception as e:
        print(f"  \033[33m(QR error: {e})\033[0m")


# ── Streaming Multipart Parser ───────────────────────────────────────────


class StreamingMultipartParser:
    def __init__(self, rfile, boundary, content_length):
        self.rfile = rfile
        self.boundary = b"--" + boundary
        self.end_boundary = self.boundary + b"--"
        self.content_length = content_length
        self.bytes_read = 0

    def _read(self, n):
        remaining = self.content_length - self.bytes_read
        to_read = min(n, remaining)
        if to_read <= 0:
            return b""
        data = self.rfile.read(to_read)
        self.bytes_read += len(data)
        return data

    def _readline(self, limit=65536):
        remaining = self.content_length - self.bytes_read
        if remaining <= 0:
            return b""
        data = self.rfile.readline(min(limit, remaining))
        self.bytes_read += len(data)
        return data

    def parse(self):
        # Skip the initial boundary line
        self._readline()
        while self.bytes_read < self.content_length:
            # Parse headers
            headers = {}
            while True:
                line = self._readline()
                if not line or line.strip() == b"":
                    break
                if b":" in line:
                    k, v = line.split(b":", 1)
                    headers[k.strip().lower()] = v.strip()
            if not headers:
                break

            # Extract filename
            disp = headers.get(b"content-disposition", b"").decode(
                "utf-8", errors="replace"
            )
            filename = None
            if 'filename="' in disp:
                fn_start = disp.find('filename="') + 10
                fn_end = disp.find('"', fn_start)
                filename = Path(disp[fn_start:fn_end]).name

            # Sanitize filename — reject dotfiles and empty names
            if not filename or filename.startswith("."):
                filename = f"file_{secrets.token_hex(4)}"

            # Strip null bytes, control characters, and path separators
            filename = "".join(
                c for c in filename if c.isprintable() and c not in '/\\:\x00'
            )
            if not filename:
                filename = f"file_{secrets.token_hex(4)}"

            dest = Path(UPLOAD_DIR) / filename
            if dest.exists():
                stem, suffix = dest.stem, dest.suffix
                c = 1
                while dest.exists():
                    dest = Path(UPLOAD_DIR) / f"{stem} ({c}){suffix}"
                    c += 1

            boundary_bytes = b"\r\n" + self.boundary
            written = 0
            with open(dest, "wb") as f:
                buf = b""
                while self.bytes_read < self.content_length:
                    chunk = self._read(CHUNK)
                    if not chunk:
                        if buf:
                            f.write(buf)
                            written += len(buf)
                        break
                    buf += chunk
                    idx = buf.find(boundary_bytes)
                    if idx != -1:
                        if idx > 0:
                            f.write(buf[:idx])
                            written += idx
                        after = buf[idx + len(boundary_bytes):]
                        if len(after) < 2 and self.bytes_read < self.content_length:
                            after += self._read(2 - len(after))
                        if after.startswith(b"--"):
                            yield filename, dest, written
                            return
                        elif after.startswith(b"\r\n"):
                            yield filename, dest, written
                            break
                        else:
                            yield filename, dest, written
                            return
                    else:
                        holdback = len(boundary_bytes) + 2
                        safe = len(buf) - holdback
                        if safe > 0:
                            f.write(buf[:safe])
                            written += safe
                            buf = buf[safe:]
                        if len(buf) > CHUNK * 4:
                            flush = len(buf) - holdback
                            if flush > 0:
                                f.write(buf[:flush])
                                written += flush
                                buf = buf[flush:]
                else:
                    # Reached content_length — strip trailing boundary markers
                    if buf:
                        for ending in [
                            b"\r\n" + self.end_boundary + b"\r\n",
                            b"\r\n" + self.end_boundary + b"--",
                            b"\r\n" + self.end_boundary,
                            b"\r\n" + self.boundary,
                        ]:
                            if buf.endswith(ending):
                                buf = buf[: -len(ending)]
                                break
                        if buf:
                            f.write(buf)
                            written += len(buf)
                    yield filename, dest, written
                    return
            yield filename, dest, written


# ── Helpers ──────────────────────────────────────────────────────────────


def _safe_path(filename):
    """Resolve a filename within UPLOAD_DIR; return Path or None if invalid."""
    fpath = (Path(UPLOAD_DIR) / filename).resolve()
    upload_dir = Path(UPLOAD_DIR).resolve()
    if fpath.parent != upload_dir or not fpath.is_file():
        return None
    return fpath


def _check_pin_rate_limit(ip):
    """Return True if this IP is currently locked out from PIN attempts."""
    entry = _pin_fails.get(ip)
    if not entry:
        return False
    fails, last_time = entry
    if fails >= _PIN_MAX_FAILS:
        if time.time() - last_time < _PIN_LOCKOUT_SECS:
            return True
        # Lockout expired — reset
        del _pin_fails[ip]
    return False


def _record_pin_fail(ip):
    entry = _pin_fails.get(ip, (0, 0))
    _pin_fails[ip] = (entry[0] + 1, time.time())


def _clear_pin_fails(ip):
    _pin_fails.pop(ip, None)


# ── HTML UI ──────────────────────────────────────────────────────────────


def build_html_page():
    protocol = "HTTPS" if SECURE else "HTTP"
    lock_icon = "🔒" if SECURE else "🌐"
    sec_label = "TLS Encrypted · HTTPS" if SECURE else "Local Network · HTTP"
    sec_detail = (
        f"SHA-256: {CERT_FINGERPRINT[:23]}…"
        if SECURE
        else "Secret token protected · WiFi encrypted (WPA)"
    )

    return (
        """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<title>LiquidDrop</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0a1a;--glass:rgba(255,255,255,0.06);--glass-border:rgba(255,255,255,0.12);
  --glass-hi:rgba(255,255,255,0.15);--accent:#6ee7b7;--accent2:#818cf8;--accent3:#f472b6;
  --text:#f0f0f5;--text2:rgba(255,255,255,0.55);--radius:24px;
  --safe-top:env(safe-area-inset-top,20px);--safe-bottom:env(safe-area-inset-bottom,20px);
}
html{height:100%;-webkit-text-size-adjust:100%}
body{
  min-height:100%;font-family:-apple-system,BlinkMacSystemFont,'SF Pro Display','Segoe UI',sans-serif;
  background:var(--bg);color:var(--text);overflow-x:hidden;
  padding:calc(var(--safe-top) + 16px) 16px calc(var(--safe-bottom) + 100px);
  -webkit-font-smoothing:antialiased;
}
.orb{position:fixed;border-radius:50%;filter:blur(80px);opacity:.35;pointer-events:none;z-index:0}
.orb-1{width:340px;height:340px;background:radial-gradient(circle,#6ee7b7,transparent 70%);top:-80px;right:-60px;animation:f1 12s ease-in-out infinite}
.orb-2{width:400px;height:400px;background:radial-gradient(circle,#818cf8,transparent 70%);bottom:-100px;left:-80px;animation:f2 15s ease-in-out infinite}
.orb-3{width:250px;height:250px;background:radial-gradient(circle,#f472b6,transparent 70%);top:40%;left:50%;animation:f3 10s ease-in-out infinite}
@keyframes f1{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(-40px,30px) scale(1.1)}}
@keyframes f2{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(30px,-40px) scale(1.15)}}
@keyframes f3{0%,100%{transform:translate(-50%,-50%) scale(1)}50%{transform:translate(-50%,-50%) scale(1.2) translate(20px,-20px)}}
.glass{
  background:var(--glass);backdrop-filter:blur(40px) saturate(1.6);-webkit-backdrop-filter:blur(40px) saturate(1.6);
  border:1px solid var(--glass-border);border-radius:var(--radius);position:relative;z-index:1;
  box-shadow:0 8px 32px rgba(0,0,0,0.3),inset 0 1px 0 rgba(255,255,255,0.08);
}
.glass::before{content:'';position:absolute;inset:0;border-radius:inherit;background:linear-gradient(135deg,rgba(255,255,255,0.08) 0%,transparent 50%);pointer-events:none}
.header{text-align:center;padding:28px 20px 20px;margin-bottom:16px}
.logo{font-size:42px;margin-bottom:4px;display:block;filter:drop-shadow(0 0 20px rgba(110,231,183,0.4))}
.header h1{font-size:28px;font-weight:700;background:linear-gradient(135deg,var(--accent),var(--accent2),var(--accent3));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;letter-spacing:-0.5px}
.header p{color:var(--text2);font-size:13px;margin-top:6px;font-weight:500}
.device-badge{display:inline-flex;align-items:center;gap:6px;background:rgba(110,231,183,0.1);border:1px solid rgba(110,231,183,0.2);border-radius:100px;padding:5px 14px;font-size:12px;color:var(--accent);margin-top:12px;font-weight:600}
.device-badge .dot{width:7px;height:7px;background:var(--accent);border-radius:50%;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.security-badge{display:flex;align-items:center;gap:10px;padding:14px 18px;margin-bottom:16px;font-size:12px}
.security-badge .lock{font-size:20px}
.security-info{flex:1;min-width:0}
.security-info strong{display:block;font-size:13px;color:var(--accent);margin-bottom:2px}
.security-info span{color:var(--text2);font-size:11px;word-break:break-all;font-family:'SF Mono',ui-monospace,monospace}
.qr-section{padding:24px;margin-bottom:16px;text-align:center}
.qr-section h2{font-size:15px;font-weight:600;margin-bottom:14px;color:var(--text2)}
.qr-wrap{display:inline-block;padding:14px;background:#fff;border-radius:18px;box-shadow:0 4px 24px rgba(0,0,0,0.25)}
.qr-wrap img{display:block;width:180px;height:180px}
.qr-url{margin-top:14px;font-size:11px;color:var(--text2);word-break:break-all;font-family:'SF Mono',ui-monospace,monospace;background:rgba(255,255,255,0.04);padding:8px 14px;border-radius:12px;cursor:pointer;transition:background .2s}
.qr-url:hover{background:rgba(255,255,255,0.08)}
.dropzone{padding:40px 20px;margin:0 0 16px;text-align:center;cursor:pointer;transition:all .3s cubic-bezier(.4,0,.2,1);position:relative;overflow:hidden}
.dropzone:hover,.dropzone.drag-over{background:rgba(110,231,183,0.08);border-color:rgba(110,231,183,0.3);transform:scale(1.01)}
.dropzone.drag-over .drop-icon{transform:scale(1.15);filter:drop-shadow(0 0 30px rgba(110,231,183,0.6))}
.drop-icon{font-size:52px;display:block;margin-bottom:12px;transition:all .3s ease}
.dropzone h2{font-size:18px;font-weight:600;margin-bottom:6px}
.dropzone p{color:var(--text2);font-size:13px}
.dropzone input{display:none}
.upload-bar{margin:0 0 16px;padding:16px 20px;opacity:0;transform:translateY(-10px);transition:all .4s ease;pointer-events:none}
.upload-bar.active{opacity:1;transform:translateY(0);pointer-events:auto}
.upload-info{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.upload-name{font-size:13px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:55%}
.upload-speed{font-size:11px;color:var(--text2);font-variant-numeric:tabular-nums}
.upload-pct{font-size:13px;font-weight:700;color:var(--accent);font-variant-numeric:tabular-nums}
.progress-track{height:6px;border-radius:3px;background:rgba(255,255,255,0.06);overflow:hidden}
.progress-fill{height:100%;border-radius:3px;width:0%;background:linear-gradient(90deg,var(--accent),var(--accent2));transition:width .15s linear;box-shadow:0 0 16px rgba(110,231,183,0.3)}
.section-title{font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;color:var(--text2);padding:0 8px;margin:20px 0 10px}
.file-list{display:flex;flex-direction:column;gap:8px;margin-bottom:16px}
.file-card{padding:14px 18px;display:flex;align-items:center;gap:14px;cursor:default;transition:all .25s ease;text-decoration:none;color:inherit}
.file-card:active{transform:scale(0.985)}
.file-icon{width:44px;height:44px;border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0;background:linear-gradient(135deg,rgba(110,231,183,0.15),rgba(129,140,248,0.15));border:1px solid rgba(255,255,255,0.08)}
.file-icon.img-type{background:linear-gradient(135deg,rgba(244,114,182,0.2),rgba(251,146,60,0.15))}
.file-icon.vid-type{background:linear-gradient(135deg,rgba(129,140,248,0.2),rgba(244,114,182,0.15))}
.file-icon.doc-type{background:linear-gradient(135deg,rgba(56,189,248,0.2),rgba(110,231,183,0.15))}
.file-meta{flex:1;min-width:0}
.file-name{font-size:14px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.file-detail{font-size:12px;color:var(--text2);margin-top:2px}
.file-dl{font-size:15px;flex-shrink:0;transition:all .2s;padding:10px 12px;border-radius:12px;background:rgba(110,231,183,0.08);color:var(--accent);text-decoration:none;display:flex;align-items:center;justify-content:center;line-height:1}
.file-dl:hover{background:rgba(110,231,183,0.18);color:var(--accent)}
.file-delete{font-size:15px;flex-shrink:0;padding:10px 12px;cursor:pointer;transition:all .2s;border:none;background:rgba(255,80,80,0.08);color:rgba(255,100,100,0.8);border-radius:12px;display:flex;align-items:center;justify-content:center;line-height:1}
.file-delete:hover{background:rgba(255,80,80,0.18);color:rgba(255,100,100,1)}
.file-delete:active{transform:scale(0.92)}
.empty-state{text-align:center;padding:40px 20px;color:var(--text2);font-size:14px}
.empty-state span{font-size:36px;display:block;margin-bottom:10px;opacity:.5}
.toast{position:fixed;bottom:calc(var(--safe-bottom) + 24px);left:50%;transform:translateX(-50%) translateY(80px);background:rgba(20,20,35,0.92);backdrop-filter:blur(20px);border:1px solid var(--glass-border);border-radius:16px;padding:12px 22px;font-size:14px;font-weight:600;z-index:999;opacity:0;transition:all .4s cubic-bezier(.4,0,.2,1);pointer-events:none;box-shadow:0 12px 40px rgba(0,0,0,0.4);white-space:nowrap}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.success{border-color:rgba(110,231,183,0.3);color:var(--accent)}
.toast.error{border-color:rgba(244,114,182,0.3);color:var(--accent3)}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.6);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);z-index:900;display:flex;align-items:center;justify-content:center;padding:20px;opacity:0;pointer-events:none;transition:opacity .3s ease}
.modal-overlay.show{opacity:1;pointer-events:auto}
.modal{background:rgba(20,20,40,0.95);border:1px solid var(--glass-border);border-radius:24px;padding:28px 24px;max-width:340px;width:100%;text-align:center;transform:scale(0.92) translateY(10px);transition:transform .35s cubic-bezier(.4,0,.2,1);box-shadow:0 24px 64px rgba(0,0,0,0.5)}
.modal-overlay.show .modal{transform:scale(1) translateY(0)}
.modal-icon{font-size:40px;margin-bottom:10px}
.modal h3{font-size:18px;font-weight:700;margin-bottom:6px}
.modal p{font-size:13px;color:var(--text2);margin-bottom:20px;line-height:1.5}
.modal-count{color:var(--accent);font-weight:700}
.modal-buttons{display:flex;gap:10px}
.modal-btn{flex:1;padding:14px 8px;border:none;border-radius:16px;font-size:14px;font-weight:700;cursor:pointer;transition:all .2s ease;font-family:inherit}
.modal-btn:active{transform:scale(0.96)}
.btn-zip{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#0a0a1a}
.btn-zip:hover{box-shadow:0 0 24px rgba(110,231,183,0.3)}
.btn-separate{background:rgba(255,255,255,0.08);color:var(--text);border:1px solid var(--glass-border)}
.btn-separate:hover{background:rgba(255,255,255,0.12)}

/* ── Custom checkbox — fully suppress native rendering ── */
.file-checkbox{
  width:20px;height:20px;border-radius:6px;border:2px solid var(--glass-border);
  background-color:rgba(255,255,255,0.04);background-image:none;
  appearance:none;-webkit-appearance:none;-moz-appearance:none;
  cursor:pointer;flex-shrink:0;transition:all .2s;position:relative;
  margin:0;padding:0;
  /* Kill any text/glyph the browser might render inside the checkbox */
  color:transparent !important;font-size:0 !important;line-height:0 !important;
  text-indent:-9999px;overflow:hidden;
  -webkit-font-smoothing:none;
}
.file-checkbox::before,.file-checkbox::after{display:none !important;content:none !important}
.file-checkbox::-ms-check{display:none}
.file-checkbox:checked{
  background-color:transparent;
  border-color:transparent;
  /* Gradient fill + checkmark as a single SVG — no url(#id) refs for cross-browser safety */
  background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 20 20' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Crect width='20' height='20' rx='6' fill='%236ee7b7'/%3E%3Cpath d='M6 10l3 3 5-6' stroke='%230a0a1a' stroke-width='2.5' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
  background-repeat:no-repeat;background-position:center;background-size:100% 100%;
}
.file-checkbox:checked::before,.file-checkbox:checked::after{display:none !important;content:none !important}

.batch-toolbar{display:none;align-items:center;gap:10px;padding:12px 18px;margin:0 0 10px}
.batch-toolbar.show{display:flex}
.batch-info{flex:1;font-size:13px;font-weight:600;color:var(--text2)}
.batch-info strong{color:var(--accent)}
.batch-btn{padding:10px 16px;border:none;border-radius:14px;font-size:13px;font-weight:700;cursor:pointer;transition:all .2s;font-family:inherit;display:flex;align-items:center;gap:6px}
.batch-btn:active{transform:scale(0.96)}
.batch-btn.del{background:rgba(255,80,80,0.12);color:rgba(255,120,120,0.9);border:1px solid rgba(255,80,80,0.2)}
.batch-btn.del:hover{background:rgba(255,80,80,0.2)}
.batch-btn.dl{background:rgba(110,231,183,0.1);color:var(--accent);border:1px solid rgba(110,231,183,0.2)}
.batch-btn.dl:hover{background:rgba(110,231,183,0.18)}
.select-all-wrap{display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px;color:var(--text2);font-weight:600;padding:2px 0;user-select:none;-webkit-user-select:none}
.select-all-wrap:hover{color:var(--text)}
.confirm-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.6);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);z-index:950;display:flex;align-items:center;justify-content:center;padding:20px;opacity:0;pointer-events:none;transition:opacity .3s ease}
.confirm-overlay.show{opacity:1;pointer-events:auto}
.confirm-box{background:rgba(20,20,40,0.95);border:1px solid var(--glass-border);border-radius:24px;padding:28px 24px;max-width:360px;width:100%;text-align:center;transform:scale(0.92) translateY(10px);transition:transform .35s cubic-bezier(.4,0,.2,1);box-shadow:0 24px 64px rgba(0,0,0,0.5)}
.confirm-overlay.show .confirm-box{transform:scale(1) translateY(0)}
.confirm-icon{font-size:40px;margin-bottom:10px}
.confirm-box h3{font-size:18px;font-weight:700;margin-bottom:6px}
.confirm-box p{font-size:13px;color:var(--text2);margin-bottom:20px;line-height:1.5}
.confirm-box p strong{color:var(--text)}
.confirm-buttons{display:flex;gap:10px}
.confirm-btn{flex:1;padding:14px 8px;border:none;border-radius:16px;font-size:14px;font-weight:700;cursor:pointer;transition:all .2s ease;font-family:inherit}
.confirm-btn:active{transform:scale(0.96)}
.confirm-btn.cancel{background:rgba(255,255,255,0.08);color:var(--text);border:1px solid var(--glass-border)}
.confirm-btn.cancel:hover{background:rgba(255,255,255,0.12)}
.confirm-btn.danger{background:linear-gradient(135deg,#f87171,#ef4444);color:#fff}
.confirm-btn.danger:hover{box-shadow:0 0 24px rgba(248,113,113,0.3)}
.confirm-btn.action{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#0a0a1a}
.confirm-btn.action:hover{box-shadow:0 0 24px rgba(110,231,183,0.3)}
@media(min-width:600px){body{max-width:480px;margin:0 auto;padding:40px 20px 120px}.dropzone{padding:56px 20px}}
.fade-in{animation:fadeIn .5s ease both}
@keyframes fadeIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
.file-card{animation:slideIn .35s ease both}
@keyframes slideIn{from{opacity:0;transform:translateX(-16px)}to{opacity:1;transform:none}}
::-webkit-scrollbar{width:0;background:transparent}
</style>
</head>
<body>
<div class="orb orb-1"></div><div class="orb orb-2"></div><div class="orb orb-3"></div>

<div class="header glass fade-in">
  <span class="logo">\U0001f4a7</span>
  <h1>LiquidDrop</h1>
  <p>Tap to send \xb7 Tap to receive</p>
  <div class="device-badge"><span class="dot"></span> Connected on local network</div>
</div>

<div class="security-badge glass fade-in" style="animation-delay:.03s">
  <span class="lock">"""
        + lock_icon
        + """</span>
  <div class="security-info">
    <strong>"""
        + sec_label
        + """</strong>
    <span>"""
        + sec_detail
        + """</span>
  </div>
</div>

<div class="qr-section glass fade-in" id="qrSection" style="animation-delay:.05s">
  <h2>\U0001f4f1 Scan to open on another device</h2>
  <div class="qr-wrap"><img src="/"""
        + TOKEN
        + """/qr.png" alt="QR Code"></div>
  <div class="qr-url" id="urlCopy" title="Tap to copy">"""
        + BASE_URL
        + """</div>
  <div style="margin-top:16px;padding:12px 18px;background:rgba(129,140,248,0.08);border:1px solid rgba(129,140,248,0.2);border-radius:16px">
    <div style="font-size:12px;color:var(--text2);margin-bottom:6px;font-weight:600">\U0001f511 Or share this PIN code</div>
    <div style="font-size:32px;font-weight:800;letter-spacing:12px;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;font-family:'SF Mono',ui-monospace,monospace">"""
        + PIN_CODE
        + """</div>
    <div style="font-size:11px;color:var(--text2);margin-top:4px">Enter at <span style="font-family:'SF Mono',ui-monospace,monospace">"""
        + f"http://{LOCAL_IP}:{PORT}"
        + """</span></div>
  </div>
</div>

<div class="dropzone glass fade-in" id="dropzone" style="animation-delay:.1s">
  <span class="drop-icon">\u2b06\ufe0f</span>
  <h2>Send Files</h2>
  <p>Tap here or drag & drop anything</p>
  <input type="file" id="fileInput" multiple>
</div>

<div class="upload-bar glass" id="uploadBar">
  <div class="upload-info">
    <div style="display:flex;flex-direction:column;min-width:0;flex:1">
      <span class="upload-name" id="uploadName">file.zip</span>
      <span class="upload-speed" id="uploadSpeed"></span>
    </div>
    <span class="upload-pct" id="uploadPct">0%</span>
  </div>
  <div class="progress-track"><div class="progress-fill" id="progressFill"></div></div>
</div>

<div class="section-title" id="filesTitle" style="display:none">\U0001f4c1 Shared Files</div>
<div class="batch-toolbar glass" id="batchToolbar">
  <label class="select-all-wrap"><input type="checkbox" class="file-checkbox" id="selectAll"> Select All</label>
  <div class="batch-info"><strong id="selectedCount">0</strong> selected</div>
  <button class="batch-btn dl" id="batchDownloadBtn">\u2193 Download</button>
  <button class="batch-btn del" id="batchDeleteBtn">\u2715 Delete</button>
</div>
<div class="file-list" id="fileList"></div>
<div class="toast" id="toast"></div>

<div class="modal-overlay" id="zipModal">
  <div class="modal">
    <div class="modal-icon">\U0001f4e6</div>
    <h3>Zip them up?</h3>
    <p>You're sending <span class="modal-count" id="modalCount">5</span> files. Want to bundle them into one clean zip?</p>
    <div class="modal-buttons">
      <button class="modal-btn btn-zip" id="btnZip">Zip & Send</button>
      <button class="modal-btn btn-separate" id="btnSeparate">Send separately</button>
    </div>
  </div>
</div>

<div class="confirm-overlay" id="confirmOverlay">
  <div class="confirm-box">
    <div class="confirm-icon" id="confirmIcon">\u26a0\ufe0f</div>
    <h3 id="confirmTitle">Confirm</h3>
    <p id="confirmMessage">Are you sure?</p>
    <div class="confirm-buttons">
      <button class="confirm-btn cancel" id="confirmCancel">Cancel</button>
      <button class="confirm-btn danger" id="confirmOk">Confirm</button>
    </div>
  </div>
</div>

<script>
const $=s=>document.querySelector(s);
const TOKEN=location.pathname.split('/')[1];
const API='/'+TOKEN;

$('#urlCopy').addEventListener('click',()=>{
  navigator.clipboard.writeText($('#urlCopy').textContent)
    .then(()=>toast('\U0001f4cb URL copied!','success'))
    .catch(()=>{});
});

const dz=$('#dropzone'),fi=$('#fileInput');
dz.addEventListener('click',()=>fi.click());
fi.addEventListener('change',()=>{
  if(fi.files.length) handleFiles(Array.from(fi.files));
  fi.value='';
});
['dragenter','dragover'].forEach(e=>dz.addEventListener(e,ev=>{
  ev.preventDefault();dz.classList.add('drag-over');
}));
['dragleave','drop'].forEach(e=>dz.addEventListener(e,ev=>{
  ev.preventDefault();dz.classList.remove('drag-over');
}));
dz.addEventListener('drop',ev=>{
  if(ev.dataTransfer.files.length) handleFiles(Array.from(ev.dataTransfer.files));
});

const ZIP_THRESHOLD=3;
let pendingFiles=null;

function handleFiles(files){
  if(files.length>=ZIP_THRESHOLD && typeof JSZip!=='undefined'){
    pendingFiles=files;
    $('#modalCount').textContent=files.length;
    $('#zipModal').classList.add('show');
  } else {
    uploadFiles(files);
  }
}

$('#btnZip').addEventListener('click',async()=>{
  $('#zipModal').classList.remove('show');
  if(!pendingFiles) return;
  const f=pendingFiles; pendingFiles=null;
  await zipAndUpload(f);
});
$('#btnSeparate').addEventListener('click',()=>{
  $('#zipModal').classList.remove('show');
  if(!pendingFiles) return;
  const f=pendingFiles; pendingFiles=null;
  uploadFiles(f);
});
$('#zipModal').addEventListener('click',e=>{
  if(e.target===$('#zipModal')){$('#zipModal').classList.remove('show');pendingFiles=null;}
});

function fmtSpeed(bps){
  if(bps<1024) return bps.toFixed(0)+' B/s';
  if(bps<1048576) return(bps/1024).toFixed(0)+' KB/s';
  if(bps<1073741824) return(bps/1048576).toFixed(1)+' MB/s';
  return(bps/1073741824).toFixed(2)+' GB/s';
}

function sendXHR(file,displayName){
  const bar=$('#uploadBar'),pct=$('#uploadPct'),fill=$('#progressFill'),
        name=$('#uploadName'),spd=$('#uploadSpeed');
  name.textContent=displayName||file.name;
  pct.textContent='0%';fill.style.width='0%';spd.textContent='';
  bar.classList.add('active');
  let lastLoaded=0,lastTime=Date.now();
  return new Promise((res,rej)=>{
    const xhr=new XMLHttpRequest();
    xhr.open('POST',API+'/upload');
    xhr.upload.onprogress=e=>{
      if(!e.lengthComputable) return;
      const p=Math.round(e.loaded/e.total*100);
      pct.textContent=p+'%'; fill.style.width=p+'%';
      const now=Date.now(),dt=(now-lastTime)/1000;
      if(dt>=0.3){
        const speed=(e.loaded-lastLoaded)/dt;
        spd.textContent=fmtSpeed(speed);
        const rem=(e.total-e.loaded)/speed;
        if(rem>1) spd.textContent+=' \xb7 ~'+Math.ceil(rem)+'s left';
        lastLoaded=e.loaded; lastTime=now;
      }
    };
    xhr.onload=()=>xhr.status===200?res():rej(new Error('HTTP '+xhr.status));
    xhr.onerror=()=>rej(new Error('Network error'));
    const fd=new FormData();fd.append('file',file);xhr.send(fd);
  });
}

async function uploadFiles(files){
  for(const file of files){
    try{
      await sendXHR(file);
      toast('\u2713 '+file.name+' sent','success');
    } catch(e){
      toast('\u2717 '+file.name+' failed','error');
    }
    setTimeout(()=>$('#uploadBar').classList.remove('active'),800);
    loadFiles();
  }
}

async function zipAndUpload(files){
  const bar=$('#uploadBar'),pct=$('#uploadPct'),fill=$('#progressFill'),
        name=$('#uploadName'),spd=$('#uploadSpeed');
  name.textContent='\U0001f4e6 Zipping '+files.length+' files...';
  pct.textContent='0%';fill.style.width='0%';spd.textContent='Compressing...';
  bar.classList.add('active');
  try{
    const zip=new JSZip();
    for(let i=0;i<files.length;i++){
      const buf=await files[i].arrayBuffer();
      zip.file(files[i].name,buf);
      const p=Math.round((i+1)/files.length*40);
      pct.textContent=p+'%';fill.style.width=p+'%';
    }
    const blob=await zip.generateAsync(
      {type:'blob',compression:'DEFLATE',compressionOptions:{level:6}},
      meta=>{const p=40+Math.round(meta.percent*0.3);pct.textContent=p+'%';fill.style.width=p+'%';}
    );
    const ts=new Date().toISOString().slice(0,16).replace(/[:T]/g,'-');
    const zipName='LiquidDrop-'+ts+'.zip';
    const zipFile=new File([blob],zipName,{type:'application/zip'});
    spd.textContent='Uploading...';name.textContent=zipName;
    pct.textContent='70%';fill.style.width='70%';
    await sendXHR(zipFile,zipName);
    toast('\u2713 '+files.length+' files zipped & sent','success');
  } catch(e){
    toast('\u2717 Zip failed','error');console.error(e);
  }
  setTimeout(()=>bar.classList.remove('active'),800);
  loadFiles();
}

/* ===== File list with selection state preserved across refreshes ===== */
let lastHash='',selectedFiles=new Set();
let isBusy=false;  /* guard to prevent loadFiles from clobbering mid-action */

async function loadFiles(){
  if(isBusy) return;  /* skip refresh while batch action is in progress */
  try{
    const r=await fetch(API+'/files');
    if(!r.ok) return;
    const files=await r.json();
    const hash=JSON.stringify(files.map(f=>f.name+f.size+f.modified));
    if(hash===lastHash) return;
    lastHash=hash;

    const list=$('#fileList'),title=$('#filesTitle');

    /* Prune selected names that no longer exist on disk */
    const existingNames=new Set(files.map(f=>f.name));
    for(const n of [...selectedFiles]){
      if(!existingNames.has(n)) selectedFiles.delete(n);
    }

    if(!files.length){
      title.style.display='none';
      selectedFiles.clear();
      list.innerHTML='<div class="empty-state"><span>\U0001f30a</span>No files yet \u2014 drop something!</div>';
      updateBatchUI();
      return;
    }
    title.style.display='block';
    list.innerHTML=files.map((f,i)=>{
      const ext=f.name.split('.').pop().toLowerCase();
      const isImg=['jpg','jpeg','png','gif','webp','heic','svg','bmp','ico'].includes(ext);
      const isVid=['mp4','mov','avi','mkv','webm','m4v'].includes(ext);
      const isDoc=['pdf','doc','docx','txt','xls','xlsx','ppt','pptx','csv','md'].includes(ext);
      const ic=isImg?'img-type':isVid?'vid-type':isDoc?'doc-type':'';
      const em=isImg?'\U0001f5bc\ufe0f':isVid?'\U0001f3ac':isDoc?'\U0001f4c4':'\U0001f4e6';
      const checked=selectedFiles.has(f.name)?'checked':'';
      const dn=f.name.replace(/&/g,'&amp;').replace(/"/g,'&quot;');
      return '<div class="file-card glass" style="animation-delay:'+i*0.06+'s">'+
        '<input type="checkbox" class="file-checkbox file-select" data-name="'+dn+'" '+checked+'>'+
        '<div class="file-icon '+ic+'">'+em+'</div>'+
        '<div class="file-meta"><div class="file-name">'+esc(f.name)+'</div><div class="file-detail">'+fmtSize(f.size)+' \xb7 '+fmtTime(f.modified)+'</div></div>'+
        '<button class="file-delete" data-name="'+dn+'" title="Delete">\u2715</button>'+
        '<a href="'+API+'/download/'+encodeURIComponent(f.name)+'" download class="file-dl" title="Download">\u2193</a></div>';
    }).join('');
    updateBatchUI();
  } catch(e){/* network hiccup \u2014 silently retry next interval */}
}

/* ===== Event delegation for the file list ===== */
$('#fileList').addEventListener('click',e=>{
  /* Delete button */
  const del=e.target.closest('.file-delete');
  if(del){
    e.preventDefault();e.stopPropagation();
    const n=del.dataset.name;
    showConfirm('\U0001f5d1\ufe0f','Delete File','Delete <strong>'+esc(n)+'</strong>?<br>This cannot be undone.','Delete','danger',()=>{
      fetch(API+'/delete/'+encodeURIComponent(n),{method:'DELETE'})
        .then(()=>{toast('\U0001f5d1\ufe0f Deleted','success');selectedFiles.delete(n);lastHash='';loadFiles();})
        .catch(()=>toast('\u2717 Delete failed','error'));
    });
    return;
  }
  /* Checkbox toggle */
  const cb=e.target.closest('.file-select');
  if(cb){
    if(cb.checked) selectedFiles.add(cb.dataset.name);
    else selectedFiles.delete(cb.dataset.name);
    updateBatchUI();
    return;
  }
});

$('#selectAll').addEventListener('change',e=>{
  document.querySelectorAll('.file-select').forEach(cb=>{
    cb.checked=e.target.checked;
    if(e.target.checked) selectedFiles.add(cb.dataset.name);
    else selectedFiles.delete(cb.dataset.name);
  });
  updateBatchUI();
});

function updateBatchUI(){
  const boxes=document.querySelectorAll('.file-select');
  const count=selectedFiles.size;
  $('#selectedCount').textContent=count;

  if(boxes.length>0){
    $('#batchToolbar').classList.add('show');
  } else {
    $('#batchToolbar').classList.remove('show');
  }

  /* Sync the "Select All" checkbox — supports indeterminate state */
  const sa=$('#selectAll');
  sa.checked = boxes.length>0 && count===boxes.length;
  sa.indeterminate = count>0 && count<boxes.length;

  const hasSelection = count>0;
  ['#batchDeleteBtn','#batchDownloadBtn'].forEach(s=>{
    $(s).style.opacity=hasSelection?'1':'0.3';
    $(s).style.pointerEvents=hasSelection?'auto':'none';
  });
}

/* ===== Batch delete ===== */
$('#batchDeleteBtn').addEventListener('click',()=>{
  if(!selectedFiles.size) return;
  const c=selectedFiles.size;
  showConfirm(
    '\u26a0\ufe0f',
    'Delete '+c+' File'+(c>1?'s':''),
    'Are you sure you want to delete <strong>'+c+'</strong> file'+(c>1?'s':'')+'?<br>This cannot be undone.',
    'Delete All','danger',
    async()=>{
      isBusy=true;
      const names=[...selectedFiles];
      let ok=0;
      for(const n of names){
        try{
          await fetch(API+'/delete/'+encodeURIComponent(n),{method:'DELETE'});
          ok++;
        } catch(e){}
      }
      selectedFiles.clear();
      isBusy=false;
      lastHash='';
      loadFiles();
      toast('\U0001f5d1\ufe0f Deleted '+ok+' file'+(ok!==1?'s':''),'success');
    }
  );
});

/* ===== Batch download — intentionally preserves selection afterward ===== */
$('#batchDownloadBtn').addEventListener('click',()=>{
  if(!selectedFiles.size) return;
  const c=selectedFiles.size;
  showConfirm(
    '\U0001f4e5',
    'Download '+c+' File'+(c>1?'s':''),
    'Download <strong>'+c+'</strong> selected file'+(c>1?'s':'')+'?',
    'Download','action',
    async()=>{
      if(typeof JSZip!=='undefined'){
        const bar=$('#uploadBar'),pct=$('#uploadPct'),fill=$('#progressFill'),
              uname=$('#uploadName'),spd=$('#uploadSpeed');
        uname.textContent='\U0001f4e6 Zipping '+c+' files...';
        pct.textContent='0%';fill.style.width='0%';spd.textContent='Downloading...';
        bar.classList.add('active');
        isBusy=true;
        try{
          const zip=new JSZip();
          const names=[...selectedFiles];
          for(let i=0;i<names.length;i++){
            const resp=await fetch(API+'/download/'+encodeURIComponent(names[i]));
            if(!resp.ok) throw new Error('Failed to fetch '+names[i]);
            const blob=await resp.blob();
            zip.file(names[i],blob);
            const p=Math.round((i+1)/names.length*70);
            pct.textContent=p+'%';fill.style.width=p+'%';
          }
          spd.textContent='Compressing...';
          const blob=await zip.generateAsync(
            {type:'blob',compression:'DEFLATE',compressionOptions:{level:6}},
            meta=>{const p=70+Math.round(meta.percent*0.3);pct.textContent=p+'%';fill.style.width=p+'%';}
          );
          const ts=new Date().toISOString().slice(0,16).replace(/[:T]/g,'-');
          const a=document.createElement('a');
          a.href=URL.createObjectURL(blob);
          a.download='LiquidDrop-'+ts+'.zip';
          document.body.appendChild(a);a.click();a.remove();
          /* Revoke after delay so browser can start the download */
          setTimeout(()=>URL.revokeObjectURL(a.href),5000);
          toast('\u2713 Downloaded '+c+' files as zip','success');
        } catch(e){
          toast('\u2717 Download failed','error');console.error(e);
        }
        isBusy=false;
        setTimeout(()=>bar.classList.remove('active'),800);
        /* Selection is intentionally preserved so the user can still
           click Delete to remove the same batch after downloading. */
      } else {
        /* Fallback: trigger individual downloads */
        const names=[...selectedFiles];
        for(const n of names){
          const a=document.createElement('a');
          a.href=API+'/download/'+encodeURIComponent(n);
          a.download='';
          document.body.appendChild(a);a.click();a.remove();
          await new Promise(r=>setTimeout(r,300));
        }
        toast('\u2713 Downloaded '+c+' file'+(c>1?'s':''),'success');
      }
    }
  );
});

/* ===== Confirm dialog ===== */
let confirmCb=null;
function showConfirm(icon,title,msg,okText,okClass,cb){
  $('#confirmIcon').textContent=icon;
  $('#confirmTitle').textContent=title;
  $('#confirmMessage').innerHTML=msg;
  const ok=$('#confirmOk');
  ok.textContent=okText;
  ok.className='confirm-btn '+okClass;
  confirmCb=cb;
  $('#confirmOverlay').classList.add('show');
}
$('#confirmCancel').addEventListener('click',()=>{
  $('#confirmOverlay').classList.remove('show');confirmCb=null;
});
$('#confirmOk').addEventListener('click',()=>{
  $('#confirmOverlay').classList.remove('show');
  if(confirmCb){const fn=confirmCb;confirmCb=null;fn();}
});
$('#confirmOverlay').addEventListener('click',e=>{
  if(e.target===$('#confirmOverlay')){$('#confirmOverlay').classList.remove('show');confirmCb=null;}
});

/* ===== Utility ===== */
function fmtSize(b){
  if(b<1024) return b+' B';
  if(b<1048576) return(b/1024).toFixed(1)+' KB';
  if(b<1073741824) return(b/1048576).toFixed(1)+' MB';
  return(b/1073741824).toFixed(2)+' GB';
}
function fmtTime(t){
  const d=new Date(t*1000),diff=(Date.now()-d)/1000;
  if(diff<60) return 'Just now';
  if(diff<3600) return Math.floor(diff/60)+'m ago';
  if(diff<86400) return Math.floor(diff/3600)+'h ago';
  return d.toLocaleDateString();
}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML;}
function toast(m,t='success'){
  const e=$('#toast');e.textContent=m;
  e.className='toast '+t+' show';
  clearTimeout(e._t);
  e._t=setTimeout(()=>e.classList.remove('show'),2500);
}

loadFiles();
setInterval(loadFiles,3000);
</script>
</body>
</html>"""
    )


# ── PIN Entry Page ────────────────────────────────────────────────────────


def build_pin_page(error=False, locked=False):
    if locked:
        err_html = '<div style="color:#f472b6;font-size:13px;margin-top:12px;font-weight:600">Too many attempts. Try again in 60 seconds.</div>'
    elif error:
        err_html = '<div style="color:#f472b6;font-size:13px;margin-top:12px;font-weight:600">Wrong PIN. Try again.</div>'
    else:
        err_html = ""

    return (
        """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<title>LiquidDrop \u2014 Enter PIN</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0a0a1a;--glass:rgba(255,255,255,0.06);--glass-border:rgba(255,255,255,0.12);--accent:#6ee7b7;--accent2:#818cf8;--accent3:#f472b6;--text:#f0f0f5;--text2:rgba(255,255,255,0.55);--radius:24px;--safe-top:env(safe-area-inset-top,20px);--safe-bottom:env(safe-area-inset-bottom,20px)}
html{height:100%;-webkit-text-size-adjust:100%}
body{min-height:100%;font-family:-apple-system,BlinkMacSystemFont,'SF Pro Display','Segoe UI',sans-serif;background:var(--bg);color:var(--text);display:flex;align-items:center;justify-content:center;padding:20px;-webkit-font-smoothing:antialiased}
.orb{position:fixed;border-radius:50%;filter:blur(80px);opacity:.35;pointer-events:none;z-index:0}
.orb-1{width:340px;height:340px;background:radial-gradient(circle,#6ee7b7,transparent 70%);top:-80px;right:-60px;animation:f1 12s ease-in-out infinite}
.orb-2{width:400px;height:400px;background:radial-gradient(circle,#818cf8,transparent 70%);bottom:-100px;left:-80px;animation:f2 15s ease-in-out infinite}
@keyframes f1{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(-40px,30px) scale(1.1)}}
@keyframes f2{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(30px,-40px) scale(1.15)}}
.card{background:var(--glass);backdrop-filter:blur(40px) saturate(1.6);-webkit-backdrop-filter:blur(40px) saturate(1.6);border:1px solid var(--glass-border);border-radius:var(--radius);padding:40px 32px;max-width:380px;width:100%;text-align:center;position:relative;z-index:1;box-shadow:0 8px 32px rgba(0,0,0,0.3),inset 0 1px 0 rgba(255,255,255,0.08);animation:fadeIn .5s ease both}
.card::before{content:'';position:absolute;inset:0;border-radius:inherit;background:linear-gradient(135deg,rgba(255,255,255,0.08) 0%,transparent 50%);pointer-events:none}
@keyframes fadeIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
.logo{font-size:48px;margin-bottom:8px;display:block;filter:drop-shadow(0 0 20px rgba(110,231,183,0.4))}
h1{font-size:28px;font-weight:700;background:linear-gradient(135deg,var(--accent),var(--accent2),var(--accent3));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;letter-spacing:-0.5px;margin-bottom:6px}
.subtitle{color:var(--text2);font-size:14px;margin-bottom:28px}
.pin-row{display:flex;gap:12px;justify-content:center;margin-bottom:8px}
.pin-box{width:58px;height:68px;border:2px solid var(--glass-border);border-radius:16px;background:rgba(255,255,255,0.04);font-size:28px;font-weight:800;color:var(--text);text-align:center;font-family:'SF Mono',ui-monospace,monospace;outline:none;transition:all .2s ease;-webkit-appearance:none;caret-color:var(--accent)}
.pin-box:focus{border-color:var(--accent);background:rgba(110,231,183,0.06);box-shadow:0 0 20px rgba(110,231,183,0.15)}
.pin-box.error{border-color:var(--accent3);animation:shake .4s ease}
@keyframes shake{0%,100%{transform:translateX(0)}20%,60%{transform:translateX(-6px)}40%,80%{transform:translateX(6px)}}
.submit-btn{width:100%;padding:16px;border:none;border-radius:16px;font-size:16px;font-weight:700;cursor:pointer;background:linear-gradient(135deg,var(--accent),var(--accent2));color:#0a0a1a;margin-top:20px;transition:all .2s ease;font-family:inherit}
.submit-btn:hover{box-shadow:0 0 24px rgba(110,231,183,0.3);transform:translateY(-1px)}
.submit-btn:active{transform:scale(0.98)}
</style>
</head>
<body>
<div class="orb orb-1"></div><div class="orb orb-2"></div>
<div class="card">
  <span class="logo">\U0001f4a7</span>
  <h1>LiquidDrop</h1>
  <p class="subtitle">Enter the 4-digit PIN to connect</p>
  <form method="POST" action="/pin" id="pinForm">
    <div class="pin-row">
      <input class="pin-box"""
        + (" error" if error else "")
        + """" type="tel" maxlength="1" inputmode="numeric" pattern="[0-9]" name="d1" id="d1" autofocus autocomplete="off">
      <input class="pin-box"""
        + (" error" if error else "")
        + """" type="tel" maxlength="1" inputmode="numeric" pattern="[0-9]" name="d2" id="d2" autocomplete="off">
      <input class="pin-box"""
        + (" error" if error else "")
        + """" type="tel" maxlength="1" inputmode="numeric" pattern="[0-9]" name="d3" id="d3" autocomplete="off">
      <input class="pin-box"""
        + (" error" if error else "")
        + """" type="tel" maxlength="1" inputmode="numeric" pattern="[0-9]" name="d4" id="d4" autocomplete="off">
    </div>
    """
        + err_html
        + """
    <button type="submit" class="submit-btn">\U0001f4a7 Connect</button>
  </form>
</div>
<script>
const boxes=document.querySelectorAll('.pin-box');
boxes.forEach((b,i)=>{
  b.addEventListener('input',e=>{
    b.value=b.value.replace(/[^0-9]/g,'');
    if(b.value && i<3) boxes[i+1].focus();
    if([...boxes].every(x=>x.value)) document.getElementById('pinForm').submit();
  });
  b.addEventListener('keydown',e=>{
    if(e.key==='Backspace' && !b.value && i>0){boxes[i-1].focus();boxes[i-1].value='';}
  });
  b.addEventListener('paste',e=>{
    e.preventDefault();
    const p=(e.clipboardData||window.clipboardData).getData('text').replace(/[^0-9]/g,'');
    for(let j=0;j<4&&j<p.length;j++){boxes[j].value=p[j];}
    if(p.length>=4) document.getElementById('pinForm').submit();
  });
});
</script>
</body>
</html>"""
    )


# ── Server ───────────────────────────────────────────────────────────────


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "LiquidDrop/3.1"
    sys_version = ""  # Hide Python version from Server header

    def log_message(self, fmt, *args):
        ts = datetime.now().strftime("%H:%M:%S")
        msg = fmt % args
        if "200" in msg or "301" in msg or "302" in msg:
            print(f"  \033[90m{ts}\033[0m  \033[32m{msg}\033[0m")
        elif "404" in msg or "403" in msg:
            print(f"  \033[90m{ts}\033[0m  \033[33m{msg}\033[0m")
        else:
            print(f"  \033[90m{ts}\033[0m  {msg}")

    def _client_ip(self):
        return self.client_address[0]

    def _is_authed(self):
        """Check if the request path starts with the correct token."""
        parts = self.path.strip("/").split("/")
        return parts and parts[0] == TOKEN

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html, status=200):
        body = html.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path_stripped = self.path.strip("/")
        # Strip query strings for routing
        if "?" in path_stripped:
            path_stripped = path_stripped.split("?", 1)[0]
        parts = path_stripped.split("/", 2)

        # ── Unauthenticated routes (PIN entry page) ──
        if not parts[0] or parts[0] != TOKEN:
            if path_stripped == "" or path_stripped == "pin":
                locked = _check_pin_rate_limit(self._client_ip())
                self._send_html(build_pin_page(locked=locked))
            else:
                self.send_error(403, "Forbidden")
            return

        # ── Authenticated routes (token prefix valid) ──
        route = parts[1] if len(parts) > 1 else ""

        if route == "" or route == "index.html":
            self._send_html(build_html_page())

        elif route == "qr.png":
            if QR_PNG_BYTES:
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Length", str(len(QR_PNG_BYTES)))
                self.send_header("Cache-Control", "public, max-age=3600")
                self.end_headers()
                self.wfile.write(QR_PNG_BYTES)
            else:
                self.send_error(404)

        elif route == "files":
            files = []
            try:
                for f in sorted(
                    Path(UPLOAD_DIR).iterdir(),
                    key=lambda x: x.stat().st_mtime,
                    reverse=True,
                ):
                    if f.is_file() and not f.name.startswith("."):
                        s = f.stat()
                        files.append(
                            {
                                "name": f.name,
                                "size": s.st_size,
                                "modified": s.st_mtime,
                            }
                        )
            except OSError:
                pass
            self._send_json(files)

        elif route == "download" and len(parts) > 2:
            fname = urllib.parse.unquote(parts[2])
            fpath = _safe_path(fname)
            if fpath is None:
                self.send_error(404)
                return
            fsize = fpath.stat().st_size
            mime = mimetypes.guess_type(fname)[0] or "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(fsize))
            safe_fname = fname.replace('"', '\\"')
            self.send_header(
                "Content-Disposition", f'attachment; filename="{safe_fname}"'
            )
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            try:
                with open(fpath, "rb") as f:
                    while True:
                        chunk = f.read(CHUNK)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
            except (BrokenPipeError, ConnectionResetError):
                pass  # Client disconnected mid-download
        else:
            self.send_error(404)

    def do_POST(self):
        path_stripped = self.path.strip("/")

        # ── Unauthenticated POST: PIN verification ──
        if path_stripped == "pin":
            ip = self._client_ip()

            # Rate limit check
            if _check_pin_rate_limit(ip):
                self._send_html(build_pin_page(locked=True))
                print(f"  \033[31m\U0001f511 PIN locked out for {ip}\033[0m")
                return

            cl = int(self.headers.get("Content-Length", 0))
            if cl > 1024:  # Reject absurdly large POST bodies
                self.send_error(400)
                return
            body = self.rfile.read(cl).decode("utf-8", errors="replace")
            params = urllib.parse.parse_qs(body)
            # Only take first character per digit field to prevent injection
            entered = "".join(
                [params.get(f"d{i}", [""])[0][:1] for i in range(1, 5)]
            )

            if entered == PIN_CODE:
                _clear_pin_fails(ip)
                self.send_response(302)
                self.send_header("Location", f"/{TOKEN}/")
                self.end_headers()
                print(f"  \033[32m\U0001f511 PIN accepted \u2014 device connected\033[0m")
            else:
                _record_pin_fail(ip)
                locked = _check_pin_rate_limit(ip)
                self._send_html(build_pin_page(error=True, locked=locked))
                print(f"  \033[33m\U0001f511 Wrong PIN attempt from {ip}\033[0m")
            return

        # ── Authenticated POST routes ──
        if not self._is_authed():
            self.send_error(403, "Forbidden")
            return
        parts = self.path.strip("/").split("/")
        route = parts[1] if len(parts) > 1 else ""

        if route == "upload":
            ct = self.headers.get("Content-Type", "")
            if "multipart/form-data" not in ct:
                self.send_error(400)
                return
            try:
                boundary = ct.split("boundary=")[1]
            except IndexError:
                self.send_error(400)
                return
            if ";" in boundary:
                boundary = boundary.split(";")[0]
            boundary = boundary.strip().encode()
            cl = int(self.headers.get("Content-Length", 0))

            parser = StreamingMultipartParser(self.rfile, boundary, cl)
            count = 0
            for filename, dest, written in parser.parse():
                count += 1
                if written > 1048576:
                    sz = f"{written / (1024 * 1024):.1f} MB"
                elif written > 1024:
                    sz = f"{written / 1024:.1f} KB"
                else:
                    sz = f"{written} B"
                print(f"  \033[36m\u2b06  Received:\033[0m {dest.name} ({sz})")
            self._send_json({"status": "ok", "count": count})
        else:
            self.send_error(404)

    def do_DELETE(self):
        if not self._is_authed():
            self.send_error(403, "Forbidden")
            return
        parts = self.path.strip("/").split("/", 2)
        route = parts[1] if len(parts) > 1 else ""
        if route == "delete" and len(parts) > 2:
            fname = urllib.parse.unquote(parts[2])
            fpath = _safe_path(fname)
            if fpath is not None:
                try:
                    fpath.unlink()
                    print(f"  \033[31m\U0001f5d1  Deleted:\033[0m {fname}")
                except OSError as e:
                    print(f"  \033[31m\U0001f5d1  Delete failed:\033[0m {fname} ({e})")
            self._send_json({"status": "ok"})
        else:
            self.send_error(404)


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    request_queue_size = 32
    daemon_threads = True


def main():
    global BASE_URL, SECURE, TOKEN, PIN_CODE, PORT

    parser = argparse.ArgumentParser(
        description="\U0001f4a7 LiquidDrop \u2014 Local File Transfer"
    )
    parser.add_argument(
        "--secure",
        action="store_true",
        help="Enable HTTPS with self-signed TLS certificate",
    )
    parser.add_argument(
        "--port", type=int, default=PORT, help=f"Port number (default: {PORT})"
    )
    parser.add_argument(
        "--new-token",
        action="store_true",
        help="Generate a new token (invalidates old bookmarks)",
    )
    args = parser.parse_args()
    SECURE = args.secure
    port = args.port
    PORT = port

    if args.new_token:
        TOKEN = load_or_create_token(force_new=True)

    PIN_CODE = generate_pin(TOKEN)

    os.system("cls" if os.name == "nt" else "clear")
    print()

    if SECURE:
        print("  \033[1;96m\U0001f4a7 LiquidDrop v3.1 \u2014 Secure Mode (HTTPS)\033[0m")
        print("  \033[90m" + "\u2500" * 50 + "\033[0m\n")
        generate_certificate()
        BASE_URL = f"https://{LOCAL_IP}:{port}/{TOKEN}"
    else:
        print("  \033[1;96m\U0001f4a7 LiquidDrop v3.1\033[0m")
        print("  \033[90m" + "\u2500" * 50 + "\033[0m\n")
        BASE_URL = f"http://{LOCAL_IP}:{port}/{TOKEN}"

    print("  \033[33m\U0001f4f7 Generating QR code...\033[0m")
    qr = generate_qr()

    os.system("cls" if os.name == "nt" else "clear")
    print()
    if SECURE:
        print("  \033[1;96m\U0001f4a7 LiquidDrop v3.1 \u2014 Secure Mode (HTTPS)\033[0m")
    else:
        print("  \033[1;96m\U0001f4a7 LiquidDrop v3.1\033[0m")
    print("  \033[90m" + "\u2500" * 50 + "\033[0m\n")
    print_terminal_qr(qr)
    print()
    print("  \033[90m" + "\u2500" * 50 + "\033[0m")
    print(f"  \033[1;97m\U0001f4f1 Scan the QR or open:\033[0m")
    print(f"  \033[1;92m   {BASE_URL}\033[0m\n")

    protocol = "https" if SECURE else "http"
    pin_url = f"{protocol}://{LOCAL_IP}:{port}"
    print(f"  \033[1;97m\U0001f511 Or enter PIN:  \033[1;93m{PIN_CODE}\033[0m")
    print(f"  \033[90m   at {pin_url}\033[0m\n")

    if SECURE:
        print(f"  \033[1;32m\U0001f512 HTTPS Enabled \u2014 TLS Encrypted\033[0m")
        print(f"  \033[90m   Fingerprint: {CERT_FINGERPRINT[:48]}\033[0m")
        print(f"  \033[90m   {CERT_FINGERPRINT[48:]}\033[0m\n")
        print(f"  \033[33m   \u26a0  First visit: tap Advanced \u2192 Proceed\033[0m\n")
    else:
        print(f"  \033[1;32m\U0001f310 Protected by secret token + WiFi encryption\033[0m")
        print(
            f"  \033[90m   Add --secure for full HTTPS/TLS encryption\033[0m\n"
        )

    print(f"  \033[90mFiles: ~/LiquidDrop  \xb7  Streaming 256KB chunks\033[0m")
    print(
        f"  \033[90mURL is stable \u2014 bookmarks & home screen shortcuts persist\033[0m"
    )
    print(f"  \033[90mPress Ctrl+C to stop\033[0m")
    print("  \033[90m" + "\u2500" * 50 + "\033[0m\n")

    with ThreadedServer(("0.0.0.0", port), Handler) as httpd:
        if SECURE:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(CERT_FILE, KEY_FILE)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

        def shutdown(sig, frame):
            print("\n  \033[33m\u23f9  Shutting down...\033[0m\n")
            # shutdown() must be called from a different thread than serve_forever()
            threading.Thread(target=httpd.shutdown, daemon=True).start()

        signal.signal(signal.SIGINT, shutdown)
        threading.Timer(0.5, lambda: webbrowser.open(BASE_URL)).start()
        print(f"  \033[90m\U0001f310 Opening browser...\033[0m\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()