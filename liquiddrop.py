#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════╗
║          💧 LiquidDrop v3.2                  ║
║   Beautiful Local File Transfer              ║
║                                              ║
║   python3 liquiddrop.py              (HTTP)  ║
║   python3 liquiddrop.py --secure     (HTTPS) ║
║                                              ║
║   Scan the QR code or enter the PIN!         ║
╚══════════════════════════════════════════════╝
"""

import http.server, socketserver, os, sys, socket, json, secrets
import urllib.parse, mimetypes, shutil, signal, subprocess, io, atexit
import webbrowser, threading, ssl, hashlib, argparse, time
from pathlib import Path
from datetime import datetime, timedelta, timezone

APP_VERSION = "3.2"
PORT = 7777
UPLOAD_DIR = os.path.join(os.path.expanduser("~"), "LiquidDrop")
CERT_DIR = os.path.join(UPLOAD_DIR, ".certs")
TOKEN_FILE = os.path.join(UPLOAD_DIR, ".token")
INSTANCE_FILE = os.path.join(UPLOAD_DIR, ".instance.json")
CHUNK = 256 * 1024
SECURE = False
PIN_CODE = ""
HOST_VIEW_URL = ""
INSTANCE_OWNED = False
INSTANCE_STATE = {}

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


def get_host_ips():
    ips = {"127.0.0.1", "::1", LOCAL_IP}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ip:
                ips.add(ip.split("%", 1)[0])
    except socket.gaierror:
        pass
    return {ip for ip in ips if ip}


HOST_IPS = get_host_ips()


def is_host_client_ip(ip):
    if not ip:
        return False
    return ip.split("%", 1)[0] in HOST_IPS


def _pid_exists(pid):
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if os.name == "nt":
        try:
            import ctypes

            access = 0x1000  # PROCESS_QUERY_LIMITED_INFORMATION
            handle = ctypes.windll.kernel32.OpenProcess(access, False, pid)
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)
                return True
            return False
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def _read_instance_state():
    try:
        with open(INSTANCE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _write_instance_state(state):
    tmp = INSTANCE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f)
    os.replace(tmp, INSTANCE_FILE)


def build_instance_state(port, secure, base_url, host_url, status="starting"):
    return {
        "pid": os.getpid(),
        "port": port,
        "secure": secure,
        "token": TOKEN,
        "local_ip": LOCAL_IP,
        "base_url": base_url,
        "host_url": host_url,
        "status": status,
        "version": APP_VERSION,
        "started_at": int(time.time()),
    }


def claim_single_instance(state):
    global INSTANCE_OWNED, INSTANCE_STATE

    for _ in range(3):
        try:
            fd = os.open(INSTANCE_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            existing = _read_instance_state() or {}
            if _pid_exists(existing.get("pid")):
                return False, existing
            try:
                os.remove(INSTANCE_FILE)
            except OSError:
                time.sleep(0.1)
            continue

        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f)
        INSTANCE_OWNED = True
        INSTANCE_STATE = dict(state)
        atexit.register(release_instance)
        return True, INSTANCE_STATE

    return False, _read_instance_state() or {}


def update_instance_state(**updates):
    global INSTANCE_STATE
    if not INSTANCE_OWNED:
        return
    INSTANCE_STATE.update(updates)
    try:
        _write_instance_state(INSTANCE_STATE)
    except OSError:
        pass


def release_instance():
    global INSTANCE_OWNED, INSTANCE_STATE
    if not INSTANCE_OWNED:
        return
    current = _read_instance_state()
    if current and current.get("pid") not in (None, os.getpid()):
        return
    try:
        os.remove(INSTANCE_FILE)
    except OSError:
        pass
    INSTANCE_OWNED = False
    INSTANCE_STATE = {}

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
APP_ICON_SVG_BYTES = None
APP_ICON_PNG_BYTES = None
APP_ICON_ICO_BYTES = None


def _liquiddrop_icon_svg():
    return """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 180 180" fill="none">
<defs>
  <linearGradient id="bg" x1="18" y1="12" x2="162" y2="168" gradientUnits="userSpaceOnUse">
    <stop stop-color="#1b1d44"/>
    <stop offset="1" stop-color="#16283b"/>
  </linearGradient>
  <radialGradient id="glow" cx="0" cy="0" r="1" gradientUnits="userSpaceOnUse" gradientTransform="translate(70 48) rotate(43) scale(68 58)">
    <stop stop-color="#6EE7B7" stop-opacity=".42"/>
    <stop offset="1" stop-color="#6EE7B7" stop-opacity="0"/>
  </radialGradient>
  <linearGradient id="drop" x1="90" y1="28" x2="90" y2="138" gradientUnits="userSpaceOnUse">
    <stop stop-color="#9FE2FF"/>
    <stop offset=".44" stop-color="#68B9FF"/>
    <stop offset="1" stop-color="#6EE7B7"/>
  </linearGradient>
</defs>
<rect width="180" height="180" rx="42" fill="url(#bg)"/>
<rect x="1" y="1" width="178" height="178" rx="41" stroke="#FFFFFF" stroke-opacity=".12"/>
<circle cx="66" cy="46" r="44" fill="url(#glow)"/>
<path d="M90 26C72 50 56 72 56 98C56 123.1 71.7 142 90 142C108.3 142 124 123.1 124 98C124 72 108 50 90 26Z" fill="url(#drop)"/>
<path d="M77 65C81 53 89 41 95 34C86 43 74 59 71 73C68.6 84.2 74.4 89.8 80 91C74.5 85.8 73.5 76 77 65Z" fill="white" fill-opacity=".36"/>
</svg>""".encode("utf-8")


def generate_app_icons():
    global APP_ICON_SVG_BYTES, APP_ICON_PNG_BYTES, APP_ICON_ICO_BYTES
    APP_ICON_SVG_BYTES = _liquiddrop_icon_svg()
    try:
        pip_install("Pillow", "PIL")
        from PIL import Image, ImageDraw, ImageFilter

        size = 180
        bg = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(bg)
        top = (27, 29, 68, 255)
        bottom = (22, 40, 59, 255)
        for y in range(size):
            t = y / max(size - 1, 1)
            color = tuple(
                int(top[i] + (bottom[i] - top[i]) * t) for i in range(4)
            )
            draw.line((0, y, size, y), fill=color)

        card_mask = Image.new("L", (size, size), 0)
        ImageDraw.Draw(card_mask).rounded_rectangle(
            (0, 0, size - 1, size - 1), radius=42, fill=255
        )
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        img.paste(bg, (0, 0), card_mask)

        glow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        gd = ImageDraw.Draw(glow)
        gd.ellipse((20, 10, 118, 108), fill=(110, 231, 183, 92))
        gd.ellipse((56, 18, 136, 98), fill=(129, 140, 248, 58))
        glow = glow.filter(ImageFilter.GaussianBlur(18))
        img = Image.alpha_composite(img, glow)

        drop_mask = Image.new("L", (size, size), 0)
        dm = ImageDraw.Draw(drop_mask)
        dm.polygon([(90, 26), (56, 90), (124, 90)], fill=255)
        dm.ellipse((54, 72, 126, 144), fill=255)

        drop = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        dd = ImageDraw.Draw(drop)
        top_drop = (159, 226, 255, 255)
        bottom_drop = (110, 231, 183, 255)
        for y in range(size):
            t = y / max(size - 1, 1)
            color = tuple(
                int(top_drop[i] + (bottom_drop[i] - top_drop[i]) * t)
                for i in range(4)
            )
            dd.line((0, y, size, y), fill=color)
        drop.putalpha(drop_mask)
        img = Image.alpha_composite(img, drop)

        shine = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        sd = ImageDraw.Draw(shine)
        sd.ellipse((70, 46, 102, 88), fill=(255, 255, 255, 88))
        sd.ellipse((64, 56, 92, 112), fill=(255, 255, 255, 36))
        shine = shine.filter(ImageFilter.GaussianBlur(6))
        img = Image.alpha_composite(img, shine)

        outline = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        od = ImageDraw.Draw(outline)
        od.rounded_rectangle(
            (1, 1, size - 2, size - 2),
            radius=41,
            outline=(255, 255, 255, 26),
            width=1,
        )
        img = Image.alpha_composite(img, outline)

        png_buf = io.BytesIO()
        img.save(png_buf, format="PNG")
        APP_ICON_PNG_BYTES = png_buf.getvalue()

        ico_buf = io.BytesIO()
        img.save(ico_buf, format="ICO", sizes=[(64, 64), (32, 32), (16, 16)])
        APP_ICON_ICO_BYTES = ico_buf.getvalue()
    except Exception:
        APP_ICON_PNG_BYTES = None
        APP_ICON_ICO_BYTES = None


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


def build_html_page(is_host=False):
    protocol = "HTTPS" if SECURE else "HTTP"
    lock_icon = "🔒" if SECURE else "🌐"
    sec_label = "TLS Encrypted · HTTPS" if SECURE else "Local Network · HTTP"
    sec_detail = (
        f"SHA-256: {CERT_FINGERPRINT[:23]}…"
        if SECURE
        else "Secret token protected · WiFi encrypted (WPA)"
    )
    body_class = "host-view" if is_host else ""
    host_panel_html = (
        """<div class="host-panel glass fade-in app-host" style="animation-delay:.08s">
  <div class="host-panel-head">
    <div>
      <div class="host-eyebrow">Host Controls</div>
      <h2>This computer is running LiquidDrop</h2>
      <p id="hostStatusNote">Stop sharing when you're finished.</p>
    </div>
    <div class="host-status">Host Only</div>
  </div>
  <button class="stop-btn" id="stopServerBtn">⏹ Stop LiquidDrop</button>
</div>"""
        if is_host
        else ""
    )
    host_section_html = (
        """<div class="app-stack app-host-shell">"""
        + host_panel_html
        + """</div>"""
        if is_host
        else ""
    )

    return (
        """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="LiquidDrop">
<meta name="application-name" content="LiquidDrop">
<meta name="theme-color" content="#141935">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="alternate icon" href="/favicon.ico">
<link rel="shortcut icon" href="/favicon.ico">
<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
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
.app-shell{position:relative;z-index:1;display:flex;flex-direction:column;gap:16px}
.app-stack{display:flex;flex-direction:column;gap:16px}
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
.header{text-align:center;padding:24px 20px 20px}
.logo{font-size:42px;margin-bottom:4px;display:block;filter:drop-shadow(0 0 20px rgba(110,231,183,0.4))}
.header h1{font-size:28px;font-weight:700;background:linear-gradient(135deg,var(--accent),var(--accent2),var(--accent3));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;letter-spacing:-0.5px}
.header p{color:var(--text2);font-size:13px;margin-top:6px;font-weight:500}
.device-badge{display:inline-flex;align-items:center;gap:6px;background:rgba(110,231,183,0.1);border:1px solid rgba(110,231,183,0.2);border-radius:100px;padding:5px 14px;font-size:12px;color:var(--accent);margin-top:12px;font-weight:600}
.device-badge .dot{width:7px;height:7px;background:var(--accent);border-radius:50%;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.security-badge{display:flex;align-items:center;gap:10px;padding:14px 18px;font-size:12px}
.security-badge .lock{font-size:20px}
.security-info{flex:1;min-width:0}
.security-info strong{display:block;font-size:13px;color:var(--accent);margin-bottom:2px}
.security-info span{color:var(--text2);font-size:11px;word-break:break-all;font-family:'SF Mono',ui-monospace,monospace}
.host-panel{padding:18px}
.host-panel-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}
.host-eyebrow,.files-eyebrow{font-size:12px;font-weight:800;letter-spacing:1px;text-transform:uppercase;color:var(--accent)}
.host-panel h2{font-size:18px;font-weight:700;letter-spacing:-0.25px;margin-top:4px}
.host-panel p{font-size:12px;color:var(--text2);line-height:1.45;margin-top:6px}
.host-status,.files-status{flex-shrink:0;padding:8px 12px;border-radius:999px;border:1px solid rgba(110,231,183,0.2);background:rgba(110,231,183,0.08);color:var(--accent);font-size:11px;font-weight:700;letter-spacing:.7px;text-transform:uppercase}
.stop-btn{width:100%;margin-top:16px;padding:15px 18px;border:none;border-radius:18px;background:linear-gradient(135deg,#fb7185,#ef4444);color:#fff;font-size:15px;font-weight:800;cursor:pointer;transition:all .2s ease;font-family:inherit}
.stop-btn:hover{transform:translateY(-1px);box-shadow:0 0 24px rgba(239,68,68,0.35)}
.stop-btn:active{transform:scale(0.98)}
.stop-btn:disabled{opacity:.7;cursor:wait;transform:none;box-shadow:none}
.qr-section{padding:22px;text-align:center}
.qr-section h2{font-size:15px;font-weight:600;margin-bottom:14px;color:var(--text2)}
.qr-wrap{display:inline-block;padding:14px;background:#fff;border-radius:18px;box-shadow:0 4px 24px rgba(0,0,0,0.25)}
.qr-wrap img{display:block;width:180px;height:180px}
.qr-url{margin-top:14px;font-size:11px;color:var(--text2);word-break:break-all;font-family:'SF Mono',ui-monospace,monospace;background:rgba(255,255,255,0.04);padding:8px 14px;border-radius:12px;cursor:pointer;transition:background .2s}
.qr-url:hover{background:rgba(255,255,255,0.08)}
.dropzone{padding:38px 20px;text-align:center;cursor:pointer;transition:all .3s cubic-bezier(.4,0,.2,1);position:relative;overflow:hidden}
.dropzone:hover,.dropzone.drag-over{background:rgba(110,231,183,0.08);border-color:rgba(110,231,183,0.3);transform:scale(1.01)}
.dropzone.drag-over .drop-icon{transform:scale(1.15);filter:drop-shadow(0 0 30px rgba(110,231,183,0.6))}
.drop-icon{font-size:52px;display:block;margin-bottom:12px;transition:all .3s ease}
.dropzone h2{font-size:18px;font-weight:600;margin-bottom:6px}
.dropzone p{color:var(--text2);font-size:13px}
.dropzone input{display:none}
.upload-bar{max-height:0;padding:0 20px;opacity:0;transform:translateY(-10px);transition:max-height .35s ease,padding .35s ease,opacity .35s ease,transform .35s ease;pointer-events:none;overflow:hidden}
.upload-bar.active{max-height:120px;padding:16px 20px;opacity:1;transform:translateY(0);pointer-events:auto}
.upload-info{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.upload-name{font-size:13px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:55%}
.upload-speed{font-size:11px;color:var(--text2);font-variant-numeric:tabular-nums}
.upload-pct{font-size:13px;font-weight:700;color:var(--accent);font-variant-numeric:tabular-nums}
.progress-track{height:6px;border-radius:3px;background:rgba(255,255,255,0.06);overflow:hidden}
.progress-fill{height:100%;border-radius:3px;width:0%;background:linear-gradient(90deg,var(--accent),var(--accent2));transition:width .15s linear;box-shadow:0 0 16px rgba(110,231,183,0.3)}
.files-panel.glass{background:transparent;border:none;box-shadow:none;backdrop-filter:none;-webkit-backdrop-filter:none;padding:0}
.files-panel.glass::before{display:none}
.files-panel-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:0 4px 4px}
.files-heading{display:flex;align-items:center;gap:10px;min-width:0}
.file-list-wrap{min-height:72px}
.file-list{display:flex;flex-direction:column;gap:10px}
.file-card{padding:16px 18px;display:flex;align-items:center;gap:14px;cursor:default;transition:all .25s ease;text-decoration:none;color:inherit}
.file-card:active{transform:scale(0.985)}
.file-preview{width:54px;height:54px;border-radius:16px;display:flex;align-items:center;justify-content:center;overflow:hidden;flex-shrink:0;background:linear-gradient(135deg,rgba(110,231,183,0.15),rgba(129,140,248,0.18));border:1px solid rgba(255,255,255,0.08);position:relative}
.file-preview img,.file-preview video{display:block;width:100%;height:100%;object-fit:cover;border-radius:inherit;background:rgba(255,255,255,0.04)}
.file-preview.placeholder{font-size:22px;color:var(--text2)}
.file-preview.img-type{background:linear-gradient(135deg,rgba(244,114,182,0.2),rgba(251,146,60,0.15))}
.file-preview.vid-type{background:linear-gradient(135deg,rgba(129,140,248,0.2),rgba(244,114,182,0.15))}
.file-preview.vid-type::after{content:'▶';position:absolute;right:6px;bottom:6px;width:18px;height:18px;border-radius:999px;background:rgba(10,10,26,0.66);color:#fff;font-size:10px;display:flex;align-items:center;justify-content:center;pointer-events:none}
.file-preview.doc-type{background:linear-gradient(135deg,rgba(56,189,248,0.2),rgba(110,231,183,0.15))}
.file-preview.audio-type{background:linear-gradient(135deg,rgba(251,191,36,0.42),rgba(244,114,182,0.34));color:#fff;font-size:26px;text-shadow:0 2px 12px rgba(124,58,237,0.38);isolation:isolate}
.file-preview.audio-type::before{content:'';position:absolute;inset:8px;border-radius:14px;background:rgba(255,255,255,0.18);border:1px solid rgba(255,255,255,0.18);box-shadow:inset 0 1px 0 rgba(255,255,255,0.16);z-index:0}
.file-preview.audio-type span{position:relative;z-index:1;display:block;transform:translateY(1px)}
.file-preview.code-type{background:linear-gradient(135deg,rgba(96,165,250,0.22),rgba(129,140,248,0.16));font-size:16px;font-weight:800;font-family:'SF Mono',ui-monospace,monospace;letter-spacing:-0.4px}
.file-meta{flex:1;min-width:0}
.file-name{font-size:14px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.file-detail{font-size:12px;color:var(--text2);margin-top:2px}
.file-dl{font-size:15px;flex-shrink:0;transition:all .2s;padding:10px 12px;border-radius:14px;background:rgba(110,231,183,0.08);color:var(--accent);text-decoration:none;display:flex;align-items:center;justify-content:center;line-height:1}
.file-dl:hover{background:rgba(110,231,183,0.18);color:var(--accent)}
.file-delete{font-size:15px;flex-shrink:0;padding:10px 12px;cursor:pointer;transition:all .2s;border:none;background:rgba(255,80,80,0.08);color:rgba(255,100,100,0.8);border-radius:14px;display:flex;align-items:center;justify-content:center;line-height:1}
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

.batch-toolbar{display:none;flex-direction:column;align-items:stretch;gap:12px;padding:14px 16px;margin:0 0 10px;overflow:hidden}
.batch-toolbar.show{display:flex}
.batch-row{display:flex;align-items:center;gap:12px}
.batch-main{display:flex;align-items:center;gap:10px;min-width:0;flex:1}
.batch-actions{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.batch-info{font-size:13px;font-weight:600;color:var(--text2);white-space:nowrap}
.batch-info strong{color:var(--accent)}
.batch-btn{flex:1;padding:12px 16px;border:none;border-radius:16px;font-size:14px;font-weight:700;cursor:pointer;transition:all .2s;font-family:inherit;display:flex;align-items:center;justify-content:center;gap:6px}
.batch-btn:active{transform:scale(0.96)}
.batch-btn.del{background:rgba(255,80,80,0.12);color:rgba(255,120,120,0.9);border:1px solid rgba(255,80,80,0.2)}
.batch-btn.del:hover{background:rgba(255,80,80,0.2)}
.batch-btn.dl{background:rgba(110,231,183,0.1);color:var(--accent);border:1px solid rgba(110,231,183,0.2)}
.batch-btn.dl:hover{background:rgba(110,231,183,0.18)}
.select-all-wrap{display:flex;align-items:center;gap:10px;cursor:pointer;font-size:15px;color:var(--text);font-weight:700;padding:2px 0;user-select:none;-webkit-user-select:none;min-width:0;white-space:nowrap}
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
.shutdown-screen{position:fixed;inset:0;z-index:1200;display:flex;align-items:center;justify-content:center;padding:24px;background:radial-gradient(circle at top,rgba(110,231,183,0.12),transparent 38%),radial-gradient(circle at bottom,rgba(129,140,248,0.16),transparent 42%),rgba(8,8,22,0.94);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);opacity:0;pointer-events:none;transition:opacity .45s ease}
.shutdown-screen.show{opacity:1;pointer-events:auto}
.shutdown-card{max-width:520px;width:100%;padding:34px 30px 30px;text-align:center}
.shutdown-icon{font-size:54px;display:block;margin-bottom:10px;filter:drop-shadow(0 0 22px rgba(110,231,183,0.28))}
.shutdown-card h2{font-size:32px;font-weight:800;letter-spacing:-0.7px;margin-bottom:10px;background:linear-gradient(135deg,#f0fdf4,#93c5fd,#c084fc);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.shutdown-card p{font-size:15px;line-height:1.7;color:var(--text2);margin-bottom:12px}
.shutdown-note{display:inline-flex;align-items:center;gap:8px;padding:10px 14px;border-radius:999px;background:rgba(110,231,183,0.08);border:1px solid rgba(110,231,183,0.18);color:var(--accent);font-size:13px;font-weight:700;margin-top:6px}
@media(min-width:600px){body{padding:40px 20px 120px}.dropzone{padding:56px 20px}}
@media(min-width:980px){
  body{padding:24px 28px 32px}
  .app-shell{max-width:1360px;margin:0 auto;display:grid;grid-template-columns:minmax(0,1.38fr) minmax(360px,.84fr);gap:18px 28px;align-items:start}
  body.host-view .app-shell{
    grid-template-areas:
      "intro qr"
      "host qr"
      "upload upload"
      "files files";
  }
  body:not(.host-view) .app-shell{
    grid-template-areas:
      "intro qr"
      "upload upload"
      "files files";
  }
  .app-intro{grid-area:intro}
  .app-upload-shell{grid-area:upload}
  .app-host-shell{grid-area:host}
  .app-qr-shell{grid-area:qr}
  .app-files-shell{grid-area:files}
  .app-header{text-align:left;padding:28px 30px 26px;min-height:206px;display:flex;flex-direction:column;justify-content:center}
  .app-security,.app-host,.app-upload,.app-qr,.app-files{margin-bottom:0}
  .app-upload-shell{display:flex;flex-direction:column;gap:0}
  .app-drop{min-height:184px;display:flex;flex-direction:column;justify-content:center;padding:32px 30px}
  .app-upload-shell .upload-bar{margin-top:0}
  .app-upload-shell .upload-bar.active{margin-top:12px}
  .app-qr-shell{display:flex;align-self:stretch}
  .app-qr{position:relative;z-index:2;display:flex;flex-direction:column;justify-content:center;width:100%;height:100%}
  .app-qr .qr-wrap{display:flex;align-items:center;justify-content:center;align-self:center}
  .app-qr .qr-wrap img{margin:0 auto}
  .app-files{overflow:hidden}
  .files-panel.glass{
    background:var(--glass);backdrop-filter:blur(40px) saturate(1.6);-webkit-backdrop-filter:blur(40px) saturate(1.6);
    border:1px solid var(--glass-border);border-radius:var(--radius);position:relative;z-index:1;
    box-shadow:0 8px 32px rgba(0,0,0,0.3),inset 0 1px 0 rgba(255,255,255,0.08);
    padding:18px 18px 16px;display:flex;flex-direction:column;width:100%
  }
  .files-panel.glass::before{display:block;content:'';position:absolute;inset:0;border-radius:inherit;background:linear-gradient(135deg,rgba(255,255,255,0.08) 0%,transparent 50%);pointer-events:none}
  .files-panel-head{padding:0 8px 8px}
  .file-list-wrap{min-height:0;max-height:min(52vh,620px);overflow:auto;overscroll-behavior:contain;-webkit-overflow-scrolling:touch;padding-right:6px;scrollbar-gutter:stable}
  .file-list{height:auto;overflow:visible;padding-right:0}
  .batch-toolbar{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:16px;padding:12px 14px}
  .batch-toolbar.show{display:grid}
  .batch-row{min-width:0}
  .batch-main{gap:12px}
  .batch-actions{display:flex;gap:10px;min-width:0}
  .batch-btn{min-width:140px;padding:11px 14px;font-size:13px}
  .header h1{font-size:38px}
  .header p{font-size:15px}
  .device-badge{margin-top:14px}
  .qr-section{padding:28px}
  .qr-wrap img{width:210px;height:210px}
  .dropzone h2{font-size:24px}
  .dropzone p{font-size:15px}
  .host-panel h2{font-size:19px}
}
.fade-in{animation:fadeIn .5s ease both}
@keyframes fadeIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
.file-card{animation:slideIn .35s ease both}
@keyframes slideIn{from{opacity:0;transform:translateX(-16px)}to{opacity:1;transform:none}}
.file-list::-webkit-scrollbar,.file-list-wrap::-webkit-scrollbar{width:8px;background:transparent}
.file-list::-webkit-scrollbar-thumb,.file-list-wrap::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.14);border-radius:999px}
</style>
</head>
<body class=\""""
        + body_class
        + """\">
<div class="orb orb-1"></div><div class="orb orb-2"></div><div class="orb orb-3"></div>

<div class="app-shell">
<div class="app-stack app-intro">
<div class="header glass fade-in app-header">
  <span class="logo">\U0001f4a7</span>
  <h1>LiquidDrop</h1>
  <p>Tap to send \xb7 Tap to receive</p>
  <div class="device-badge"><span class="dot"></span> Connected on local network</div>
</div>

<div class="security-badge glass fade-in app-security" style="animation-delay:.03s">
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
</div>

<div class="app-stack app-qr-shell">
<div class="qr-section glass fade-in app-qr" id="qrSection" style="animation-delay:.05s">
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
</div>

"""
        + host_section_html
        + """

<div class="app-stack app-upload-shell">
<div class="dropzone glass fade-in app-drop" id="dropzone" style="animation-delay:.1s">
  <span class="drop-icon">\u2b06\ufe0f</span>
  <h2>Send Files</h2>
  <p>Tap here or drag & drop anything</p>
  <input type="file" id="fileInput" multiple>
</div>

<div class="upload-bar glass app-upload" id="uploadBar">
  <div class="upload-info">
    <div style="display:flex;flex-direction:column;min-width:0;flex:1">
      <span class="upload-name" id="uploadName">file.zip</span>
      <span class="upload-speed" id="uploadSpeed"></span>
    </div>
    <span class="upload-pct" id="uploadPct">0%</span>
  </div>
  <div class="progress-track"><div class="progress-fill" id="progressFill"></div></div>
</div>
</div>

<div class="app-stack app-files-shell">
<div class="files-panel glass fade-in app-files" style="animation-delay:.12s">
  <div class="files-panel-head">
    <div class="files-heading">
      <div class="files-eyebrow">\U0001f4c1 Shared Files</div>
    </div>
    <div class="files-status">Live</div>
  </div>
  <div class="batch-toolbar glass" id="batchToolbar">
    <div class="batch-row">
      <div class="batch-main">
        <label class="select-all-wrap"><input type="checkbox" class="file-checkbox" id="selectAll"> Select All</label>
        <div class="batch-info"><strong id="selectedCount">0</strong> selected</div>
      </div>
    </div>
    <div class="batch-actions">
      <button class="batch-btn dl" id="batchDownloadBtn">\u2193 Download</button>
      <button class="batch-btn del" id="batchDeleteBtn">\u2715 Delete</button>
    </div>
  </div>
  <div class="file-list-wrap">
    <div class="file-list" id="fileList"></div>
  </div>
</div>
</div>
</div>
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

<div class="shutdown-screen" id="shutdownScreen">
  <div class="shutdown-card glass">
    <span class="shutdown-icon">\U0001f49a</span>
    <h2>LiquidDrop has safely shut down</h2>
    <p>Everything is wrapped up. Thanks for sharing a little moment of convenience with someone.</p>
    <p>You can close this tab now. If you started LiquidDrop from the Windows launcher, the command window should close automatically too.</p>
    <div class="shutdown-note">\u2713 Session ended successfully</div>
  </div>
</div>

<script>
const $=s=>document.querySelector(s);
const TOKEN=location.pathname.split('/')[1];
const API='/'+TOKEN;
const IMAGE_EXTS=['jpg','jpeg','png','gif','webp','heic','svg','bmp','ico','avif'];
const VIDEO_EXTS=['mp4','mov','avi','mkv','webm','m4v'];
const AUDIO_EXTS=['mp3','wav','m4a','aac','flac','ogg','oga','opus','weba','aiff','wma','mid','midi'];
const CODE_EXTS=['py','pyw','js','mjs','cjs','ts','tsx','jsx','java','c','cc','cpp','cxx','h','hpp','cs','go','rs','php','rb','swift','kt','kts','dart','lua','pl','r','sh','bash','zsh','bat','cmd','ps1','sql','html','htm','css','scss','sass','less','json','xml','yaml','yml','toml','ini','cfg','conf','vue','svelte','ipynb'];
const DOC_EXTS=['pdf','doc','docx','txt','rtf','odt','pages','xls','xlsx','csv','tsv','ppt','pptx','key','numbers','md'];

$('#urlCopy').addEventListener('click',()=>{
  navigator.clipboard.writeText($('#urlCopy').textContent)
    .then(()=>toast('\U0001f4cb URL copied!','success'))
    .catch(()=>{});
});

function showShutdownScreen(){
  const screen=$('#shutdownScreen');
  if(!screen) return;
  document.body.style.overflow='hidden';
  $('#confirmOverlay').classList.remove('show');
  $('#zipModal').classList.remove('show');
  screen.classList.add('show');
}

const stopServerBtn=$('#stopServerBtn');
if(stopServerBtn){
  stopServerBtn.addEventListener('click',()=>{
    showConfirm(
      '\u23f9\ufe0f',
      'Stop LiquidDrop',
      'This will stop sharing and disconnect every device using this session.',
      'Stop LiquidDrop',
      'danger',
      async()=>{
        stopServerBtn.disabled=true;
        stopServerBtn.textContent='Shutting down...';
        try{
          const r=await fetch(API+'/shutdown',{method:'POST'});
          if(!r.ok) throw new Error('HTTP '+r.status);
          $('#hostStatusNote').textContent='LiquidDrop has safely shut down.';
          showShutdownScreen();
        } catch(e){
          stopServerBtn.disabled=false;
          stopServerBtn.textContent='\u23f9 Stop LiquidDrop';
          toast('\u2717 Shutdown failed','error');
        }
      }
    );
  });
}

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

function getFileKind(name){
  const ext=name.includes('.') ? name.split('.').pop().toLowerCase() : '';
  if(IMAGE_EXTS.includes(ext)) return 'image';
  if(VIDEO_EXTS.includes(ext)) return 'video';
  if(AUDIO_EXTS.includes(ext)) return 'audio';
  if(CODE_EXTS.includes(ext)) return 'code';
  if(DOC_EXTS.includes(ext)) return 'document';
  return 'other';
}

function filePreviewMarkup(file){
  const kind=getFileKind(file.name);
  const src=API+'/preview/'+encodeURIComponent(file.name);
  if(kind==='image'){
    return '<div class="file-preview img-type"><img src="'+src+'" alt=""></div>';
  }
  if(kind==='video'){
    return '<div class="file-preview vid-type"><video muted playsinline preload="metadata" data-preview-video src="'+src+'"></video></div>';
  }
  if(kind==='audio'){
    return '<div class="file-preview placeholder audio-type"><span>\U0001f3b5</span></div>';
  }
  if(kind==='code'){
    return '<div class="file-preview placeholder code-type">&lt;/&gt;</div>';
  }
  if(kind==='document'){
    return '<div class="file-preview placeholder doc-type">\U0001f4c4</div>';
  }
  return '<div class="file-preview placeholder">\U0001f4e6</div>';
}

function hydratePreviewMedia(){
  document.querySelectorAll('video[data-preview-video]:not([data-hydrated])').forEach(v=>{
    v.dataset.hydrated='1';
    v.addEventListener('loadedmetadata',()=>{
      try{
        const target=v.duration && Number.isFinite(v.duration) ? Math.min(0.15,v.duration/2) : 0;
        if(target>0) v.currentTime=target;
      } catch(_){}
    },{once:true});
    v.addEventListener('seeked',()=>v.pause(),{once:true});
  });
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

    const list=$('#fileList');

    /* Prune selected names that no longer exist on disk */
    const existingNames=new Set(files.map(f=>f.name));
    for(const n of [...selectedFiles]){
      if(!existingNames.has(n)) selectedFiles.delete(n);
    }

    if(!files.length){
      selectedFiles.clear();
      list.innerHTML='<div class="empty-state"><span>\U0001f30a</span>No files yet \u2014 drop something!</div>';
      updateBatchUI();
      return;
    }
    list.innerHTML=files.map((f,i)=>{
      const checked=selectedFiles.has(f.name)?'checked':'';
      const dn=f.name.replace(/&/g,'&amp;').replace(/"/g,'&quot;');
      return '<div class="file-card glass" style="animation-delay:'+i*0.06+'s">'+
        '<input type="checkbox" class="file-checkbox file-select" data-name="'+dn+'" '+checked+'>'+
        filePreviewMarkup(f)+
        '<div class="file-meta"><div class="file-name">'+esc(f.name)+'</div><div class="file-detail">'+fmtSize(f.size)+' \xb7 '+fmtTime(f.modified)+'</div></div>'+
        '<button class="file-delete" data-name="'+dn+'" title="Delete">\u2715</button>'+
        '<a href="'+API+'/download/'+encodeURIComponent(f.name)+'" download class="file-dl" title="Download">\u2193</a></div>';
    }).join('');
    hydratePreviewMedia();
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
<meta name="apple-mobile-web-app-title" content="LiquidDrop">
<meta name="application-name" content="LiquidDrop">
<meta name="theme-color" content="#141935">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="alternate icon" href="/favicon.ico">
<link rel="shortcut icon" href="/favicon.ico">
<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
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
    server_version = f"LiquidDrop/{APP_VERSION}"
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

    def _is_host_client(self):
        return is_host_client_ip(self._client_ip())

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

    def _send_bytes(self, body, content_type, status=200, cache="public, max-age=3600"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path_stripped = self.path.strip("/")
        # Strip query strings for routing
        if "?" in path_stripped:
            path_stripped = path_stripped.split("?", 1)[0]
        parts = path_stripped.split("/", 2)
        if path_stripped == "favicon.svg":
            if APP_ICON_SVG_BYTES:
                self._send_bytes(
                    APP_ICON_SVG_BYTES,
                    "image/svg+xml",
                    cache="public, max-age=86400",
                )
            else:
                self.send_error(404)
            return
        elif path_stripped == "favicon.ico":
            if APP_ICON_ICO_BYTES:
                self._send_bytes(
                    APP_ICON_ICO_BYTES,
                    "image/x-icon",
                    cache="public, max-age=86400",
                )
            elif APP_ICON_PNG_BYTES:
                self._send_bytes(
                    APP_ICON_PNG_BYTES,
                    "image/png",
                    cache="public, max-age=86400",
                )
            else:
                self.send_error(404)
            return
        elif path_stripped == "apple-touch-icon.png":
            if APP_ICON_PNG_BYTES:
                self._send_bytes(
                    APP_ICON_PNG_BYTES,
                    "image/png",
                    cache="public, max-age=86400",
                )
            else:
                self.send_error(404)
            return

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
            self._send_html(build_html_page(is_host=self._is_host_client()))

        elif route == "qr.png":
            if QR_PNG_BYTES:
                self._send_bytes(QR_PNG_BYTES, "image/png")
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

        elif route == "preview" and len(parts) > 2:
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
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Disposition", 'inline; filename="preview"')
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
                pass

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
        elif route == "shutdown":
            if not self._is_host_client():
                self.send_error(403, "Host only")
                return
            self._send_json({"status": "shutting_down"})
            self.server.initiate_shutdown(
                "  \033[33m⏹  Shutdown requested from the host web app\033[0m"
            )
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
    _shutdown_started = False

    def initiate_shutdown(self, message=None):
        if self._shutdown_started:
            return
        self._shutdown_started = True
        update_instance_state(status="stopping")
        if message:
            print(message)
        threading.Timer(0.2, self.shutdown).start()


def main():
    global BASE_URL, SECURE, TOKEN, PIN_CODE, PORT, HOST_VIEW_URL

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
    protocol = "https" if SECURE else "http"
    BASE_URL = f"{protocol}://{LOCAL_IP}:{port}/{TOKEN}"
    HOST_VIEW_URL = f"{protocol}://127.0.0.1:{port}/{TOKEN}"

    claimed, existing = claim_single_instance(
        build_instance_state(port, SECURE, BASE_URL, HOST_VIEW_URL)
    )
    if not claimed:
        running_url = (
            existing.get("host_url")
            or existing.get("base_url")
            or HOST_VIEW_URL
        )
        print()
        print(
            "  \033[33m\u26a0 LiquidDrop is already running. Opening the existing host view...\033[0m"
        )
        if args.new_token:
            print(
                "  \033[90mStop the current session before generating a new token.\033[0m"
            )
        print(f"  \033[90m{running_url}\033[0m\n")
        threading.Timer(0.2, lambda: webbrowser.open(running_url)).start()
        return

    if args.new_token:
        TOKEN = load_or_create_token(force_new=True)

    PIN_CODE = generate_pin(TOKEN)
    BASE_URL = f"{protocol}://{LOCAL_IP}:{port}/{TOKEN}"
    HOST_VIEW_URL = f"{protocol}://127.0.0.1:{port}/{TOKEN}"
    update_instance_state(
        token=TOKEN,
        base_url=BASE_URL,
        host_url=HOST_VIEW_URL,
        status="starting",
    )

    try:
        os.system("cls" if os.name == "nt" else "clear")
        print()

        if SECURE:
            print(
                f"  \033[1;96m\U0001f4a7 LiquidDrop v{APP_VERSION} \u2014 Secure Mode (HTTPS)\033[0m"
            )
            print("  \033[90m" + "\u2500" * 50 + "\033[0m\n")
            generate_certificate()
        else:
            print(f"  \033[1;96m\U0001f4a7 LiquidDrop v{APP_VERSION}\033[0m")
            print("  \033[90m" + "\u2500" * 50 + "\033[0m\n")

        print("  \033[33m\U0001f4a7 Preparing app icon...\033[0m")
        generate_app_icons()
        print("  \033[33m\U0001f4f7 Generating QR code...\033[0m")
        qr = generate_qr()

        os.system("cls" if os.name == "nt" else "clear")
        print()
        if SECURE:
            print(
                f"  \033[1;96m\U0001f4a7 LiquidDrop v{APP_VERSION} \u2014 Secure Mode (HTTPS)\033[0m"
            )
        else:
            print(f"  \033[1;96m\U0001f4a7 LiquidDrop v{APP_VERSION}\033[0m")
        print("  \033[90m" + "\u2500" * 50 + "\033[0m\n")
        print_terminal_qr(qr)
        print()
        print("  \033[90m" + "\u2500" * 50 + "\033[0m")
        print(f"  \033[1;97m\U0001f4f1 Scan the QR or open:\033[0m")
        print(f"  \033[1;92m   {BASE_URL}\033[0m\n")

        pin_url = f"{protocol}://{LOCAL_IP}:{port}"
        print(f"  \033[1;97m\U0001f511 Or enter PIN:  \033[1;93m{PIN_CODE}\033[0m")
        print(f"  \033[90m   at {pin_url}\033[0m\n")

        if SECURE:
            print(f"  \033[1;32m\U0001f512 HTTPS Enabled \u2014 TLS Encrypted\033[0m")
            print(f"  \033[90m   Fingerprint: {CERT_FINGERPRINT[:48]}\033[0m")
            print(f"  \033[90m   {CERT_FINGERPRINT[48:]}\033[0m\n")
            print(f"  \033[33m   \u26a0  First visit: tap Advanced \u2192 Proceed\033[0m\n")
        else:
            print(
                f"  \033[1;32m\U0001f310 Protected by secret token + WiFi encryption\033[0m"
            )
            print(
                f"  \033[90m   Add --secure for full HTTPS/TLS encryption\033[0m\n"
            )

        print(f"  \033[90mFiles: ~/LiquidDrop  \xb7  Streaming 256KB chunks\033[0m")
        print(
            "  \033[90mThe host browser includes a clear stop button for ending the session.\033[0m"
        )
        print(
            f"  \033[90mURL is stable \u2014 bookmarks & home screen shortcuts persist\033[0m"
        )
        print("  \033[90m" + "\u2500" * 50 + "\033[0m\n")

        with ThreadedServer(("0.0.0.0", port), Handler) as httpd:
            if SECURE:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(CERT_FILE, KEY_FILE)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

            def shutdown(sig, frame):
                print("\n  \033[33m\u23f9  Shutting down...\033[0m\n")
                httpd.initiate_shutdown()

            signal.signal(signal.SIGINT, shutdown)
            threading.Timer(0.5, lambda: webbrowser.open(HOST_VIEW_URL)).start()
            print(f"  \033[90m\U0001f310 Opening browser...\033[0m\n")
            update_instance_state(status="running")
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                pass
    finally:
        release_instance()


if __name__ == "__main__":
    main()
