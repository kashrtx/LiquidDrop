use serde_json::Value;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

// ── Time ────────────────────────────────────────────────────────────────

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn system_time_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn system_time_f64(t: SystemTime) -> f64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn system_time_nanos(t: SystemTime) -> u128 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}

/// Days since 1970-01-01 -> (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub struct Civil {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    pub weekday: u32, // 0 = Sunday
}

pub fn civil(secs: i64) -> Civil {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    Civil {
        year,
        month,
        day,
        hour: (rem / 3600) as u32,
        minute: ((rem % 3600) / 60) as u32,
        second: (rem % 60) as u32,
        weekday: (days + 4).rem_euclid(7) as u32,
    }
}

pub fn iso_utc(secs: u64) -> String {
    let c = civil(secs as i64);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        c.year, c.month, c.day, c.hour, c.minute, c.second
    )
}

pub fn utc_now_iso() -> String {
    iso_utc(now_secs())
}

pub fn http_date(secs: u64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let c = civil(secs as i64);
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        DAYS[(c.weekday % 7) as usize],
        c.day,
        MONTHS[((c.month.max(1) - 1) % 12) as usize],
        c.year,
        c.hour,
        c.minute,
        c.second
    )
}

/// (time, date) in MS-DOS format, UTC. Dates before 1980 clamp to 1980-01-01.
pub fn dos_datetime(secs: u64) -> (u16, u16) {
    let c = civil(secs as i64);
    if c.year < 1980 {
        return (0, (1 << 5) | 1);
    }
    let year = (c.year - 1980).min(127) as u16;
    let time = ((c.hour as u16) << 11) | ((c.minute as u16) << 5) | ((c.second as u16) / 2);
    let date = (year << 9) | ((c.month as u16) << 5) | (c.day as u16);
    (time, date)
}

pub fn filename_stamp(secs: u64) -> String {
    let c = civil(secs as i64);
    format!(
        "{:04}-{:02}-{:02}-{:02}-{:02}",
        c.year, c.month, c.day, c.hour, c.minute
    )
}

// ── Escaping ────────────────────────────────────────────────────────────

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decoding like Python's urllib.parse.unquote.
pub fn url_unquote(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Form decoding (application/x-www-form-urlencoded) for one value.
pub fn form_unquote(s: &str) -> String {
    url_unquote(&s.replace('+', " "))
}

/// Percent-encoding like Python's urllib.parse.quote(s, safe="/").
pub fn url_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// RFC 5987 encoding for `filename*=UTF-8''...`.
pub fn rfc5987(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let keep = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'!' | b'#' | b'$' | b'&' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
            );
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// A Content-Disposition value that is always valid ASCII, with the real
/// UTF-8 name in `filename*` (fixes downloads of non-Latin file names).
pub fn content_disposition(kind: &str, name: &str) -> String {
    let fallback: String = name
        .chars()
        .map(|c| {
            if c.is_ascii() && !c.is_ascii_control() && c != '"' && c != '\\' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!(
        "{}; filename=\"{}\"; filename*=UTF-8''{}",
        kind,
        fallback,
        rfc5987(name)
    )
}

pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

pub fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("");
        if form_unquote(k) == key {
            return Some(form_unquote(it.next().unwrap_or("")));
        }
    }
    None
}

// ── Randomness ──────────────────────────────────────────────────────────

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    if getrandom::getrandom(&mut v).is_err() {
        // Extremely unlikely; fall back to hashing time + address entropy.
        use sha2::{Digest, Sha256};
        let seed = format!("{:?}{:p}{}", SystemTime::now(), &v, std::process::id());
        let digest = Sha256::digest(seed.as_bytes());
        for (i, b) in v.iter_mut().enumerate() {
            *b = digest[i % digest.len()];
        }
    }
    v
}

pub fn random_hex(n: usize) -> String {
    random_bytes(n).iter().map(|b| format!("{:02x}", b)).collect()
}

/// Same shape as Python's secrets.token_urlsafe(n).
pub fn token_urlsafe(n: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let bytes = random_bytes(n);
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i] as u32;
        let b1 = if i + 1 < bytes.len() { bytes[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < bytes.len() { bytes[i + 2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        let remaining = bytes.len() - i;
        let chars = if remaining >= 3 { 4 } else if remaining == 2 { 3 } else { 2 };
        for k in 0..chars {
            let idx = ((triple >> (18 - 6 * k)) & 0x3F) as usize;
            out.push(ALPHABET[idx] as char);
        }
        i += 3;
    }
    out
}

/// Constant-time string comparison (for the URL token).
pub fn ct_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── JSON files ──────────────────────────────────────────────────────────

pub fn read_json_file(path: &Path) -> Option<Value> {
    let bytes = fs::read(path).ok()?;
    let body = bytes
        .strip_prefix(&b"\xEF\xBB\xBF"[..])
        .unwrap_or(&bytes[..]);
    serde_json::from_slice(body).ok()
}

fn tmp_sibling(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

/// Atomic write: temp file + rename.
pub fn write_json_file(path: &Path, value: &Value) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let body = serde_json::to_vec_pretty(value)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let tmp = tmp_sibling(path);
    fs::write(&tmp, body)?;
    fs::rename(&tmp, path)
}

pub fn write_bytes_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = tmp_sibling(path);
    fs::write(&tmp, data)?;
    fs::rename(&tmp, path)
}

// ── Python-compatible coercions (keeps extension behaviour identical) ──

fn py_number(n: &serde_json::Number) -> String {
    if n.is_f64() {
        let f = n.as_f64().unwrap_or(0.0);
        if f.fract() == 0.0 && f.abs() < 1e16 {
            format!("{:.1}", f)
        } else {
            format!("{}", f)
        }
    } else {
        n.to_string()
    }
}

/// Python's str(value) for JSON values.
pub fn py_str(v: &Value) -> String {
    match v {
        Value::Null => "None".to_string(),
        Value::Bool(b) => (if *b { "True" } else { "False" }).to_string(),
        Value::Number(n) => py_number(n),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Python's bool(value).
pub fn py_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Python's float(value), restricted to finite numbers.
pub fn py_float(v: &Value) -> Option<f64> {
    let f = match v {
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    }?;
    if f.is_finite() {
        Some(f)
    } else {
        None
    }
}

pub fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// `_plain_string` from the Python version.
pub fn plain_string(v: Option<&Value>, default: &str, max_len: usize) -> String {
    let raw = match v {
        None | Some(Value::Null) => default.to_string(),
        Some(val) => py_str(val),
    };
    let trimmed = raw.trim();
    let s = if trimmed.is_empty() { default.trim() } else { trimmed };
    truncate_chars(s, max_len)
}

pub fn json_number(f: f64) -> Value {
    serde_json::Number::from_f64(f)
        .map(Value::Number)
        .unwrap_or(Value::from(0))
}

// ── Formatting ──────────────────────────────────────────────────────────

pub fn fmt_size(n: u64) -> String {
    if n > 1_048_576 {
        format!("{:.1} MB", n as f64 / 1_048_576.0)
    } else if n > 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{} B", n)
    }
}

#[allow(dead_code)] // used by the tray (Windows/macOS)
pub fn fmt_speed(bps: u64) -> String {
    let b = bps as f64;
    if b < 1024.0 {
        format!("{} B/s", bps)
    } else if b < 1_048_576.0 {
        format!("{:.0} KB/s", b / 1024.0)
    } else if b < 1_073_741_824.0 {
        format!("{:.1} MB/s", b / 1_048_576.0)
    } else {
        format!("{:.2} GB/s", b / 1_073_741_824.0)
    }
}

pub fn extension_of(name: &str) -> String {
    match name.rfind('.') {
        Some(i) if i > 0 && i + 1 < name.len() => name[i + 1..].to_ascii_lowercase(),
        _ => String::new(),
    }
}

pub fn mime_for(name: &str) -> &'static str {
    match extension_of(name).as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" | "cjs" => "application/javascript; charset=utf-8",
        "json" | "map" => "application/json",
        "txt" | "text" | "log" | "md" | "markdown" | "ini" | "cfg" | "conf" | "env" | "toml"
        | "yaml" | "yml" | "py" | "rs" | "go" | "c" | "h" | "cpp" | "hpp" | "java" | "sh" => {
            "text/plain; charset=utf-8"
        }
        "csv" => "text/csv; charset=utf-8",
        "tsv" => "text/tab-separated-values; charset=utf-8",
        "xml" => "application/xml",
        "srt" => "application/x-subrip",
        "vtt" => "text/vtt",
        "png" => "image/png",
        "jpg" | "jpeg" | "jfif" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "bmp" => "image/bmp",
        "avif" => "image/avif",
        "heic" => "image/heic",
        "heif" => "image/heif",
        "tif" | "tiff" => "image/tiff",
        "mp4" | "m4v" => "video/mp4",
        "mov" => "video/quicktime",
        "webm" => "video/webm",
        "mkv" => "video/x-matroska",
        "avi" => "video/x-msvideo",
        "3gp" => "video/3gpp",
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        "aac" => "audio/aac",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "ogg" | "oga" => "audio/ogg",
        "opus" => "audio/opus",
        "weba" => "audio/webm",
        "aiff" | "aif" => "audio/aiff",
        "mid" | "midi" => "audio/midi",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "tar" => "application/x-tar",
        "7z" => "application/x-7z-compressed",
        "rar" => "application/vnd.rar",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "rtf" => "application/rtf",
        "epub" => "application/epub+zip",
        "apk" => "application/vnd.android.package-archive",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

// ── OS integration ──────────────────────────────────────────────────────

/// Put text on the system clipboard using the OS's built-in tool.
#[allow(dead_code)] // used by the tray (Windows/macOS)
pub fn copy_to_clipboard(text: &str) -> bool {
    use std::io::Write;
    #[cfg(target_os = "windows")]
    let mut cmd = {
        use std::os::windows::process::CommandExt;
        let mut c = Command::new("clip.exe");
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        c
    };
    #[cfg(target_os = "macos")]
    let mut cmd = Command::new("pbcopy");
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let mut cmd = {
        let mut c = Command::new("sh");
        c.args(["-c", "wl-copy 2>/dev/null || xclip -selection clipboard 2>/dev/null || xsel -b"]);
        c
    };
    let mut child = match cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(text.as_bytes());
    }
    child.wait().map(|s| s.success()).unwrap_or(false)
}

/// Open a URL or folder with the system default handler.
pub fn open_in_os(target: &str) -> bool {
    #[cfg(target_os = "windows")]
    let result = {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        Command::new("cmd")
            .args(["/C", "start", "", target])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    };
    #[cfg(target_os = "macos")]
    let result = Command::new("open")
        .arg(target)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let result = Command::new("xdg-open")
        .arg(target)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    result.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
    }

    #[test]
    fn quoting() {
        assert_eq!(url_quote("a b/ç"), "a%20b/%C3%A7");
        assert_eq!(url_unquote("a%20b/%C3%A7"), "a b/ç");
        assert_eq!(url_unquote("100%"), "100%");
        assert!(content_disposition("attachment", "照片.txt").is_ascii());
    }

    #[test]
    fn tokens() {
        assert_eq!(token_urlsafe(8).len(), 11);
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
    }

    #[test]
    fn python_strings() {
        assert_eq!(py_str(&serde_json::json!(1.0)), "1.0");
        assert_eq!(py_str(&serde_json::json!(true)), "True");
        assert_eq!(plain_string(Some(&serde_json::json!("  hi  ")), "x", 10), "hi");
        assert_eq!(plain_string(None, "dflt", 3), "dfl");
    }
}
