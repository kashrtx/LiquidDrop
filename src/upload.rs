//! Uploads.
//!
//! New protocol (used by the v5 UI): each file is sent as raw chunks to
//! `PUT /{token}/uploads/{id}?offset=N`. Data lands in `.partial/{id}.part`
//! and only becomes visible after `POST .../complete` renames it. A dropped
//! connection loses nothing: the client asks for the current offset and
//! continues, even mid-chunk. Several files upload in parallel.
//!
//! Legacy `POST /{token}/upload` (multipart) still works for old clients and
//! add-ons; it now also writes to a temp file first.

use crate::app::App;
use crate::config::UPLOAD_CHUNK_HINT;
use crate::events::{Kind, LiveEvent};
use crate::files;
use crate::web::{json, json_error, ok_json, Resp};
use crate::term::{CYAN, RESET, YELLOW};
use crate::util;
use bytes::{Buf, BytesMut};
use http::StatusCode;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncSeekExt, AsyncWriteExt, BufWriter};

const BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

pub fn valid_upload_id(id: &str) -> bool {
    (8..=80).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn part_path(app: &App, id: &str) -> PathBuf {
    app.paths.partial.join(format!("{}.part", id))
}

fn meta_path(app: &App, id: &str) -> PathBuf {
    app.paths.partial.join(format!("{}.json", id))
}

fn value_u64(v: Option<&Value>) -> Option<u64> {
    let v = v?;
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    v.as_f64().filter(|f| *f >= 0.0 && f.fract() == 0.0).map(|f| f as u64)
}

/// POST /{token}/uploads  {id, name, size}  -> {id, offset, size, chunk}
pub async fn start(app: &Arc<App>, body: Value) -> Resp {
    let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if !valid_upload_id(&id) {
        return json_error(StatusCode::BAD_REQUEST, "Invalid upload id.");
    }
    let size = match value_u64(body.get("size")) {
        Some(s) => s,
        None => return json_error(StatusCode::BAD_REQUEST, "Missing file size."),
    };
    let name = files::sanitize_filename(body.get("name").and_then(|v| v.as_str()).unwrap_or(""));
    let _ = tokio::fs::create_dir_all(&app.paths.partial).await;
    let part = part_path(app, &id);
    let meta = meta_path(app, &id);

    let lock = app.upload_lock(&id);
    let _guard = match tokio::time::timeout(Duration::from_secs(10), lock.lock_owned()).await {
        Ok(g) => g,
        Err(_) => return json_error(StatusCode::CONFLICT, "Upload is busy."),
    };

    if let Ok(mut m) = app.completed.lock() {
        m.remove(&id); // a new upload with this id starts fresh
    }
    let existing = util::read_json_file(&meta);
    let same = existing
        .as_ref()
        .and_then(|m| value_u64(m.get("size")))
        .map(|s| s == size)
        .unwrap_or(false);
    let mut offset = 0u64;
    if same {
        if let Ok(m) = tokio::fs::metadata(&part).await {
            offset = m.len();
        }
    }
    if !same || offset > size {
        offset = 0;
        let record = json!({"id": id, "name": name, "size": size, "created": util::now_secs()});
        if let Err(e) = util::write_json_file(&meta, &record) {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }
        if let Err(e) = tokio::fs::write(&part, b"").await {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }
    } else if tokio::fs::metadata(&part).await.is_err() {
        let _ = tokio::fs::write(&part, b"").await;
    }
    ok_json(&json!({"id": id, "offset": offset, "size": size, "chunk": UPLOAD_CHUNK_HINT}))
}

/// GET /{token}/uploads/{id} -> {offset, size}
pub async fn status(app: &Arc<App>, id: &str) -> Resp {
    if !valid_upload_id(id) {
        return json_error(StatusCode::BAD_REQUEST, "Invalid upload id.");
    }
    let meta = match util::read_json_file(&meta_path(app, id)) {
        Some(m) => m,
        None => return json_error(StatusCode::NOT_FOUND, "Unknown upload."),
    };
    let size = value_u64(meta.get("size")).unwrap_or(0);
    let offset = tokio::fs::metadata(part_path(app, id))
        .await
        .map(|m| m.len())
        .unwrap_or(0);
    ok_json(&json!({"id": id, "offset": offset, "size": size}))
}

/// PUT /{token}/uploads/{id}?offset=N  (raw bytes)
pub async fn put_chunk(app: &Arc<App>, id: &str, query: &str, body: Incoming) -> Resp {
    if !valid_upload_id(id) {
        return json_error(StatusCode::BAD_REQUEST, "Invalid upload id.");
    }
    let offset: u64 = match util::query_param(query, "offset").and_then(|v| v.parse().ok()) {
        Some(o) => o,
        None => return json_error(StatusCode::BAD_REQUEST, "Missing offset."),
    };
    let meta = match util::read_json_file(&meta_path(app, id)) {
        Some(m) => m,
        None => return json_error(StatusCode::NOT_FOUND, "Unknown upload."),
    };
    let size = value_u64(meta.get("size")).unwrap_or(0);
    let part = part_path(app, id);

    let lock = app.upload_lock(id);
    let _guard = match tokio::time::timeout(Duration::from_secs(15), lock.lock_owned()).await {
        Ok(g) => g,
        Err(_) => return json_error(StatusCode::CONFLICT, "Upload is busy."),
    };

    let mut file = match tokio::fs::OpenOptions::new().write(true).open(&part).await {
        Ok(f) => f,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "Unknown upload."),
    };
    let len = match file.metadata().await {
        Ok(m) => m.len(),
        Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    if offset > len {
        return json(
            StatusCode::CONFLICT,
            &json!({"error": "Offset mismatch.", "offset": len, "size": size}),
        );
    }
    if offset < len {
        if let Err(e) = file.set_len(offset).await {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }
    }
    if let Err(e) = file.seek(std::io::SeekFrom::Start(offset)).await {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
    }

    let mut writer = BufWriter::with_capacity(1 << 20, file);
    let mut body = body;
    let mut written: u64 = 0;
    let mut failure: Option<(StatusCode, String)> = None;
    loop {
        let next = match tokio::time::timeout(BODY_IDLE_TIMEOUT, body.frame()).await {
            Err(_) => {
                failure = Some((StatusCode::REQUEST_TIMEOUT, "Upload stalled.".to_string()));
                break;
            }
            Ok(None) => break,
            Ok(Some(Err(e))) => {
                failure = Some((StatusCode::BAD_REQUEST, e.to_string()));
                break;
            }
            Ok(Some(Ok(frame))) => frame,
        };
        let data = match next.into_data() {
            Ok(d) => d,
            Err(_) => continue,
        };
        if offset + written + data.len() as u64 > size {
            failure = Some((StatusCode::BAD_REQUEST, "More data than the declared file size.".to_string()));
            break;
        }
        if let Err(e) = writer.write_all(&data).await {
            failure = Some((StatusCode::INSUFFICIENT_STORAGE, e.to_string()));
            break;
        }
        written += data.len() as u64;
        app.stats.record(Kind::Upload, data.len() as u64);
    }
    // Whatever reached the disk is a valid prefix of the file, so keep it, but
    // report the size that is really on disk (a failed flush may have lost the
    // tail) so the phone resumes from the right place.
    let flushed = writer.flush().await;
    drop(writer);
    if let Err(e) = flushed {
        if failure.is_none() {
            failure = Some((StatusCode::INSUFFICIENT_STORAGE, format!("Could not save the file: {}", e)));
        }
    }
    let on_disk = tokio::fs::metadata(&part).await.map(|m| m.len()).unwrap_or(offset);
    let new_offset = on_disk.min(offset + written);
    if failure.is_none() && new_offset != offset + written {
        failure = Some((StatusCode::INSUFFICIENT_STORAGE, "Could not save the file.".to_string()));
    }
    if let Some((status, msg)) = &failure {
        let name = meta.get("name").and_then(|v| v.as_str()).unwrap_or(id);
        say!(
            "  {}⚠  Upload interrupted:{} {} at {} ({} {}) — the device will resume",
            YELLOW,
            RESET,
            name,
            util::fmt_size(new_offset),
            status.as_u16(),
            msg
        );
    }
    match failure {
        None => ok_json(&json!({"offset": new_offset, "size": size})),
        Some((status, msg)) => json(status, &json!({"error": msg, "offset": new_offset, "size": size})),
    }
}

/// POST /{token}/uploads/{id}/complete -> {name, size}
pub async fn complete(app: &Arc<App>, id: &str) -> Resp {
    if !valid_upload_id(id) {
        return json_error(StatusCode::BAD_REQUEST, "Invalid upload id.");
    }
    let meta_file = meta_path(app, id);
    let meta = match util::read_json_file(&meta_file) {
        Some(m) => m,
        None => {
            // Already completed (the phone retried because the reply got lost)?
            let done = app.completed.lock().ok().and_then(|m| m.get(id).cloned());
            return match done {
                Some((name, size, _)) => ok_json(&json!({"status": "ok", "name": name, "size": size})),
                None => json_error(StatusCode::NOT_FOUND, "Unknown upload."),
            };
        }
    };
    let size = value_u64(meta.get("size")).unwrap_or(0);
    let name = files::sanitize_filename(meta.get("name").and_then(|v| v.as_str()).unwrap_or(""));
    let part = part_path(app, id);

    let lock = app.upload_lock(id);
    let _guard = match tokio::time::timeout(Duration::from_secs(15), lock.lock_owned()).await {
        Ok(g) => g,
        Err(_) => return json_error(StatusCode::CONFLICT, "Upload is busy."),
    };
    let have = tokio::fs::metadata(&part).await.map(|m| m.len()).unwrap_or(0);
    if have != size {
        return json(
            StatusCode::CONFLICT,
            &json!({"error": "Upload is incomplete.", "offset": have, "size": size}),
        );
    }
    let root = app.paths.root.clone();
    let dest = match files::finalize(app, &part, &root, &name).await {
        Ok(d) => d,
        Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    let _ = tokio::fs::remove_file(&meta_file).await;
    app.forget_upload_lock(id);
    let final_name = files::file_name_of(&dest);
    if let Ok(mut m) = app.completed.lock() {
        m.insert(id.to_string(), (final_name.clone(), size, std::time::Instant::now()));
    }
    say!("  {}⬆  Received:{} {} ({})", CYAN, RESET, final_name, util::fmt_size(size));
    app.hub.send(LiveEvent::Files);
    ok_json(&json!({"status": "ok", "name": final_name, "size": size}))
}

/// DELETE /{token}/uploads/{id}
pub async fn cancel(app: &Arc<App>, id: &str) -> Resp {
    if !valid_upload_id(id) {
        return json_error(StatusCode::BAD_REQUEST, "Invalid upload id.");
    }
    let lock = app.upload_lock(id);
    let _guard = tokio::time::timeout(Duration::from_secs(5), lock.lock_owned()).await;
    let _ = tokio::fs::remove_file(part_path(app, id)).await;
    let _ = tokio::fs::remove_file(meta_path(app, id)).await;
    app.forget_upload_lock(id);
    ok_json(&json!({"status": "ok"}))
}

// ── Multipart (legacy /upload and extension assets) ────────────────────

pub fn boundary_from(content_type: &str) -> Option<Vec<u8>> {
    if !content_type.to_ascii_lowercase().contains("multipart/form-data") {
        return None;
    }
    let idx = content_type.find("boundary=")?;
    let raw = &content_type[idx + "boundary=".len()..];
    let raw = raw.split(';').next().unwrap_or("").trim().trim_matches('"');
    if raw.is_empty() || raw.len() > 200 {
        None
    } else {
        Some(raw.as_bytes().to_vec())
    }
}

fn header_filename(headers: &str) -> Option<String> {
    for line in headers.split("\r\n") {
        let lower = line.to_ascii_lowercase();
        if !lower.starts_with("content-disposition:") {
            continue;
        }
        if let Some(i) = lower.find("filename*=") {
            let v = &line[i + "filename*=".len()..];
            let v = v.split(';').next().unwrap_or("").trim();
            if let Some(pos) = v.find("''") {
                return Some(util::url_unquote(&v[pos + 2..]));
            }
        }
        if let Some(i) = lower.find("filename=\"") {
            let start = i + "filename=\"".len();
            let rest = &line[start..];
            let end = rest.find('"').unwrap_or(rest.len());
            return Some(rest[..end].replace("%22", "\""));
        }
        if let Some(i) = lower.find("filename=") {
            let v = &line[i + "filename=".len()..];
            return Some(v.split(';').next().unwrap_or("").trim().to_string());
        }
    }
    None
}

struct BodyReader {
    body: Incoming,
    buf: BytesMut,
    eof: bool,
    total: u64,
    max: Option<u64>,
    app: Arc<App>,
}

impl BodyReader {
    async fn fill(&mut self) -> Result<bool, String> {
        if self.eof {
            return Ok(false);
        }
        loop {
            let next = match tokio::time::timeout(BODY_IDLE_TIMEOUT, self.body.frame()).await {
                Err(_) => return Err("Upload stalled.".to_string()),
                Ok(None) => {
                    self.eof = true;
                    return Ok(false);
                }
                Ok(Some(Err(e))) => return Err(e.to_string()),
                Ok(Some(Ok(f))) => f,
            };
            if let Ok(data) = next.into_data() {
                if data.is_empty() {
                    continue;
                }
                self.total += data.len() as u64;
                if let Some(max) = self.max {
                    if self.total > max {
                        return Err("Upload is too large.".to_string());
                    }
                }
                self.app.stats.record(Kind::Upload, data.len() as u64);
                self.buf.extend_from_slice(&data);
                return Ok(true);
            }
        }
    }
}

pub struct Saved {
    pub name: String,
    pub size: u64,
}

/// Stream a multipart body into `target_dir`. Each file goes to a temp file
/// first; truncated uploads are discarded instead of left half-written.
pub async fn receive_multipart(
    app: &Arc<App>,
    body: Incoming,
    boundary: &[u8],
    target_dir: &Path,
    max_total: Option<u64>,
) -> Result<Vec<Saved>, String> {
    let mut delim = b"--".to_vec();
    delim.extend_from_slice(boundary);
    let mut sep = b"\r\n--".to_vec();
    sep.extend_from_slice(boundary);

    let mut r = BodyReader {
        body,
        buf: BytesMut::with_capacity(512 * 1024),
        eof: false,
        total: 0,
        max: max_total,
        app: app.clone(),
    };

    // Skip preamble up to and including the first delimiter.
    loop {
        if let Some(i) = memchr::memmem::find(&r.buf, &delim) {
            r.buf.advance(i + delim.len());
            break;
        }
        if r.buf.len() > delim.len() {
            let drop_n = r.buf.len() - delim.len();
            r.buf.advance(drop_n);
        }
        if !r.fill().await? {
            return Err("No multipart boundary found.".to_string());
        }
    }

    let _ = tokio::fs::create_dir_all(&app.paths.partial).await;
    let mut saved: Vec<Saved> = Vec::new();
    loop {
        while r.buf.len() < 2 {
            if !r.fill().await? {
                return Ok(saved);
            }
        }
        if r.buf.starts_with(b"--") {
            break; // closing delimiter
        }
        if r.buf.starts_with(b"\r\n") {
            r.buf.advance(2);
        }
        // Part headers
        let header_end = loop {
            if let Some(i) = memchr::memmem::find(&r.buf, b"\r\n\r\n") {
                break i;
            }
            if r.buf.len() > 16 * 1024 {
                return Err("Multipart headers are too large.".to_string());
            }
            if !r.fill().await? {
                return Err("Upload was cut off.".to_string());
            }
        };
        let headers = String::from_utf8_lossy(&r.buf[..header_end]).into_owned();
        r.buf.advance(header_end + 4);
        let filename = header_filename(&headers);

        let tmp = app
            .paths
            .partial
            .join(format!("mp-{}.part", util::random_hex(8)));
        let mut writer = match &filename {
            Some(_) => match tokio::fs::File::create(&tmp).await {
                Ok(f) => Some(BufWriter::with_capacity(1 << 20, f)),
                Err(e) => return Err(e.to_string()),
            },
            None => None,
        };
        let mut size = 0u64;
        let mut found = false;
        let mut failure: Option<String> = None;
        loop {
            if let Some(i) = memchr::memmem::find(&r.buf, &sep) {
                if let Err(e) = write_opt(&mut writer, &r.buf[..i]).await {
                    failure = Some(e);
                    break;
                }
                size += i as u64;
                r.buf.advance(i + sep.len());
                found = true;
                break;
            }
            let keep = sep.len();
            if r.buf.len() > keep {
                let n = r.buf.len() - keep;
                if let Err(e) = write_opt(&mut writer, &r.buf[..n]).await {
                    failure = Some(e);
                    break;
                }
                size += n as u64;
                r.buf.advance(n);
            }
            match r.fill().await {
                Ok(true) => {}
                Ok(false) => break,
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            }
        }
        if let Some(mut w) = writer.take() {
            // The buffer may hold the whole file: a failed flush means nothing was saved.
            if failure.is_none() {
                if let Err(e) = w.flush().await {
                    failure = Some(format!("Could not save the file: {}", e));
                }
            }
            drop(w);
            if failure.is_none() && !found {
                failure = Some("Upload was cut off.".to_string());
            }
            if let Some(e) = failure {
                let _ = tokio::fs::remove_file(&tmp).await;
                return Err(e);
            }
            let name = files::sanitize_filename(filename.as_deref().unwrap_or(""));
            match files::finalize(app, &tmp, target_dir, &name).await {
                Ok(dest) => saved.push(Saved {
                    name: files::file_name_of(&dest),
                    size,
                }),
                Err(e) => {
                    let _ = tokio::fs::remove_file(&tmp).await;
                    return Err(e.to_string());
                }
            }
        } else {
            if let Some(e) = failure {
                return Err(e);
            }
            if !found {
                return Err("Upload was cut off.".to_string());
            }
        }
    }
    Ok(saved)
}

async fn write_opt(writer: &mut Option<BufWriter<tokio::fs::File>>, data: &[u8]) -> Result<(), String> {
    match writer.as_mut() {
        Some(w) => w
            .write_all(data)
            .await
            .map_err(|e| format!("Could not save the file: {}", e)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids() {
        assert!(valid_upload_id("abcd1234"));
        assert!(!valid_upload_id("../../x"));
        assert!(!valid_upload_id("short"));
    }

    #[test]
    fn filenames() {
        let h = "Content-Disposition: form-data; name=\"file\"; filename=\"photo 1.jpg\"\r\nContent-Type: image/jpeg";
        assert_eq!(header_filename(h).as_deref(), Some("photo 1.jpg"));
        let h2 = "content-disposition: form-data; name=\"file\"; filename*=UTF-8''%E7%85%A7.txt";
        assert_eq!(header_filename(h2).as_deref(), Some("照.txt"));
        assert_eq!(
            boundary_from("multipart/form-data; boundary=----abc").as_deref(),
            Some(&b"----abc"[..])
        );
    }
}
