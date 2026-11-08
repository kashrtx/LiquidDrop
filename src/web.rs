use crate::config::{APP_VERSION, CHUNK, MAX_JSON_BODY};
use crate::events::{Kind, Stats};
use crate::util;
use bytes::Bytes;
use futures_util::StreamExt;
use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Response, StatusCode};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use serde_json::Value;
use std::convert::Infallible;
use std::io;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

pub type Body = UnsyncBoxBody<Bytes, io::Error>;
pub type Resp = Response<Body>;

pub fn full(data: impl Into<Bytes>) -> Body {
    Full::new(data.into())
        .map_err(|e: Infallible| -> io::Error { match e {} })
        .boxed_unsync()
}

pub fn empty() -> Body {
    Empty::<Bytes>::new()
        .map_err(|e: Infallible| -> io::Error { match e {} })
        .boxed_unsync()
}

pub fn set_header(resp: &mut Resp, name: &'static str, value: &str) {
    let v = HeaderValue::from_str(value).unwrap_or_else(|_| HeaderValue::from_static(""));
    resp.headers_mut().insert(HeaderName::from_static(name), v);
}

pub fn response(status: StatusCode, body: Body) -> Resp {
    let mut r = Response::new(body);
    *r.status_mut() = status;
    r
}

pub fn bytes(status: StatusCode, content_type: &str, data: impl Into<Bytes>, cache: &str) -> Resp {
    let data: Bytes = data.into();
    let mut r = response(status, full(data.clone()));
    set_header(&mut r, "content-type", content_type);
    set_header(&mut r, "content-length", &data.len().to_string());
    set_header(&mut r, "cache-control", cache);
    r
}

pub fn json(status: StatusCode, value: &Value) -> Resp {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    bytes(status, "application/json", body, "no-cache")
}

pub fn ok_json(value: &Value) -> Resp {
    json(StatusCode::OK, value)
}

pub fn json_error(status: StatusCode, msg: &str) -> Resp {
    json(status, &serde_json::json!({ "error": msg }))
}

pub fn html(status: StatusCode, page: String) -> Resp {
    bytes(status, "text/html; charset=utf-8", page, "no-cache")
}

/// Plain error page, like Python's send_error.
pub fn error_page(status: StatusCode, msg: &str) -> Resp {
    let reason = status.canonical_reason().unwrap_or("Error");
    let body = format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>{code} {reason}</title></head>\
         <body style=\"font-family:-apple-system,system-ui,sans-serif;background:#0a0a1a;color:#f0f0f5;padding:40px\">\
         <h1>{code} {reason}</h1><p>{msg}</p></body></html>",
        code = status.as_u16(),
        reason = reason,
        msg = util::html_escape(msg)
    );
    html(status, body)
}

pub fn not_found() -> Resp {
    error_page(StatusCode::NOT_FOUND, "Not found.")
}

pub fn redirect(location: &str) -> Resp {
    let mut r = response(StatusCode::FOUND, empty());
    set_header(&mut r, "location", location);
    set_header(&mut r, "content-length", "0");
    r
}

/// Headers added to every response.
pub fn finish(mut r: Resp) -> Resp {
    set_header(&mut r, "server", &format!("LiquidDrop/{}", APP_VERSION));
    set_header(&mut r, "x-content-type-options", "nosniff");
    set_header(&mut r, "referrer-policy", "no-referrer");
    r
}

/// Read a small request body (JSON, forms). Empty bodies become `{}`.
pub async fn read_json(body: Incoming) -> Result<Value, Resp> {
    let collected = Limited::new(body, MAX_JSON_BODY)
        .collect()
        .await
        .map_err(|_| json_error(StatusCode::PAYLOAD_TOO_LARGE, "Request body is too large."))?;
    let data = collected.to_bytes();
    if data.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(Value::Object(Default::default()));
    }
    serde_json::from_slice(&data)
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {}", e)))
}

pub async fn read_small(body: Incoming, max: usize) -> Option<Bytes> {
    Limited::new(body, max).collect().await.ok().map(|c| c.to_bytes())
}

// ── Files with Range support ───────────────────────────────────────────

pub enum Disposition<'a> {
    None,
    Inline(&'a str),
    Attachment(&'a str),
}

pub struct ServeOpts<'a> {
    pub content_type: &'a str,
    pub cache: &'a str,
    pub disposition: Disposition<'a>,
    /// Count bytes toward the live transfer-speed widget.
    pub count_download: bool,
    /// Render any HTML/SVG in an isolated origin if opened directly.
    pub sandbox: bool,
}

enum RangeReq {
    Full,
    Partial(u64, u64), // inclusive
    Unsatisfiable,
}

fn parse_range(value: &str, len: u64) -> RangeReq {
    let v = value.trim();
    let spec = match v.strip_prefix("bytes=") {
        Some(s) => s.trim(),
        None => return RangeReq::Full,
    };
    if spec.contains(',') {
        return RangeReq::Full; // multiple ranges: just send everything
    }
    let (a, b) = match spec.split_once('-') {
        Some(p) => p,
        None => return RangeReq::Full,
    };
    let (a, b) = (a.trim(), b.trim());
    if a.is_empty() {
        // suffix: last N bytes
        let n: u64 = match b.parse() {
            Ok(n) => n,
            Err(_) => return RangeReq::Full,
        };
        if n == 0 || len == 0 {
            return RangeReq::Unsatisfiable;
        }
        let start = len.saturating_sub(n);
        return RangeReq::Partial(start, len - 1);
    }
    let start: u64 = match a.parse() {
        Ok(n) => n,
        Err(_) => return RangeReq::Full,
    };
    if start >= len {
        return RangeReq::Unsatisfiable;
    }
    let end: u64 = if b.is_empty() {
        len - 1
    } else {
        match b.parse::<u64>() {
            Ok(n) => n.min(len - 1),
            Err(_) => return RangeReq::Full,
        }
    };
    if end < start {
        return RangeReq::Unsatisfiable;
    }
    RangeReq::Partial(start, end)
}

pub fn etag_for(len: u64, modified: std::time::SystemTime) -> String {
    format!("\"{:x}-{:x}\"", len, util::system_time_nanos(modified))
}

/// Serve a file from disk with Range, ETag and Last-Modified support.
pub async fn serve_path(
    req_headers: &HeaderMap,
    path: &Path,
    opts: ServeOpts<'_>,
    stats: Option<Arc<Stats>>,
) -> Resp {
    let meta = match tokio::fs::metadata(path).await {
        Ok(m) if m.is_file() => m,
        _ => return not_found(),
    };
    let len = meta.len();
    let modified = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
    let etag = etag_for(len, modified);

    if let Some(inm) = req_headers.get("if-none-match").and_then(|v| v.to_str().ok()) {
        if inm.split(',').any(|t| t.trim() == etag || t.trim() == "*") {
            let mut r = response(StatusCode::NOT_MODIFIED, empty());
            set_header(&mut r, "etag", &etag);
            set_header(&mut r, "cache-control", opts.cache);
            return r;
        }
    }

    let mut range = match req_headers.get("range").and_then(|v| v.to_str().ok()) {
        Some(v) => parse_range(v, len),
        None => RangeReq::Full,
    };
    if let Some(ir) = req_headers.get("if-range").and_then(|v| v.to_str().ok()) {
        if ir.trim() != etag {
            range = RangeReq::Full;
        }
    }

    let (status, start, count) = match range {
        RangeReq::Full => (StatusCode::OK, 0u64, len),
        RangeReq::Partial(s, e) => (StatusCode::PARTIAL_CONTENT, s, e - s + 1),
        RangeReq::Unsatisfiable => {
            let mut r = response(StatusCode::RANGE_NOT_SATISFIABLE, empty());
            set_header(&mut r, "content-range", &format!("bytes */{}", len));
            set_header(&mut r, "content-length", "0");
            return r;
        }
    };

    let mut file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(_) => return not_found(),
    };
    if start > 0 && file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, "Could not read file.");
    }
    let reader = file.take(count);
    let count_download = opts.count_download;
    let stream = ReaderStream::with_capacity(reader, CHUNK).map(move |chunk| {
        if let (Ok(data), Some(s)) = (&chunk, &stats) {
            if count_download {
                s.record(Kind::Download, data.len() as u64);
            }
        }
        chunk.map(Frame::data)
    });

    let mut r = response(status, StreamBody::new(stream).boxed_unsync());
    set_header(&mut r, "content-type", opts.content_type);
    set_header(&mut r, "content-length", &count.to_string());
    set_header(&mut r, "accept-ranges", "bytes");
    set_header(&mut r, "etag", &etag);
    set_header(&mut r, "last-modified", &util::http_date(util::system_time_secs(modified)));
    set_header(&mut r, "cache-control", opts.cache);
    if status == StatusCode::PARTIAL_CONTENT {
        set_header(
            &mut r,
            "content-range",
            &format!("bytes {}-{}/{}", start, start + count - 1, len),
        );
    }
    match opts.disposition {
        Disposition::None => {}
        Disposition::Inline(name) => {
            set_header(&mut r, "content-disposition", &util::content_disposition("inline", name))
        }
        Disposition::Attachment(name) => set_header(
            &mut r,
            "content-disposition",
            &util::content_disposition("attachment", name),
        ),
    }
    if opts.sandbox {
        set_header(&mut r, "content-security-policy", "sandbox");
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert!(matches!(parse_range("bytes=0-99", 1000), RangeReq::Partial(0, 99)));
        assert!(matches!(parse_range("bytes=900-", 1000), RangeReq::Partial(900, 999)));
        assert!(matches!(parse_range("bytes=-100", 1000), RangeReq::Partial(900, 999)));
        assert!(matches!(parse_range("bytes=0-5000", 1000), RangeReq::Partial(0, 999)));
        assert!(matches!(parse_range("bytes=1000-", 1000), RangeReq::Unsatisfiable));
        assert!(matches!(parse_range("bytes=0-1,5-6", 1000), RangeReq::Full));
        assert!(matches!(parse_range("items=0-1", 1000), RangeReq::Full));
    }
}
