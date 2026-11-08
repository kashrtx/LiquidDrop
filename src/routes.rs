//! URL layout is unchanged from v4 (`/{token}/...`), so bookmarks, home-screen
//! shortcuts and add-ons keep working. New endpoints are additive.

use crate::app::App;
use crate::assets;
use crate::config::{CHUNK, MAX_DOCUMENT_PREVIEW, MAX_EXTENSION_ASSET};
use crate::events::{self, Kind, LiveEvent};
use crate::extensions::{self, AssetLoc};
use crate::files;
use crate::net;
use crate::pages;
use crate::preview;
use crate::term::{CYAN, GREEN, RED, RESET, YELLOW};
use crate::upload;
use crate::util;
use crate::web::{self, error_page, json_error, not_found, ok_json, Disposition, Resp, ServeOpts};
use crate::zipstream::{self, ZipEntry, ZipTicket};
use futures_util::StreamExt;
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio_util::io::ReaderStream;

pub async fn handle(app: Arc<App>, req: Request<Incoming>, peer: SocketAddr) -> Resp {
    let ip = net::canonical(peer.ip());
    app.stats.seen(ip);
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    if app.verbose {
        app.log_verbose(&format!("{} {} {}", ip, method, path.replace(&app.token, "…")));
    }
    let resp = route(&app, req, ip, &method, &path, &query).await;
    web::finish(resp)
}

fn embedded(key: &str, content_type: &str, cache: &str) -> Resp {
    match assets::get(key) {
        Some(b) => web::bytes(StatusCode::OK, content_type, b, cache),
        None => not_found(),
    }
}

fn host_only() -> Resp {
    error_page(StatusCode::FORBIDDEN, "Host only")
}

async fn route(
    app: &Arc<App>,
    req: Request<Incoming>,
    ip: IpAddr,
    method: &Method,
    path: &str,
    query: &str,
) -> Resp {
    let trimmed = path.trim_matches('/');
    let is_get = *method == Method::GET || *method == Method::HEAD;
    if is_get {
        match trimmed {
            "favicon.svg" => return embedded("ui/favicon.svg", "image/svg+xml", "public, max-age=86400"),
            "favicon.ico" => return embedded("ui/favicon.ico", "image/x-icon", "public, max-age=86400"),
            "apple-touch-icon.png" | "apple-touch-icon-precomposed.png" => {
                return embedded("ui/apple-touch-icon.png", "image/png", "public, max-age=86400")
            }
            "__liquiddrop/ping" => {
                return web::bytes(StatusCode::OK, "text/plain", "liquiddrop", "no-cache")
            }
            _ => {}
        }
    }

    let mut segs = trimmed.splitn(3, '/');
    let first = segs.next().unwrap_or("");
    let route_name = segs.next().unwrap_or("").to_string();
    let rest = segs.next().unwrap_or("").to_string();

    if first.is_empty() || !util::ct_eq(first, &app.token) {
        if is_get && (trimmed.is_empty() || trimmed == "pin") {
            return web::html(StatusCode::OK, pages::pin(false, app.pins.is_locked(ip)));
        }
        if *method == Method::POST && trimmed == "pin" {
            return pin_post(app, req, ip).await;
        }
        return error_page(StatusCode::FORBIDDEN, "Forbidden");
    }

    let host = app.is_host(ip);
    match *method {
        Method::GET | Method::HEAD => get_route(app, req, ip, host, &route_name, &rest, query).await,
        Method::POST => post_route(app, req, host, &route_name, &rest).await,
        Method::PUT => {
            if route_name == "uploads" {
                upload::put_chunk(app, &rest, query, req.into_body()).await
            } else {
                not_found()
            }
        }
        Method::DELETE => delete_route(app, &route_name, &rest).await,
        _ => error_page(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed."),
    }
}

// ── PIN ────────────────────────────────────────────────────────────────

async fn pin_post(app: &Arc<App>, req: Request<Incoming>, ip: IpAddr) -> Resp {
    if app.pins.is_locked(ip) {
        say!("  {}🔑 PIN locked out for {}{}", RED, ip, RESET);
        return web::html(StatusCode::OK, pages::pin(false, true));
    }
    let declared: u64 = req
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if declared > 1024 {
        return error_page(StatusCode::BAD_REQUEST, "Bad request.");
    }
    let body = match web::read_small(req.into_body(), 1024).await {
        Some(b) => b,
        None => return error_page(StatusCode::BAD_REQUEST, "Bad request."),
    };
    let text = String::from_utf8_lossy(&body).into_owned();
    let mut digits: [Option<String>; 4] = [None, None, None, None];
    for pair in text.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let k = util::form_unquote(k);
        let idx = match k.as_str() {
            "d1" => 0,
            "d2" => 1,
            "d3" => 2,
            "d4" => 3,
            _ => continue,
        };
        if digits[idx].is_none() {
            let first: String = util::form_unquote(v).chars().take(1).collect();
            digits[idx] = Some(first);
        }
    }
    let entered: String = digits.iter().map(|d| d.clone().unwrap_or_default()).collect();
    if util::ct_eq(&entered, &app.pin) {
        app.pins.clear(ip);
        say!("  {}🔑 PIN accepted — device connected ({}){}", GREEN, ip, RESET);
        web::redirect(&format!("/{}/", app.token))
    } else {
        app.pins.record_fail(ip);
        let locked = app.pins.is_locked(ip);
        say!("  {}🔑 Wrong PIN attempt from {}{}", YELLOW, ip, RESET);
        web::html(StatusCode::OK, pages::pin(true, locked))
    }
}

// ── GET ────────────────────────────────────────────────────────────────

fn split_two(rest: &str) -> Option<(String, String)> {
    let (a, b) = rest.split_once('/')?;
    Some((util::url_unquote(a), util::url_unquote(b)))
}

async fn get_route(
    app: &Arc<App>,
    req: Request<Incoming>,
    ip: IpAddr,
    host: bool,
    route_name: &str,
    rest: &str,
    query: &str,
) -> Resp {
    match route_name {
        "" | "index.html" => web::html(StatusCode::OK, pages::index(app, host)),
        "qr.png" => web::bytes(StatusCode::OK, "image/png", app.qr_png(), "no-cache"),
        "status" => ok_json(&app.stats.snapshot()),
        "events" => events::sse(app.clone(), ip),
        "network" => ok_json(&app.network_json()),
        "files" => {
            let root = app.paths.root.clone();
            let list = tokio::task::spawn_blocking(move || files::list_files(&root))
                .await
                .unwrap_or_default();
            ok_json(&Value::Array(list))
        }
        "extensions" => {
            if rest.is_empty() {
                return ok_json(&extensions::list_for_api(app, host));
            }
            let parts: Vec<&str> = rest.split('/').collect();
            if parts.len() == 2 {
                let id = util::url_unquote(parts[0]);
                let result = match parts[1] {
                    "settings" => extensions::get_settings(app, &id).map(|s| json!({ "settings": s })),
                    "state" => extensions::get_shared_state(app, &id),
                    _ => return not_found(),
                };
                return match result {
                    Ok(v) => ok_json(&v),
                    Err(e) => json_error(StatusCode::NOT_FOUND, &e),
                };
            }
            not_found()
        }
        "extension-assets" => {
            let (id, rel) = match split_two(rest) {
                Some(p) => p,
                None => return not_found(),
            };
            let source = match extensions::visible(app, &id, host) {
                Some(s) => s,
                None => return not_found(),
            };
            let mime = util::mime_for(&rel);
            match extensions::locate_asset(&source, &rel) {
                Some(AssetLoc::Embedded(b)) => web::bytes(StatusCode::OK, mime, b, "no-cache"),
                Some(AssetLoc::File(p)) => {
                    web::serve_path(
                        req.headers(),
                        &p,
                        ServeOpts {
                            content_type: mime,
                            cache: "no-cache",
                            disposition: Disposition::None,
                            count_download: false,
                            sandbox: false,
                        },
                        None,
                    )
                    .await
                }
                None => not_found(),
            }
        }
        "extension-data" => {
            let (id, rel) = match split_two(rest) {
                Some(p) => p,
                None => return not_found(),
            };
            if extensions::visible(app, &id, host).is_none() {
                return not_found();
            }
            let path = match extensions::data_file(app, &id, &rel) {
                Some(p) => p,
                None => return not_found(),
            };
            web::serve_path(
                req.headers(),
                &path,
                ServeOpts {
                    content_type: util::mime_for(&rel),
                    cache: "no-cache",
                    disposition: Disposition::None,
                    count_download: false,
                    sandbox: true,
                },
                None,
            )
            .await
        }
        "document-preview" => {
            let name = util::url_unquote(rest);
            let path = match files::safe_path(&app.paths.root, &name) {
                Some(p) => p,
                None => return not_found(),
            };
            let n2 = name.clone();
            let p2 = path.clone();
            let result = tokio::task::spawn_blocking(move || preview::document_preview(&n2, &p2))
                .await
                .unwrap_or_else(|_| Err("Preview failed.".to_string()));
            match result {
                Ok(v) => {
                    if let Ok(m) = std::fs::metadata(&path) {
                        app.stats
                            .record(Kind::Download, m.len().min(MAX_DOCUMENT_PREVIEW as u64));
                    }
                    ok_json(&v)
                }
                Err(e) => json_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, &e),
            }
        }
        "preview" | "download" => {
            let name = util::url_unquote(rest);
            let path = match files::safe_path(&app.paths.root, &name) {
                Some(p) => p,
                None => return not_found(),
            };
            let download = route_name == "download";
            if download && !req.headers().contains_key("range") {
                say!("  {}⬇  Sending:{} {}", CYAN, RESET, name);
            }
            web::serve_path(
                req.headers(),
                &path,
                ServeOpts {
                    content_type: util::mime_for(&name),
                    cache: "no-cache",
                    disposition: if download {
                        Disposition::Attachment(&name)
                    } else {
                        Disposition::Inline(&name)
                    },
                    count_download: true,
                    sandbox: true,
                },
                Some(app.stats.clone()),
            )
            .await
        }
        "thumb" => {
            #[cfg(feature = "thumbnails")]
            {
                let name = util::url_unquote(rest);
                crate::thumbs::serve(app, req.headers(), &name).await
            }
            #[cfg(not(feature = "thumbnails"))]
            {
                let _ = (&req, rest);
                not_found()
            }
        }
        "uploads" => upload::status(app, rest).await,
        "zip" => zip_download(app, rest).await,
        "vendor" => {
            if rest.split('/').any(|p| p.is_empty() || p.starts_with('.')) {
                return not_found();
            }
            embedded(&format!("ui/vendor/{}", rest), util::mime_for(rest), "public, max-age=86400")
        }
        _ => not_found(),
    }
}

// ── ZIP ────────────────────────────────────────────────────────────────

fn names_from(body: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(list) = body.get("names").and_then(|v| v.as_array()) {
        for v in list.iter().take(20_000) {
            if let Some(s) = v.as_str() {
                if !out.iter().any(|x| x == s) {
                    out.push(s.to_string());
                }
            }
        }
    }
    out
}

async fn zip_entries(app: &App, names: &[String]) -> Vec<ZipEntry> {
    let mut entries = Vec::new();
    for name in names {
        if let Some(path) = files::safe_path(&app.paths.root, name) {
            if let Ok(meta) = tokio::fs::metadata(&path).await {
                let mtime = meta.modified().map(util::system_time_secs).unwrap_or(0);
                entries.push(ZipEntry {
                    name: name.clone(),
                    path,
                    size: meta.len(),
                    mtime,
                });
            }
        }
    }
    entries
}

async fn zip_ticket(app: &Arc<App>, body: Value) -> Resp {
    let names = names_from(&body);
    let entries = zip_entries(app, &names).await;
    if entries.is_empty() {
        return json_error(StatusCode::NOT_FOUND, "None of those files exist.");
    }
    let filename = format!("LiquidDrop-{}.zip", util::filename_stamp(util::now_secs()));
    let ticket = util::random_hex(16);
    let size = zipstream::total_size(&entries);
    let count = entries.len();
    if let Ok(mut m) = app.zip_tickets.lock() {
        m.insert(
            ticket.clone(),
            ZipTicket {
                names: entries.iter().map(|e| e.name.clone()).collect(),
                filename: filename.clone(),
                created: Instant::now(),
            },
        );
    }
    ok_json(&json!({
        "url": format!("/{}/zip/{}/{}", app.token, ticket, util::url_quote(&filename)),
        "name": filename,
        "count": count,
        "size": size,
    }))
}

async fn zip_download(app: &Arc<App>, rest: &str) -> Resp {
    let ticket = rest.split('/').next().unwrap_or("");
    let found = app
        .zip_tickets
        .lock()
        .ok()
        .and_then(|m| m.get(ticket).map(|t| (t.names.clone(), t.filename.clone())));
    let (names, filename) = match found {
        Some(f) => f,
        None => return error_page(StatusCode::NOT_FOUND, "This download link has expired."),
    };
    let entries = zip_entries(app, &names).await;
    if entries.is_empty() {
        return not_found();
    }
    let total = zipstream::total_size(&entries);
    say!("  {}📦 Zipping {} file(s) for download{}", CYAN, entries.len(), RESET);
    let (reader, mut writer) = tokio::io::duplex(1 << 20);
    let stats = app.stats.clone();
    tokio::spawn(async move {
        if let Err(e) = zipstream::write_zip(&entries, &mut writer, |n| stats.record(Kind::Download, n)).await {
            if e.kind() != std::io::ErrorKind::BrokenPipe {
                say!("  {}📦 Zip stopped: {}{}", YELLOW, e, RESET);
            }
        }
    });
    let stream = ReaderStream::with_capacity(reader, CHUNK).map(|r| r.map(Frame::data));
    let mut r = web::response(StatusCode::OK, StreamBody::new(stream).boxed_unsync());
    web::set_header(&mut r, "content-type", "application/zip");
    web::set_header(&mut r, "content-length", &total.to_string());
    web::set_header(&mut r, "content-disposition", &util::content_disposition("attachment", &filename));
    web::set_header(&mut r, "cache-control", "no-store");
    r
}

/// Server-side "Zip & Send": bundle uploaded files into one archive.
async fn bundle(app: &Arc<App>, body: Value) -> Resp {
    let names = names_from(&body);
    let entries = zip_entries(app, &names).await;
    if entries.is_empty() {
        return json_error(StatusCode::NOT_FOUND, "None of those files exist.");
    }
    let tmp = app.paths.partial.join(format!("bundle-{}.part", util::random_hex(8)));
    let file = match tokio::fs::File::create(&tmp).await {
        Ok(f) => f,
        Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    let mut writer = tokio::io::BufWriter::with_capacity(1 << 20, file);
    if let Err(e) = zipstream::write_zip(&entries, &mut writer, |_| {}).await {
        drop(writer);
        let _ = tokio::fs::remove_file(&tmp).await;
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
    }
    drop(writer);
    let name = format!("LiquidDrop-{}.zip", util::filename_stamp(util::now_secs()));
    let root = app.paths.root.clone();
    let dest = match files::finalize(app, &tmp, &root, &name).await {
        Ok(d) => d,
        Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    for e in &entries {
        let _ = tokio::fs::remove_file(&e.path).await;
    }
    let final_name = files::file_name_of(&dest);
    say!("  {}📦 Bundled {} files into{} {}", CYAN, entries.len(), RESET, final_name);
    app.hub.send(LiveEvent::Files);
    ok_json(&json!({"status": "ok", "name": final_name, "count": entries.len()}))
}

// ── POST ───────────────────────────────────────────────────────────────

fn sub_or_self<'a>(v: &'a Value, key: &str) -> &'a Value {
    match v.get(key) {
        Some(inner) if v.is_object() => inner,
        _ => v,
    }
}

async fn post_route(app: &Arc<App>, req: Request<Incoming>, host: bool, route_name: &str, rest: &str) -> Resp {
    match route_name {
        "extensions" => {
            if !host {
                return host_only();
            }
            post_extensions(app, req, rest).await
        }
        "extension-asset" => {
            if !host {
                return host_only();
            }
            let id = util::url_unquote(rest);
            if !extensions::exists(app, &id) {
                return json_error(StatusCode::NOT_FOUND, "Extension not found.");
            }
            let boundary = match req
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .and_then(upload::boundary_from)
            {
                Some(b) => b,
                None => return error_page(StatusCode::BAD_REQUEST, "Bad request."),
            };
            let declared: u64 = req
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            if declared > MAX_EXTENSION_ASSET {
                return json_error(StatusCode::PAYLOAD_TOO_LARGE, "Extension asset is too large.");
            }
            let target = app.paths.extension_data.join(&id);
            match upload::receive_multipart(app, req.into_body(), &boundary, &target, Some(MAX_EXTENSION_ASSET)).await {
                Ok(saved) => {
                    let files: Vec<Value> = saved
                        .iter()
                        .map(|s| {
                            json!({
                                "name": s.name,
                                "size": s.size,
                                "url": format!("/{}/extension-data/{}/{}", app.token, util::url_quote(&id), util::url_quote(&s.name)),
                            })
                        })
                        .collect();
                    let url = files
                        .first()
                        .and_then(|f| f.get("url").cloned())
                        .unwrap_or(json!(""));
                    ok_json(&json!({"status": "ok", "files": files, "url": url}))
                }
                Err(e) => json_error(StatusCode::BAD_REQUEST, &e),
            }
        }
        "upload" => {
            let boundary = match req
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .and_then(upload::boundary_from)
            {
                Some(b) => b,
                None => return error_page(StatusCode::BAD_REQUEST, "Bad request."),
            };
            let root = app.paths.root.clone();
            match upload::receive_multipart(app, req.into_body(), &boundary, &root, None).await {
                Ok(saved) => {
                    for s in &saved {
                        say!("  {}⬆  Received:{} {} ({})", CYAN, RESET, s.name, util::fmt_size(s.size));
                    }
                    if !saved.is_empty() {
                        app.hub.send(LiveEvent::Files);
                    }
                    ok_json(&json!({"status": "ok", "count": saved.len()}))
                }
                Err(e) => json_error(StatusCode::BAD_REQUEST, &e),
            }
        }
        "uploads" => {
            if rest.is_empty() {
                let body = match web::read_json(req.into_body()).await {
                    Ok(v) => v,
                    Err(r) => return r,
                };
                return upload::start(app, body).await;
            }
            match rest.split_once('/') {
                Some((id, "complete")) => upload::complete(app, id).await,
                _ => not_found(),
            }
        }
        "zip-ticket" | "bundle" => {
            let body = match web::read_json(req.into_body()).await {
                Ok(v) => v,
                Err(r) => return r,
            };
            if route_name == "bundle" {
                bundle(app, body).await
            } else {
                zip_ticket(app, body).await
            }
        }
        "network" => {
            if !host {
                return host_only();
            }
            let body = match web::read_json(req.into_body()).await {
                Ok(v) => v,
                Err(r) => return r,
            };
            if body.get("auto").and_then(|v| v.as_bool()).unwrap_or(false) {
                let a = app.clone();
                let _ = tokio::task::spawn_blocking(move || a.refresh_network(true)).await;
                return ok_json(&app.network_json());
            }
            let ip: Option<IpAddr> = body.get("ip").and_then(|v| v.as_str()).and_then(|s| s.parse().ok());
            match ip {
                Some(ip) if app.select_network(ip) => ok_json(&app.network_json()),
                _ => json_error(StatusCode::BAD_REQUEST, "Unknown network address."),
            }
        }
        "shutdown" => {
            if !host {
                return host_only();
            }
            app.request_shutdown(&format!(
                "  {}⏹  Shutdown requested from the host web app{}",
                YELLOW, RESET
            ));
            ok_json(&json!({"status": "shutting_down"}))
        }
        _ => not_found(),
    }
}

async fn post_extensions(app: &Arc<App>, req: Request<Incoming>, rest: &str) -> Resp {
    let parts: Vec<String> = rest.split('/').map(|s| s.to_string()).collect();
    let needs_body = !(parts.len() == 1 && parts[0] == "open-folder");
    let body = if needs_body {
        match web::read_json(req.into_body()).await {
            Ok(v) => v,
            Err(r) => return r,
        }
    } else {
        json!({})
    };
    let result: Result<Value, String> = if parts.len() == 1 {
        match parts[0].as_str() {
            "install" => extensions::install_manifest(app, sub_or_self(&body, "manifest").clone()).map(|m| {
                app.hub.send(LiveEvent::Extensions);
                json!({"status": "ok", "extension": m})
            }),
            "create" => {
                let payload = if body.is_object() { sub_or_self(&body, "extension").clone() } else { json!({}) };
                extensions::create_scaffold(app, &payload).map(|(m, folder)| {
                    app.hub.send(LiveEvent::Extensions);
                    json!({"status": "ok", "extension": m, "path": folder})
                })
            }
            "open-folder" => {
                let dir = app.paths.extensions_dir.clone();
                let _ = std::fs::create_dir_all(&dir);
                util::open_in_os(&dir.display().to_string());
                Ok(json!({"status": "ok", "path": dir.display().to_string()}))
            }
            _ => return not_found(),
        }
    } else if parts.len() >= 2 {
        let id = util::url_unquote(&parts[0]);
        match parts[1].as_str() {
            "install" => extensions::set_entry(app, &id, true, false).map(|_| {
                app.hub.send(LiveEvent::Extensions);
                json!({"status": "ok"})
            }),
            "uninstall" => extensions::uninstall(app, &id).map(|_| {
                app.hub.send(LiveEvent::Extensions);
                json!({"status": "ok"})
            }),
            "enable" => {
                let enabled = body.get("enabled").map(util::py_truthy).unwrap_or(false);
                extensions::set_entry(app, &id, true, enabled).map(|_| {
                    app.hub.send(LiveEvent::Extensions);
                    json!({"status": "ok", "enabled": enabled})
                })
            }
            "settings" => {
                let incoming = if body.is_object() { sub_or_self(&body, "settings").clone() } else { json!({}) };
                extensions::save_settings(app, &id, &incoming).map(|s| {
                    app.hub.send(LiveEvent::Settings(id.clone()));
                    json!({"status": "ok", "settings": s})
                })
            }
            "state" => {
                let incoming = if body.is_object() { sub_or_self(&body, "state").clone() } else { json!({}) };
                extensions::save_shared_state(app, &id, &incoming).map(|mut v| {
                    app.hub.send(LiveEvent::State(id.clone()));
                    if let Some(o) = v.as_object_mut() {
                        o.insert("status".into(), json!("ok"));
                    }
                    v
                })
            }
            _ => return not_found(),
        }
    } else {
        return not_found();
    };
    match result {
        Ok(v) => ok_json(&v),
        Err(e) => json_error(StatusCode::BAD_REQUEST, &e),
    }
}

// ── DELETE ─────────────────────────────────────────────────────────────

async fn delete_route(app: &Arc<App>, route_name: &str, rest: &str) -> Resp {
    match route_name {
        "delete" => {
            let name = util::url_unquote(rest);
            if let Some(path) = files::safe_path(&app.paths.root, &name) {
                match tokio::fs::remove_file(&path).await {
                    Ok(()) => {
                        say!("  {}🗑  Deleted:{} {}", RED, RESET, name);
                        app.hub.send(LiveEvent::Files);
                    }
                    Err(e) => say!("  {}🗑  Delete failed:{} {} ({})", RED, RESET, name, e),
                }
            }
            ok_json(&json!({"status": "ok"}))
        }
        "uploads" => upload::cancel(app, rest).await,
        _ => not_found(),
    }
}
