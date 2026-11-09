//! Transactional, retry-safe archives assembled from hidden staged uploads.
use crate::{
    app::App,
    events::LiveEvent,
    files, upload, util,
    web::{json_error, ok_json, Resp},
    zipstream::{self, ZipEntry},
};
use http::StatusCode;
use serde_json::{json, Value};
use std::{collections::HashSet, sync::Arc, time::Duration};

struct BundleGuard<'a> {
    app: &'a App,
    key: String,
    _guard: tokio::sync::OwnedMutexGuard<()>,
}
impl Drop for BundleGuard<'_> {
    fn drop(&mut self) {
        self.app.forget_upload_lock(&self.key);
    }
}

pub fn staged_path(app: &App, batch: &str, id: &str) -> std::path::PathBuf {
    app.paths.partial.join(format!("staged-{}-{}", batch, id))
}

fn valid_path(path: &str) -> bool {
    let path = path.strip_suffix('/').unwrap_or(path);
    !path.is_empty()
        && path.len() <= 4096
        && !path.contains(['\\', ':', '\0'])
        && !path.chars().any(char::is_control)
        && path
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
}

pub async fn create(app: &Arc<App>, body: Value) -> Resp {
    let batch = body.get("batch").and_then(Value::as_str).unwrap_or("");
    if !upload::valid_upload_id(batch) {
        return json_error(StatusCode::BAD_REQUEST, "Invalid archive batch.");
    }
    let key = format!("bundle-{}", batch);
    let lock = app.upload_lock(&key);
    let _guard = match tokio::time::timeout(Duration::from_secs(110), lock.lock_owned()).await {
        Ok(g) => g,
        Err(_) => {
            return json_error(
                StatusCode::CONFLICT,
                "Archive is still being saved. Retry shortly.",
            )
        }
    };
    let _cleanup = BundleGuard {
        app,
        key: key.clone(),
        _guard,
    };
    let receipt = app.paths.partial.join(format!("bundle-{}.json", batch));
    if let Some(result) = util::read_json_file(&receipt) {
        if result
            .get("name")
            .and_then(Value::as_str)
            .and_then(|n| files::safe_path(&app.paths.root, n))
            .is_none()
        {
            return json_error(
                StatusCode::GONE,
                "This archive was already created and has since been removed.",
            );
        }
        return ok_json(&result);
    }
    let manifest = match body.get("entries").and_then(Value::as_array) {
        Some(v) if !v.is_empty() && v.len() <= 20_000 => v,
        _ => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "Archive must contain between 1 and 20000 entries.",
            )
        }
    };
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let mut sources = Vec::new();
    for item in manifest {
        let name = item.get("path").and_then(Value::as_str).unwrap_or("");
        if !valid_path(name) || !seen.insert(name.to_string()) {
            return json_error(
                StatusCode::BAD_REQUEST,
                "Invalid or duplicate archive path.",
            );
        }
        if name.ends_with('/') {
            entries.push(ZipEntry {
                name: name.into(),
                path: std::path::PathBuf::new(),
                size: 0,
                mtime: util::now_secs(),
            });
            continue;
        }
        let id = item.get("id").and_then(Value::as_str).unwrap_or("");
        if !upload::valid_upload_id(id) {
            return json_error(StatusCode::BAD_REQUEST, "Invalid staged upload.");
        }
        let path = staged_path(app, batch, id);
        let meta = match tokio::fs::symlink_metadata(&path).await {
            Ok(m) if m.is_file() && item.get("size").and_then(Value::as_u64) == Some(m.len()) => m,
            _ => {
                return json_error(
                    StatusCode::CONFLICT,
                    "An archive file is missing or incomplete. No archive was created.",
                )
            }
        };
        sources.push(path.clone());
        entries.push(ZipEntry {
            name: name.into(),
            path,
            size: meta.len(),
            mtime: meta.modified().map(util::system_time_secs).unwrap_or(0),
        });
    }
    let file_names: HashSet<_> = entries
        .iter()
        .filter(|e| !e.name.ends_with('/'))
        .map(|e| e.name.as_str())
        .collect();
    for e in &entries {
        for (at, _) in e.name.match_indices('/') {
            if file_names.contains(&e.name[..at]) {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "An archive path conflicts with a file.",
                );
            }
        }
    }
    let tmp = app.paths.partial.join(format!("bundle-{}.part", batch));
    let file = match tokio::fs::File::create(&tmp).await {
        Ok(f) => f,
        Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    let mut writer = tokio::io::BufWriter::with_capacity(1 << 20, file);
    let result = zipstream::write_zip(&entries, &mut writer, |_| {}).await;
    drop(writer);
    if let Err(e) = result {
        let _ = tokio::fs::remove_file(&tmp).await;
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
    }
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .map(files::sanitize_filename)
        .filter(|s| s.to_ascii_lowercase().ends_with(".zip"))
        .unwrap_or_else(|| format!("LiquidDrop-{}.zip", util::filename_stamp(util::now_secs())));
    let dest = match files::finalize(app, &tmp, &app.paths.root, &name).await {
        Ok(p) => p,
        Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    let result = json!({"status":"ok", "name": files::file_name_of(&dest), "count": sources.len()});
    if let Err(e) = util::write_json_file(&receipt, &result) {
        let _ = tokio::fs::remove_file(&dest).await;
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
    }
    for path in sources {
        let _ = tokio::fs::remove_file(path).await;
    }
    app.hub.send(LiveEvent::Files);
    ok_json(&result)
}
