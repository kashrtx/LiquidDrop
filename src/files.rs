use crate::app::App;
use crate::util;
use serde_json::{json, Value};
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io;
use std::path::{Path, PathBuf};

/// Top-level, non-hidden files, newest first (same as v4's /files).
pub fn list_files(root: &Path) -> Vec<Value> {
    let mut items: Vec<(f64, String, u64)> = Vec::new();
    if let Ok(rd) = fs::read_dir(root) {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            let meta = match fs::metadata(entry.path()) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !meta.is_file() {
                continue;
            }
            let modified = meta.modified().map(util::system_time_f64).unwrap_or(0.0);
            items.push((modified, name, meta.len()));
        }
    }
    items.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    items
        .into_iter()
        .map(|(modified, name, size)| json!({"name": name, "size": size, "modified": modified}))
        .collect()
}

/// Cheap fingerprint of the folder used to push live "files changed" events.
pub fn dir_signature(root: &Path) -> u64 {
    let mut entries: Vec<(String, u64, u128)> = Vec::new();
    if let Ok(rd) = fs::read_dir(root) {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                let m = meta.modified().map(util::system_time_nanos).unwrap_or(0);
                entries.push((name, meta.len(), m));
            }
        }
    }
    entries.sort();
    let mut h = DefaultHasher::new();
    entries.hash(&mut h);
    h.finish() | 1
}

/// Resolve a user-supplied name to a file directly inside `root`.
/// Rejects separators, traversal, hidden files and symlinks escaping root.
pub fn safe_path(root: &Path, name: &str) -> Option<PathBuf> {
    if name.is_empty()
        || name.starts_with('.')
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || (cfg!(windows) && name.contains(':'))
    {
        return None;
    }
    let candidate = root.join(name);
    let resolved = fs::canonicalize(&candidate).ok()?;
    let root_resolved = fs::canonicalize(root).ok()?;
    if resolved.parent()? != root_resolved.as_path() {
        return None;
    }
    if !resolved.is_file() {
        return None;
    }
    Some(candidate)
}

fn is_windows_reserved(stem: &str) -> bool {
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((upper.starts_with("COM") || upper.starts_with("LPT"))
            && upper.len() == 4
            && upper.as_bytes()[3].is_ascii_digit())
}

/// Make an uploaded name safe to create on this OS.
pub fn sanitize_filename(raw: &str) -> String {
    let base = raw.rsplit(|c| c == '/' || c == '\\').next().unwrap_or("");
    let mut name: String = base
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '/' | '\\' | ':' | '\0'))
        .collect();
    if cfg!(windows) {
        name = name
            .chars()
            .filter(|c| !matches!(c, '<' | '>' | '"' | '|' | '?' | '*'))
            .collect();
        name = name.trim_end_matches(|c| c == '.' || c == ' ').to_string();
        let stem = name.split('.').next().unwrap_or("");
        if is_windows_reserved(stem) {
            name = format!("_{}", name);
        }
    }
    let name = name.trim().to_string();
    if name.is_empty() || name.starts_with('.') {
        return format!("file_{}", util::random_hex(4));
    }
    limit_name_bytes(&name, 200)
}

fn split_ext(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(i) if i > 0 && i + 1 < name.len() => (&name[..i], &name[i..]),
        _ => (name, ""),
    }
}

fn limit_name_bytes(name: &str, max: usize) -> String {
    if name.len() <= max {
        return name.to_string();
    }
    let (stem, ext) = split_ext(name);
    let ext = if ext.len() > 20 { "" } else { ext };
    let budget = max.saturating_sub(ext.len());
    let mut out = String::new();
    for c in stem.chars() {
        if out.len() + c.len_utf8() > budget {
            break;
        }
        out.push(c);
    }
    out.push_str(ext);
    out
}

/// "photo.jpg" -> "photo (1).jpg" while taken (same pattern as v4).
pub fn unique_destination(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if !first.exists() {
        return first;
    }
    let (stem, ext) = split_ext(name);
    let mut n = 1u32;
    loop {
        let candidate = dir.join(format!("{} ({}){}", stem, n, ext));
        if !candidate.exists() {
            return candidate;
        }
        n += 1;
    }
}

/// Move a finished temp file into `dir` under a unique version of `name`.
/// Serialized so two uploads with the same name can never overwrite.
pub async fn finalize(app: &App, src: &Path, dir: &Path, name: &str) -> io::Result<PathBuf> {
    let _guard = app.finalize_lock.lock().await;
    tokio::fs::create_dir_all(dir).await?;
    let dest = unique_destination(dir, name);
    match tokio::fs::rename(src, &dest).await {
        Ok(()) => Ok(dest),
        Err(_) => {
            tokio::fs::copy(src, &dest).await?;
            let _ = tokio::fs::remove_file(src).await;
            Ok(dest)
        }
    }
}

pub fn file_name_of(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// Remove abandoned partial uploads and stale thumbnails.
pub fn cleanup_stale(app: &App) {
    let now = util::now_secs();
    let max_age = crate::config::PARTIAL_MAX_AGE_SECS;
    for dir in [&app.paths.partial, &app.paths.thumbs] {
        let limit = if dir == &app.paths.thumbs { 30 * 86_400 } else { max_age };
        if let Ok(rd) = fs::read_dir(dir) {
            for entry in rd.flatten() {
                let old = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .map(|t| now.saturating_sub(util::system_time_secs(t)) > limit)
                    .unwrap_or(false);
                if old {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizing() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("C:\\Users\\me\\photo.jpg"), "photo.jpg");
        assert!(sanitize_filename(".hidden").starts_with("file_"));
        assert!(sanitize_filename("").starts_with("file_"));
        assert_eq!(sanitize_filename("照片 🎉.png"), "照片 🎉.png");
        assert!(sanitize_filename(&"a".repeat(400)).len() <= 200);
    }

    #[test]
    fn extensions() {
        assert_eq!(split_ext("a.tar.gz"), ("a.tar", ".gz"));
        assert_eq!(split_ext("README"), ("README", ""));
        assert_eq!(split_ext(".env"), (".env", ""));
    }
}
