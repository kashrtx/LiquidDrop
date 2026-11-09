//! Add-on registry, ported 1:1 from v4 so existing add-ons, settings and
//! shared state keep working. Bundled add-ons are now embedded in the binary.

use crate::app::App;
use crate::assets;
use crate::config::MAX_EXTENSION_SHARED_STATE;
use crate::term::{RESET, YELLOW};
use crate::util::{self, plain_string, py_float, py_str, py_truthy};
use serde_json::{json, Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

const EMBED_PREFIX: &str = "extensions/";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Bundled,
    User,
}

#[derive(Clone)]
pub enum Root {
    Embedded(String), // e.g. "extensions/liquiddrop.preview"
    Dir(PathBuf),
}

#[derive(Clone)]
pub struct Source {
    pub kind: Kind,
    pub root: Root,
    pub manifest: Value,
}

struct Invalid {
    id: String,
    name: String,
    kind: Kind,
    root: Root,
    error: String,
}

pub enum AssetLoc {
    Embedded(&'static [u8]),
    File(PathBuf),
}

pub fn valid_id(id: &str) -> bool {
    let b = id.as_bytes();
    if b.len() < 2 || b.len() > 64 {
        return false;
    }
    let first_ok = b[0].is_ascii_lowercase() || b[0].is_ascii_digit();
    first_ok
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-'))
}

pub fn safe_relpath(value: &str) -> Option<String> {
    let rel = value.trim().replace('\\', "/");
    let rel = rel.trim_start_matches('/');
    if rel.is_empty() || rel.starts_with('.') {
        return None;
    }
    let parts: Vec<&str> = rel.split('/').filter(|p| !p.is_empty() && *p != ".").collect();
    if parts.is_empty() || parts.iter().any(|p| *p == ".." || p.starts_with('.')) {
        return None;
    }
    Some(parts.join("/"))
}

fn root_display(root: &Root) -> String {
    match root {
        Root::Embedded(p) => format!("(built into LiquidDrop) {}", p.trim_start_matches(EMBED_PREFIX)),
        Root::Dir(d) => d.display().to_string(),
    }
}

fn resolve_in_dir(dir: &Path, rel: &str) -> Option<PathBuf> {
    let root = fs::canonicalize(dir).ok()?;
    let mut p = root.clone();
    for part in rel.split('/') {
        p.push(part);
    }
    let resolved = fs::canonicalize(&p).ok()?;
    if !resolved.starts_with(&root) || !resolved.is_file() {
        return None;
    }
    Some(resolved)
}

impl Source {
    fn id(&self) -> String {
        self.manifest.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string()
    }

    fn locate(&self, rel: &str) -> Option<AssetLoc> {
        let rel = safe_relpath(rel)?;
        match &self.root {
            Root::Embedded(prefix) => assets::get(&format!("{}/{}", prefix, rel)).map(AssetLoc::Embedded),
            Root::Dir(dir) => resolve_in_dir(dir, &rel).map(AssetLoc::File),
        }
    }

    fn file_exists(&self, rel: &str) -> bool {
        self.locate(rel).is_some()
    }
}

// ── Manifest normalization ─────────────────────────────────────────────

fn valid_setting_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 64
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn normalize_setting_schema(schema: Option<&Value>) -> Vec<Value> {
    let list = match schema.and_then(|v| v.as_array()) {
        Some(l) => l,
        None => return Vec::new(),
    };
    let allowed = ["string", "text", "number", "boolean", "select", "color", "asset"];
    let mut out = Vec::new();
    for field in list.iter().take(20) {
        let obj = match field.as_object() {
            Some(o) => o,
            None => continue,
        };
        let key = plain_string(obj.get("key"), "", 64);
        if !valid_setting_key(&key) {
            continue;
        }
        let mut kind = plain_string(obj.get("type"), "string", 16);
        if !allowed.contains(&kind.as_str()) {
            kind = "string".to_string();
        }
        let mut item = Map::new();
        item.insert("key".into(), json!(key));
        item.insert("label".into(), json!(plain_string(obj.get("label"), &key, 80)));
        item.insert("type".into(), json!(kind));
        item.insert("default".into(), obj.get("default").cloned().unwrap_or(Value::Null));
        item.insert("help".into(), json!(plain_string(obj.get("help"), "", 180)));
        if kind == "number" {
            for nk in ["min", "max", "step"] {
                if let Some(f) = obj.get(nk).and_then(py_float) {
                    item.insert(nk.into(), util::json_number(f));
                }
            }
        }
        if kind == "select" {
            let mut options = Vec::new();
            if let Some(opts) = obj.get("options").and_then(|v| v.as_array()) {
                for opt in opts.iter().take(24) {
                    let (val, label) = match opt.as_object() {
                        Some(o) => {
                            let val = plain_string(o.get("value"), "", 80);
                            let label = plain_string(o.get("label"), &val, 80);
                            (val, label)
                        }
                        None => {
                            let val = plain_string(Some(opt), "", 80);
                            (val.clone(), val)
                        }
                    };
                    if !val.is_empty() {
                        options.push(json!({"value": val, "label": label}));
                    }
                }
            }
            item.insert("options".into(), Value::Array(options));
        }
        if kind == "asset" {
            item.insert("accept".into(), json!(plain_string(obj.get("accept"), "", 80)));
            item.insert("name_key".into(), json!(plain_string(obj.get("name_key"), "", 64)));
        }
        out.push(Value::Object(item));
    }
    out
}

pub fn normalize_manifest(data: &Value) -> Result<Value, String> {
    let obj = data
        .as_object()
        .ok_or_else(|| "Extension manifest must be a JSON object.".to_string())?;
    let id = plain_string(obj.get("id"), "", 64).to_lowercase();
    if !valid_id(&id) {
        return Err(
            "Extension id must use lowercase letters, numbers, dots, dashes, or underscores.".to_string(),
        );
    }
    let mut client = Map::new();
    if let Some(c) = obj.get("client").and_then(|v| v.as_object()) {
        if let Some(s) = c.get("script").and_then(|v| v.as_str()).and_then(safe_relpath) {
            client.insert("script".into(), json!(s));
        }
        if let Some(s) = c.get("style").and_then(|v| v.as_str()).and_then(safe_relpath) {
            client.insert("style".into(), json!(s));
        }
    }
    let capabilities: Vec<Value> = obj
        .get("capabilities")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .take(10)
                .map(|c| plain_string(Some(c), "", 60))
                .filter(|s| !s.is_empty())
                .map(Value::String)
                .collect()
        })
        .unwrap_or_default();
    let defaults = match obj.get("settings_defaults") {
        Some(Value::Object(m)) => Value::Object(m.clone()),
        _ => json!({}),
    };
    Ok(json!({
        "id": id,
        "name": plain_string(obj.get("name"), &id, 80),
        "version": plain_string(obj.get("version"), "1.0.0", 32),
        "description": plain_string(obj.get("description"), "", 300),
        "author": plain_string(obj.get("author"), "", 80),
        "created_at": plain_string(obj.get("created_at"), "", 40),
        "updated_at": plain_string(obj.get("updated_at"), "", 40),
        "license": plain_string(obj.get("license"), "Creator retains rights", 120),
        "category": plain_string(obj.get("category"), "Utility", 40),
        "default_enabled": obj.get("default_enabled").map(py_truthy).unwrap_or(true),
        "capabilities": capabilities,
        "settings_schema": normalize_setting_schema(obj.get("settings_schema")),
        "settings_defaults": defaults,
        "client": Value::Object(client),
    }))
}

fn schema_of(manifest: &Value) -> Vec<Value> {
    manifest
        .get("settings_schema")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

fn manifest_defaults(manifest: &Value) -> Map<String, Value> {
    let mut defaults = manifest
        .get("settings_defaults")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    for field in schema_of(manifest) {
        if let Some(key) = field.get("key").and_then(|v| v.as_str()) {
            if !defaults.contains_key(key) {
                if let Some(d) = field.get("default") {
                    defaults.insert(key.to_string(), d.clone());
                }
            }
        }
    }
    defaults
}

fn coerce_setting_value(field: &Value, value: &Value) -> Value {
    let kind = field.get("type").and_then(|v| v.as_str()).unwrap_or("string");
    match kind {
        "boolean" => json!(py_truthy(value)),
        "number" => {
            let mut num = py_float(value).unwrap_or_else(|| {
                field.get("default").and_then(py_float).unwrap_or(0.0)
            });
            if let Some(min) = field.get("min").and_then(py_float) {
                num = num.max(min);
            }
            if let Some(max) = field.get("max").and_then(py_float) {
                num = num.min(max);
            }
            util::json_number(num)
        }
        "select" => {
            let allowed: Vec<String> = field
                .get("options")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .map(|o| o.get("value").map(py_str).unwrap_or_default())
                        .collect()
                })
                .unwrap_or_default();
            let v = py_str(value);
            if allowed.contains(&v) {
                json!(v)
            } else {
                json!(allowed.first().cloned().unwrap_or_default())
            }
        }
        "color" => {
            let v = py_str(value).trim().to_string();
            let ok = v.len() == 7
                && v.starts_with('#')
                && v[1..].bytes().all(|b| b.is_ascii_hexdigit());
            if ok {
                json!(v)
            } else {
                let d = field.get("default").map(|d| if py_truthy(d) { py_str(d) } else { String::new() });
                json!(d.filter(|s| !s.is_empty()).unwrap_or_else(|| "#050816".to_string()))
            }
        }
        "asset" => {
            let v = if value.is_null() { String::new() } else { py_str(value).trim().to_string() };
            json!(util::truncate_chars(&v, 1200))
        }
        _ => {
            let v = if value.is_null() { String::new() } else { py_str(value) };
            json!(util::truncate_chars(&v, 8000))
        }
    }
}

fn coerce_settings(manifest: &Value, incoming: &Value, current: Option<&Map<String, Value>>) -> Map<String, Value> {
    let mut settings = manifest_defaults(manifest);
    if let Some(cur) = current {
        for (k, v) in cur {
            settings.insert(k.clone(), v.clone());
        }
    }
    let fields = schema_of(manifest);
    if let Some(inc) = incoming.as_object() {
        for (key, value) in inc {
            let field = fields
                .iter()
                .find(|f| f.get("key").and_then(|v| v.as_str()) == Some(key.as_str()));
            match field {
                Some(f) => {
                    settings.insert(key.clone(), coerce_setting_value(f, value));
                }
                None => {
                    if !value.is_array() && !value.is_object() {
                        settings.insert(util::truncate_chars(key, 64), value.clone());
                    }
                }
            }
        }
    }
    settings
}

// ── Discovery and state ────────────────────────────────────────────────

fn read_manifest_value(root: &Root) -> Value {
    match root {
        Root::Embedded(prefix) => assets::get(&format!("{}/manifest.json", prefix))
            .and_then(|b| {
                let b = b.strip_prefix(&b"\xEF\xBB\xBF"[..]).unwrap_or(b);
                serde_json::from_slice(b).ok()
            })
            .unwrap_or(Value::Null),
        Root::Dir(dir) => util::read_json_file(&dir.join("manifest.json")).unwrap_or(Value::Null),
    }
}

fn bundled_roots() -> Vec<Root> {
    let mut names: Vec<String> = Vec::new();
    for key in assets::keys_with_prefix(EMBED_PREFIX) {
        let rest = &key[EMBED_PREFIX.len()..];
        if let Some((folder, file)) = rest.split_once('/') {
            if file == "manifest.json" && !names.iter().any(|n| n == folder) {
                names.push(folder.to_string());
            }
        }
    }
    names.sort_by_key(|n| n.to_lowercase());
    names
        .into_iter()
        .map(|n| Root::Embedded(format!("{}{}", EMBED_PREFIX, n)))
        .collect()
}

fn user_roots(dir: &Path) -> Vec<Root> {
    let mut dirs: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir() && p.join("manifest.json").is_file())
            .collect(),
        Err(_) => Vec::new(),
    };
    dirs.sort_by_key(|p| {
        p.file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default()
    });
    dirs.into_iter().map(Root::Dir).collect()
}

fn root_name(root: &Root) -> String {
    match root {
        Root::Embedded(p) => p.trim_start_matches(EMBED_PREFIX).to_string(),
        Root::Dir(d) => d
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default(),
    }
}

fn discover(app: &App) -> (Vec<Source>, Vec<Invalid>) {
    let mut sources: Vec<Source> = Vec::new();
    let mut errors: Vec<Invalid> = Vec::new();
    let mut roots: Vec<(Kind, Root)> = bundled_roots().into_iter().map(|r| (Kind::Bundled, r)).collect();
    roots.extend(user_roots(&app.paths.extensions_dir).into_iter().map(|r| (Kind::User, r)));
    for (kind, root) in roots {
        let folder = root_name(&root);
        match normalize_manifest(&read_manifest_value(&root)) {
            Err(e) => {
                say!("  {}Extension skipped:{} {} ({})", YELLOW, RESET, root_display(&root), e);
                errors.push(Invalid {
                    id: if folder.is_empty() { "invalid-extension".into() } else { folder.to_lowercase() },
                    name: if folder.is_empty() { "Invalid extension".into() } else { folder.clone() },
                    kind,
                    root,
                    error: e,
                });
            }
            Ok(manifest) => {
                let id = manifest["id"].as_str().unwrap_or("").to_string();
                if sources.iter().any(|s| s.id() == id) {
                    let msg = format!("Duplicate extension id: {}", id);
                    say!("  {}Extension skipped:{} {}", YELLOW, RESET, msg);
                    errors.push(Invalid {
                        name: manifest["name"].as_str().unwrap_or(&id).to_string(),
                        id,
                        kind,
                        root,
                        error: msg,
                    });
                    continue;
                }
                sources.push(Source { kind, root, manifest });
            }
        }
    }
    (sources, errors)
}

fn load_state(app: &App) -> Map<String, Value> {
    match util::read_json_file(&app.paths.extensions_state) {
        Some(Value::Object(m)) => m,
        _ => Map::new(),
    }
}

fn save_state(app: &App, state: &Map<String, Value>) -> Result<(), String> {
    util::write_json_file(&app.paths.extensions_state, &Value::Object(state.clone())).map_err(|e| e.to_string())
}

fn ensure_state(app: &App, sources: &[Source]) -> Map<String, Value> {
    let mut state = load_state(app);
    let mut changed = false;
    for source in sources {
        let id = source.id();
        let defaults = manifest_defaults(&source.manifest);
        let default_enabled = source.manifest["default_enabled"].as_bool().unwrap_or(true);
        let entry_ok = state.get(&id).map(|v| v.is_object()).unwrap_or(false);
        if !entry_ok {
            state.insert(
                id.clone(),
                json!({
                    "installed": true,
                    "enabled": if source.kind == Kind::Bundled { default_enabled } else { false },
                    "settings": Value::Object(defaults),
                    "shared_state": {},
                    "shared_state_updated_at": "",
                }),
            );
            changed = true;
            continue;
        }
        let entry = match state.get_mut(&id).and_then(|v| v.as_object_mut()) {
            Some(e) => e,
            None => continue,
        };
        if source.kind == Kind::User && entry.get("installed").map(py_truthy) == Some(false) {
            entry.insert("installed".into(), json!(true));
            changed = true;
        }
        if !entry.contains_key("enabled") {
            entry.insert("enabled".into(), json!(default_enabled));
            changed = true;
        }
        match entry.get("settings").and_then(|v| v.as_object()).cloned() {
            None => {
                entry.insert("settings".into(), Value::Object(defaults));
                changed = true;
            }
            Some(current) => {
                let mut merged = defaults;
                for (k, v) in &current {
                    merged.insert(k.clone(), v.clone());
                }
                if merged != current {
                    entry.insert("settings".into(), Value::Object(merged));
                    changed = true;
                }
            }
        }
        if !entry.get("shared_state").map(|v| v.is_object()).unwrap_or(false) {
            entry.insert("shared_state".into(), json!({}));
            changed = true;
        }
        if !entry.contains_key("shared_state_updated_at") {
            entry.insert("shared_state_updated_at".into(), json!(""));
            changed = true;
        }
    }
    if changed {
        let _ = save_state(app, &state);
    }
    state
}

fn find(app: &App, id: &str) -> Option<Source> {
    discover(app).0.into_iter().find(|s| s.id() == id)
}

fn asset_url(app: &App, id: &str, rel: &str) -> String {
    format!("/{}/extension-assets/{}/{}", app.token, util::url_quote(id), util::url_quote(rel))
}

fn root_times(root: &Root) -> (String, String) {
    let dir = match root {
        Root::Dir(d) => d,
        Root::Embedded(_) => return (String::new(), String::new()),
    };
    let mut created: Option<u64> = None;
    let mut updated: Option<u64> = None;
    let mut stack = vec![dir.clone()];
    while let Some(d) = stack.pop() {
        if let Ok(rd) = fs::read_dir(&d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if let Ok(m) = e.metadata() {
                    let c = m.created().or_else(|_| m.modified()).map(util::system_time_secs).unwrap_or(0);
                    let u = m.modified().map(util::system_time_secs).unwrap_or(0);
                    created = Some(created.map_or(c, |x| x.min(c)));
                    updated = Some(updated.map_or(u, |x| x.max(u)));
                }
            }
        }
    }
    (
        created.map(util::iso_utc).unwrap_or_default(),
        updated.map(util::iso_utc).unwrap_or_default(),
    )
}

fn health(source: &Source, entry: &Value) -> Value {
    let installed = entry.get("installed").map(py_truthy).unwrap_or(true);
    let enabled = entry.get("enabled").map(py_truthy).unwrap_or(false) && installed;
    let mut messages: Vec<String> = Vec::new();
    let (mut status, mut label) = ("ready", "Ready");
    if !installed {
        status = "not_installed";
        label = "Not installed";
    } else if !enabled {
        status = "disabled";
        label = "Disabled";
    } else {
        let client = &source.manifest["client"];
        let script = client.get("script").and_then(|v| v.as_str());
        let style = client.get("style").and_then(|v| v.as_str());
        if let Some(s) = script {
            if !source.file_exists(s) {
                messages.push(format!("Missing client script: {}", s));
            }
        }
        if let Some(s) = style {
            if !source.file_exists(s) {
                messages.push(format!("Missing stylesheet: {}", s));
            }
        }
        if script.is_none() && style.is_none() {
            messages.push("No client script or stylesheet is declared.".to_string());
        }
        if !messages.is_empty() {
            status = "error";
            label = "Load error";
        }
    }
    let safety = if source.kind == Kind::Bundled {
        json!({"level": "trusted", "label": "Bundled", "messages": ["Shipped with LiquidDrop."]})
    } else {
        json!({
            "level": "validated",
            "label": "Manifest validated",
            "messages": ["Paths are sandboxed to this add-on folder. Review the JavaScript before enabling community code."],
        })
    };
    json!({"status": status, "label": label, "safe": status != "error", "messages": messages, "safety": safety})
}

pub fn list_for_api(app: &App, can_manage: bool) -> Value {
    let _g = app.ext_lock.lock();
    let (sources, errors) = discover(app);
    let state = ensure_state(app, &sources);
    let mut list: Vec<Value> = Vec::new();
    for source in &sources {
        let m = &source.manifest;
        let id = source.id();
        let entry = state.get(&id).cloned().unwrap_or_else(|| json!({}));
        let installed = entry.get("installed").map(py_truthy).unwrap_or(true);
        let enabled = entry.get("enabled").map(py_truthy).unwrap_or(false) && installed;
        let settings = coerce_settings(m, &json!({}), entry.get("settings").and_then(|v| v.as_object()));
        let (ct, ut) = root_times(&source.root);
        let created = m["created_at"].as_str().filter(|s| !s.is_empty()).map(|s| s.to_string()).unwrap_or(ct);
        let updated = m["updated_at"].as_str().filter(|s| !s.is_empty()).map(|s| s.to_string()).unwrap_or(ut);
        let mut client = Map::new();
        if installed && enabled {
            if let Some(s) = m["client"].get("script").and_then(|v| v.as_str()) {
                client.insert("script_url".into(), json!(asset_url(app, &id, s)));
            }
            if let Some(s) = m["client"].get("style").and_then(|v| v.as_str()) {
                client.insert("style_url".into(), json!(asset_url(app, &id, s)));
            }
        }
        list.push(json!({
            "id": id,
            "name": m["name"],
            "version": m["version"],
            "description": m["description"],
            "author": m["author"],
            "created_at": created,
            "updated_at": updated,
            "license": m["license"],
            "category": m["category"],
            "capabilities": m["capabilities"],
            "builtin": source.kind == Kind::Bundled,
            "installed": installed,
            "enabled": enabled,
            "settings_schema": m["settings_schema"],
            "settings": if can_manage { Value::Object(settings) } else { json!({}) },
            "client": Value::Object(client),
            "path": if can_manage { root_display(&source.root) } else { String::new() },
            "health": health(source, &entry),
        }));
    }
    for e in &errors {
        let (ct, ut) = root_times(&e.root);
        list.push(json!({
            "id": e.id, "name": e.name, "version": "",
            "description": "LiquidDrop could not load this manifest.",
            "author": "", "created_at": ct, "updated_at": ut, "license": "",
            "category": "Invalid", "capabilities": [], "builtin": e.kind == Kind::Bundled,
            "installed": false, "enabled": false, "settings_schema": [], "settings": {}, "client": {},
            "path": if can_manage { root_display(&e.root) } else { String::new() },
            "health": {
                "status": "error", "label": "Manifest error", "safe": false, "messages": [e.error],
                "safety": {"level": "blocked", "label": "Blocked", "messages": ["LiquidDrop skipped this add-on before loading any code."]},
            },
        }));
    }
    json!({
        "can_manage": can_manage,
        "developer_dir": app.paths.extensions_dir.display().to_string(),
        "bundled_dir": "Built into LiquidDrop",
        "extensions": list,
    })
}

fn entry_of(state: &Map<String, Value>, id: &str) -> Map<String, Value> {
    state.get(id).and_then(|v| v.as_object()).cloned().unwrap_or_default()
}

pub fn get_settings(app: &App, id: &str) -> Result<Value, String> {
    let _g = app.ext_lock.lock();
    let (sources, _) = discover(app);
    let source = sources.iter().find(|s| s.id() == id).ok_or("Extension not found.")?;
    let state = ensure_state(app, &sources);
    let entry = entry_of(&state, id);
    Ok(Value::Object(coerce_settings(
        &source.manifest,
        &json!({}),
        entry.get("settings").and_then(|v| v.as_object()),
    )))
}

pub fn save_settings(app: &App, id: &str, incoming: &Value) -> Result<Value, String> {
    let _g = app.ext_lock.lock();
    let (sources, _) = discover(app);
    let source = sources.iter().find(|s| s.id() == id).ok_or("Extension not found.")?.clone();
    let mut state = ensure_state(app, &sources);
    let mut entry = entry_of(&state, id);
    let current = entry.get("settings").and_then(|v| v.as_object()).cloned();
    let settings = Value::Object(coerce_settings(&source.manifest, incoming, current.as_ref()));
    entry.insert("settings".into(), settings.clone());
    state.insert(id.to_string(), Value::Object(entry));
    save_state(app, &state)?;
    Ok(settings)
}

pub fn get_shared_state(app: &App, id: &str) -> Result<Value, String> {
    let _g = app.ext_lock.lock();
    let (sources, _) = discover(app);
    if !sources.iter().any(|s| s.id() == id) {
        return Err("Extension not found.".into());
    }
    let state = ensure_state(app, &sources);
    let entry = entry_of(&state, id);
    let shared = entry.get("shared_state").filter(|v| v.is_object()).cloned().unwrap_or_else(|| json!({}));
    Ok(json!({"state": shared, "updated_at": entry.get("shared_state_updated_at").cloned().unwrap_or(json!(""))}))
}

pub fn save_shared_state(app: &App, id: &str, incoming: &Value) -> Result<Value, String> {
    if !incoming.is_object() {
        return Err("Shared extension state must be a JSON object.".into());
    }
    let size = serde_json::to_vec(incoming).map(|v| v.len()).unwrap_or(usize::MAX);
    if size > MAX_EXTENSION_SHARED_STATE {
        return Err("Shared extension state is too large.".into());
    }
    let _g = app.ext_lock.lock();
    let (sources, _) = discover(app);
    if !sources.iter().any(|s| s.id() == id) {
        return Err("Extension not found.".into());
    }
    let mut state = ensure_state(app, &sources);
    let mut entry = entry_of(&state, id);
    let now = util::utc_now_iso();
    entry.insert("shared_state".into(), incoming.clone());
    entry.insert("shared_state_updated_at".into(), json!(now));
    state.insert(id.to_string(), Value::Object(entry));
    save_state(app, &state)?;
    Ok(json!({"state": incoming, "updated_at": now}))
}

pub fn set_entry(app: &App, id: &str, installed: bool, enabled: bool) -> Result<(), String> {
    let _g = app.ext_lock.lock();
    if find(app, id).is_none() {
        return Err("Extension not found.".into());
    }
    let mut state = load_state(app);
    let mut entry = entry_of(&state, id);
    entry.insert("installed".into(), json!(installed));
    entry.insert("enabled".into(), json!(installed && enabled));
    state.insert(id.to_string(), Value::Object(entry));
    save_state(app, &state)
}

pub fn uninstall(app: &App, id: &str) -> Result<(), String> {
    let _g = app.ext_lock.lock();
    let source = find(app, id).ok_or("Extension not found.")?;
    let mut state = load_state(app);
    if source.kind == Kind::User {
        if let Root::Dir(dir) = &source.root {
            let _ = fs::remove_dir_all(dir);
        }
        state.remove(id);
    } else {
        let mut entry = entry_of(&state, id);
        entry.insert("installed".into(), json!(false));
        entry.insert("enabled".into(), json!(false));
        state.insert(id.to_string(), Value::Object(entry));
    }
    save_state(app, &state)
}

pub fn install_manifest(app: &App, data: Value) -> Result<Value, String> {
    let mut data = data;
    let mut inline_js = String::new();
    let mut inline_css = String::new();
    if let Some(obj) = data.as_object_mut() {
        let now = util::utc_now_iso();
        obj.entry("created_at").or_insert(json!(now.clone()));
        obj.entry("updated_at").or_insert(json!(now));
        obj.entry("license").or_insert(json!("Creator retains rights"));
        if let Some(client) = obj.get_mut("client").and_then(|v| v.as_object_mut()) {
            if let Some(js) = client.remove("inline_js") {
                inline_js = if js.is_null() { String::new() } else { py_str(&js) };
            }
            if let Some(css) = client.remove("inline_css") {
                inline_css = if css.is_null() { String::new() } else { py_str(&css) };
            }
            if !inline_js.is_empty() {
                client.insert("script".into(), json!("client.js"));
            }
            if !inline_css.is_empty() {
                client.insert("style".into(), json!("style.css"));
            }
        }
    }
    let manifest = normalize_manifest(&data)?;
    let id = manifest["id"].as_str().unwrap_or("").to_string();
    let _g = app.ext_lock.lock();
    if let Some(existing) = find(app, &id) {
        if existing.kind == Kind::Bundled {
            let mut state = load_state(app);
            let mut entry = entry_of(&state, &id);
            entry.insert("installed".into(), json!(true));
            entry.insert("enabled".into(), json!(false));
            state.insert(id.clone(), Value::Object(entry));
            save_state(app, &state)?;
            return Ok(manifest);
        }
    }
    let dest = app.paths.extensions_dir.join(&id);
    fs::create_dir_all(&dest).map_err(|e| e.to_string())?;
    if !inline_js.is_empty() {
        fs::write(dest.join("client.js"), util::truncate_chars(&inline_js, 200_000)).map_err(|e| e.to_string())?;
    }
    if !inline_css.is_empty() {
        fs::write(dest.join("style.css"), util::truncate_chars(&inline_css, 100_000)).map_err(|e| e.to_string())?;
    }
    util::write_json_file(&dest.join("manifest.json"), &manifest).map_err(|e| e.to_string())?;
    let mut state = load_state(app);
    state.insert(
        id,
        json!({"installed": true, "enabled": false, "settings": Value::Object(manifest_defaults(&manifest))}),
    );
    save_state(app, &state)?;
    Ok(manifest)
}

fn id_from_name(name: &str) -> String {
    let mut slug = String::new();
    let mut dash = false;
    for c in name.to_lowercase().chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            slug.push(c);
            dash = false;
        } else if !dash {
            slug.push('-');
            dash = true;
        }
    }
    let slug = slug.trim_matches(|c| c == '-' || c == '.' || c == '_').to_string();
    let slug = if slug.is_empty() { "addon".to_string() } else { slug };
    let base = util::truncate_chars(&format!("community.{}", slug), 64);
    let base = base.trim_end_matches(|c| c == '.' || c == '-' || c == '_').to_string();
    if valid_id(&base) {
        base
    } else {
        "community.addon".into()
    }
}

fn unique_id(app: &App, base: &str) -> String {
    let base = util::truncate_chars(base, 64).to_lowercase();
    let mut base = base.trim_end_matches(|c| c == '.' || c == '-' || c == '_').to_string();
    if !valid_id(&base) {
        base = "community.addon".into();
    }
    let existing: Vec<String> = discover(app).0.iter().map(|s| s.id()).collect();
    let mut candidate = base.clone();
    let mut n = 2;
    while existing.contains(&candidate) || app.paths.extensions_dir.join(&candidate).exists() {
        let suffix = format!("-{}", n);
        let head = util::truncate_chars(&base, 64 - suffix.len());
        candidate = format!("{}{}", head.trim_end_matches(|c| c == '.' || c == '-' || c == '_'), suffix);
        n += 1;
    }
    candidate
}

const STARTER_SCRIPT: &str = r#"(function () {
  const id = '__EXT_ID__';
  const api = window.LiquidDropExtensions;
  if (!api) return;

  function addBanner(message, color) {
    let banner = document.querySelector('[data-addon="' + id + '"]');
    if (!banner) {
      banner = document.createElement('div');
      banner.dataset.addon = id;
      banner.style.cssText = 'margin:12px 0;padding:12px 14px;border-radius:14px;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.12);font-weight:800;color:#fff;';
      const header = document.querySelector('.app-header') || document.body;
      header.appendChild(banner);
    }
    banner.textContent = message;
    banner.style.borderColor = color || 'rgba(110,231,183,.28)';
  }

  async function start() {
    const settings = await api.getSettings(id);
    addBanner(settings.message || 'Hello from my LiquidDrop add-on.', settings.accentColor);

    const shared = await api.getSharedState(id);
    if (api.canManage()) {
      await api.setSharedState(id, {
        lastHostUpdate: new Date().toISOString(),
        visits: Number(shared.visits || 0) + 1
      });
    }
  }

  // Live updates: re-run when the host changes this add-on's settings.
  if (api.on) api.on('settings', (e) => { if (e && e.id === id) start().catch((err) => api.reportError(id, err)); });

  start().catch((error) => api.reportError(id, error));
})();
"#;

pub fn create_scaffold(app: &App, data: &Value) -> Result<(Value, String), String> {
    let empty = json!({});
    let data = if data.is_object() { data } else { &empty };
    let name = plain_string(data.get("name"), "My LiquidDrop Add-on", 80);
    let requested = plain_string(data.get("id"), "", 64).to_lowercase();
    let _g = app.ext_lock.lock();
    let id = unique_id(app, &if valid_id(&requested) { requested } else { id_from_name(&name) });
    let author_default = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "Community Creator".into());
    let author = plain_string(data.get("author"), &author_default, 80);
    let description = plain_string(
        data.get("description"),
        "A community add-on created with the LiquidDrop starter.",
        300,
    );
    let now = util::utc_now_iso();
    let dest = app.paths.extensions_dir.join(&id);
    if dest.exists() {
        return Err("Extension folder already exists.".into());
    }
    fs::create_dir_all(&dest).map_err(|e| e.to_string())?;
    let manifest = json!({
        "id": id, "name": name, "version": "0.1.0", "description": description, "author": author,
        "created_at": now, "updated_at": now, "license": "Creator retains rights", "category": "Community",
        "default_enabled": false, "capabilities": ["Starter", "Cross-device state"],
        "client": {"script": "client.js"},
        "settings_schema": [
            {"key": "message", "label": "Message", "type": "string", "default": "Hello from my LiquidDrop add-on", "help": "Text shown by the starter add-on."},
            {"key": "accentColor", "label": "Accent color", "type": "color", "default": "#6ee7b7", "help": "Border color used by the starter add-on."}
        ],
        "settings_defaults": {"message": "Hello from my LiquidDrop add-on", "accentColor": "#6ee7b7"},
    });
    util::write_json_file(&dest.join("manifest.json"), &manifest).map_err(|e| e.to_string())?;
    fs::write(dest.join("client.js"), STARTER_SCRIPT.replace("__EXT_ID__", &id)).map_err(|e| e.to_string())?;
    let mut state = load_state(app);
    state.insert(
        id.clone(),
        json!({"installed": true, "enabled": false, "settings": Value::Object(manifest_defaults(&manifest)),
               "shared_state": {}, "shared_state_updated_at": ""}),
    );
    save_state(app, &state)?;
    Ok((manifest, dest.display().to_string()))
}

/// Is this add-on's code/data visible to the requester?
pub fn visible(app: &App, id: &str, is_host: bool) -> Option<Source> {
    let _g = app.ext_lock.lock();
    let source = find(app, id)?;
    let state = load_state(app);
    let entry = entry_of(&state, id);
    let installed = entry.get("installed").map(py_truthy).unwrap_or(true);
    let enabled = entry.get("enabled").map(py_truthy).unwrap_or(false);
    if !installed || !(enabled || is_host) {
        return None;
    }
    Some(source)
}

pub fn locate_asset(source: &Source, rel: &str) -> Option<AssetLoc> {
    source.locate(rel)
}

pub fn data_file(app: &App, id: &str, rel: &str) -> Option<PathBuf> {
    if !valid_id(id) {
        return None;
    }
    let rel = safe_relpath(rel)?;
    resolve_in_dir(&app.paths.extension_data.join(id), &rel)
}

pub fn exists(app: &App, id: &str) -> bool {
    let _g = app.ext_lock.lock();
    valid_id(id) && find(app, id).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_paths() {
        assert!(valid_id("liquiddrop.preview"));
        assert!(!valid_id("Bad"));
        assert!(!valid_id(".x"));
        assert_eq!(safe_relpath("/a//b.js").as_deref(), Some("a/b.js"));
        assert_eq!(safe_relpath("../x"), None);
        assert_eq!(safe_relpath(".hidden"), None);
        assert_eq!(id_from_name("My Cool Add-on!"), "community.my-cool-add-on");
    }

    #[test]
    fn coercion() {
        let field = json!({"key": "n", "type": "number", "min": 0.0, "max": 10.0, "default": 5});
        assert_eq!(coerce_setting_value(&field, &json!("42")), json!(10.0));
        let sel = json!({"type": "select", "options": [{"value": "a"}, {"value": "b"}]});
        assert_eq!(coerce_setting_value(&sel, &json!("z")), json!("a"));
        let color = json!({"type": "color", "default": "#123456"});
        assert_eq!(coerce_setting_value(&color, &json!("red")), json!("#123456"));
    }
}
