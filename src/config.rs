//! File locations and tuning constants. The folder layout is identical to the
//! Python version so tokens, bookmarks, extensions and settings carry over.

use std::io;
use std::path::PathBuf;

/// Comes from `version` in Cargo.toml, so there is only one place to change it.
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_PORT: u16 = 7777;

pub const CHUNK: usize = 256 * 1024;
pub const MAX_JSON_BODY: usize = 512 * 1024;
pub const MAX_EXTENSION_ASSET: u64 = 64 * 1024 * 1024;
pub const MAX_EXTENSION_SHARED_STATE: usize = 256 * 1024;
pub const MAX_DOCUMENT_PREVIEW: usize = 2 * 1024 * 1024;

pub const PIN_MAX_FAILS: u32 = 5;
pub const PIN_LOCKOUT_SECS: u64 = 60;

pub const STATUS_CLIENT_TTL_SECS: u64 = 120;
pub const STATUS_SPEED_WINDOW_SECS: u64 = 5;

/// Suggested chunk size for resumable uploads (the client may use any size).
pub const UPLOAD_CHUNK_HINT: u64 = 8 * 1024 * 1024;
/// Unfinished uploads older than this are cleaned up at startup.
pub const PARTIAL_MAX_AGE_SECS: u64 = 48 * 3600;

#[derive(Clone, Debug)]
pub struct Paths {
    pub root: PathBuf,
    pub certs: PathBuf,
    pub token_file: PathBuf,
    pub instance_file: PathBuf,
    pub extensions_dir: PathBuf,
    pub extensions_state: PathBuf,
    pub extension_data: PathBuf,
    pub partial: PathBuf,
    pub thumbs: PathBuf,
    pub log_file: PathBuf,
}

impl Paths {
    pub fn new(root: PathBuf) -> Paths {
        Paths {
            certs: root.join(".certs"),
            token_file: root.join(".token"),
            instance_file: root.join(".instance.json"),
            extensions_dir: root.join("extensions"),
            extensions_state: root.join(".extensions.json"),
            extension_data: root.join(".extension-data"),
            partial: root.join(".partial"),
            thumbs: root.join(".thumbs"),
            log_file: root.join(".liquiddrop.log"),
            root,
        }
    }

    pub fn ensure(&self) -> io::Result<()> {
        std::fs::create_dir_all(&self.root)?;
        std::fs::create_dir_all(&self.extensions_dir)?;
        std::fs::create_dir_all(&self.extension_data)?;
        std::fs::create_dir_all(&self.partial)?;
        let _ = std::fs::create_dir_all(&self.thumbs);
        Ok(())
    }
}

pub fn home_dir() -> PathBuf {
    let candidates: &[&str] = if cfg!(windows) {
        &["USERPROFILE", "HOME"]
    } else {
        &["HOME", "USERPROFILE"]
    };
    for key in candidates {
        if let Some(v) = std::env::var_os(key) {
            if !v.is_empty() {
                return PathBuf::from(v);
            }
        }
    }
    PathBuf::from(".")
}

pub fn default_root() -> PathBuf {
    if let Some(v) = std::env::var_os("LIQUIDDROP_DIR") {
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    home_dir().join("LiquidDrop")
}
