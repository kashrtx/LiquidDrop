//! Files compiled into the binary by build.rs (UI + bundled extensions).

include!(concat!(env!("OUT_DIR"), "/embedded_assets.rs"));

pub fn get(path: &str) -> Option<&'static [u8]> {
    EMBEDDED
        .binary_search_by(|(k, _)| (*k).cmp(path))
        .ok()
        .map(|i| EMBEDDED[i].1)
}

pub fn get_str(path: &str) -> &'static str {
    get(path)
        .and_then(|b| std::str::from_utf8(b).ok())
        .unwrap_or("")
}

/// All embedded keys that start with `prefix`.
pub fn keys_with_prefix(prefix: &str) -> Vec<&'static str> {
    EMBEDDED
        .iter()
        .map(|(k, _)| *k)
        .filter(|k| k.starts_with(prefix))
        .collect()
}
