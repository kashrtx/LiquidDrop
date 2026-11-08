use crate::config::{PIN_LOCKOUT_SECS, PIN_MAX_FAILS};
use crate::util;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Load the saved token (shared with the Python version) or create one.
pub fn load_or_create_token(path: &Path, force_new: bool) -> String {
    if !force_new {
        if let Ok(raw) = fs::read_to_string(path) {
            let token = raw.trim().to_string();
            if token.len() >= 8 && token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return token;
            }
        }
    }
    let token = util::token_urlsafe(8);
    let _ = fs::write(path, &token);
    token
}

/// Stable 4-digit PIN derived from the token (same formula as v4).
pub fn generate_pin(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    format!("{:04}", n % 10_000)
}

pub struct PinLimiter {
    fails: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl PinLimiter {
    pub fn new() -> PinLimiter {
        PinLimiter {
            fails: Mutex::new(HashMap::new()),
        }
    }

    pub fn is_locked(&self, ip: IpAddr) -> bool {
        let mut map = match self.fails.lock() {
            Ok(m) => m,
            Err(p) => p.into_inner(),
        };
        let expired = match map.get(&ip) {
            None => return false,
            Some((count, last)) => {
                if *count < PIN_MAX_FAILS {
                    return false;
                }
                last.elapsed() >= Duration::from_secs(PIN_LOCKOUT_SECS)
            }
        };
        if expired {
            map.remove(&ip);
            false
        } else {
            true
        }
    }

    pub fn record_fail(&self, ip: IpAddr) {
        let mut map = match self.fails.lock() {
            Ok(m) => m,
            Err(p) => p.into_inner(),
        };
        if map.len() > 4096 {
            map.retain(|_, (_, t)| t.elapsed() < Duration::from_secs(PIN_LOCKOUT_SECS));
        }
        let entry = map.entry(ip).or_insert((0, Instant::now()));
        entry.0 += 1;
        entry.1 = Instant::now();
    }

    pub fn clear(&self, ip: IpAddr) {
        if let Ok(mut map) = self.fails.lock() {
            map.remove(&ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_matches_python_formula() {
        // python: str(int(sha256(b"abcdefgh").hexdigest()[:8], 16) % 10000).zfill(4)
        assert_eq!(generate_pin("abcdefgh"), "4097");
    }
}
