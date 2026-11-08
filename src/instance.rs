//! A second launch opens the running session instead of starting a duplicate.

use crate::util;
use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

pub enum Claim {
    Owned,
    Existing(Value),
}

#[cfg(unix)]
fn pid_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(windows)]
fn pid_alive(pid: u32) -> bool {
    use core::ffi::c_void;
    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn GetExitCodeProcess(h: *mut c_void, code: *mut u32) -> i32;
        fn CloseHandle(h: *mut c_void) -> i32;
    }
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const STILL_ACTIVE: u32 = 259;
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return false;
        }
        let mut code: u32 = 0;
        let ok = GetExitCodeProcess(h, &mut code);
        CloseHandle(h);
        ok != 0 && code == STILL_ACTIVE
    }
}

#[cfg(not(any(unix, windows)))]
fn pid_alive(_pid: u32) -> bool {
    true
}

fn port_open(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&addr, Duration::from_millis(400)).is_ok()
}

/// Plain-HTTP probe of the ping endpoint (only meaningful without --secure).
fn ping_ok(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut s = match TcpStream::connect_timeout(&addr, Duration::from_millis(400)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = s.set_read_timeout(Some(Duration::from_millis(800)));
    if s
        .write_all(b"GET /__liquiddrop/ping HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = Vec::new();
    let _ = s.take(4096).read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).contains("liquiddrop")
}

fn alive(v: &Value) -> bool {
    let pid = v.get("pid").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    if pid == 0 || pid == std::process::id() {
        return false;
    }
    let port = v.get("port").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
    let secure = v.get("secure").and_then(|x| x.as_bool()).unwrap_or(false);
    let pid_ok = pid_alive(pid);
    if port == 0 {
        return pid_ok;
    }
    if pid_ok && port_open(port) {
        return true;
    }
    if !pid_ok && !secure && ping_ok(port) {
        return true;
    }
    let status = v.get("status").and_then(|x| x.as_str()).unwrap_or("");
    let started = v.get("started_at").and_then(|x| x.as_u64()).unwrap_or(0);
    pid_ok && status == "starting" && util::now_secs().saturating_sub(started) < 15
}

pub fn claim(path: &Path, state: &Value) -> Claim {
    for _ in 0..3 {
        match OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(mut f) => {
                let _ = f.write_all(state.to_string().as_bytes());
                return Claim::Owned;
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                let existing = util::read_json_file(path).unwrap_or(Value::Null);
                if alive(&existing) {
                    return Claim::Existing(existing);
                }
                if fs::remove_file(path).is_err() {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
            Err(_) => return Claim::Owned,
        }
    }
    let _ = util::write_json_file(path, state);
    Claim::Owned
}

pub fn update(path: &Path, state: &Value) {
    let _ = util::write_json_file(path, state);
}

pub fn release(path: &Path) {
    let mine = util::read_json_file(path)
        .and_then(|v| v.get("pid").and_then(|p| p.as_u64()))
        .map(|p| p as u32 == std::process::id())
        .unwrap_or(false);
    if mine {
        let _ = fs::remove_file(path);
    }
}
