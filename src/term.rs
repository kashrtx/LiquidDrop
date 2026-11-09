//! Console output. Colors are used only on a real terminal; when LiquidDrop is
//! launched without one (macOS .app, desktop shortcut) output goes to a log file.

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

pub const RESET: &str = "\x1b[0m";
pub const DIM: &str = "\x1b[90m";
pub const RED: &str = "\x1b[31m";
pub const GREEN: &str = "\x1b[32m";
pub const YELLOW: &str = "\x1b[33m";
pub const CYAN: &str = "\x1b[36m";
pub const BOLD_CYAN: &str = "\x1b[1;96m";
pub const BOLD_WHITE: &str = "\x1b[1;97m";
pub const BOLD_GREEN: &str = "\x1b[1;92m";
pub const BOLD_YELLOW: &str = "\x1b[1;93m";
pub const BOLD_OK: &str = "\x1b[1;32m";

enum Sink {
    Terminal { color: bool },
    File(File),
}

static SINK: OnceLock<Mutex<Sink>> = OnceLock::new();

pub fn init_terminal(color: bool) {
    let _ = SINK.set(Mutex::new(Sink::Terminal { color }));
}

pub fn init_file(path: &Path) {
    let sink = match File::create(path) {
        Ok(f) => Sink::File(f),
        Err(_) => Sink::Terminal { color: false },
    };
    let _ = SINK.set(Mutex::new(sink));
}

/// True when output goes to a console (not a log file).
pub fn on_terminal() -> bool {
    match SINK.get() {
        Some(m) => match m.lock() {
            Ok(g) => matches!(*g, Sink::Terminal { .. }),
            Err(_) => false,
        },
        None => true,
    }
}

pub fn uses_color() -> bool {
    match SINK.get() {
        Some(m) => match m.lock() {
            Ok(g) => matches!(*g, Sink::Terminal { color: true }),
            Err(_) => false,
        },
        None => false,
    }
}

pub fn line(s: &str) {
    let sink = SINK.get_or_init(|| Mutex::new(Sink::Terminal { color: false }));
    let mut guard = match sink.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    match &mut *guard {
        Sink::Terminal { color } => {
            let text = if *color { s.to_string() } else { strip_ansi(s) };
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "{}", text);
            let _ = out.flush();
        }
        Sink::File(f) => {
            let _ = writeln!(f, "{}", strip_ansi(s));
            let _ = f.flush();
        }
    }
}

pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for n in chars.by_ref() {
                    if n.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// Format-and-print helper used everywhere instead of println!.
macro_rules! say {
    ($($arg:tt)*) => {
        $crate::term::line(&format!($($arg)*))
    };
}

/// Turn on ANSI escape processing in the classic Windows console.
#[cfg(windows)]
pub fn enable_windows_ansi() -> bool {
    use core::ffi::c_void;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(n: u32) -> *mut c_void;
        fn GetConsoleMode(h: *mut c_void, mode: *mut u32) -> i32;
        fn SetConsoleMode(h: *mut c_void, mode: u32) -> i32;
    }
    const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5; // (DWORD)-11
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    unsafe {
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        if h.is_null() {
            return false;
        }
        let mut mode: u32 = 0;
        if GetConsoleMode(h, &mut mode) == 0 {
            return false;
        }
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

#[cfg(not(windows))]
pub fn enable_windows_ansi() -> bool {
    true
}

/// True when this process owns its console window (i.e. it was double-clicked
/// on Windows). Used to keep the window open long enough to read errors.
#[cfg(windows)]
pub fn owns_console() -> bool {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetConsoleProcessList(list: *mut u32, count: u32) -> u32;
    }
    let mut pids = [0u32; 4];
    let n = unsafe { GetConsoleProcessList(pids.as_mut_ptr(), 4) };
    n == 1
}

#[cfg(not(windows))]
pub fn owns_console() -> bool {
    false
}

/// Close the console window LiquidDrop was double-clicked with (tray mode).
#[cfg(windows)]
pub fn detach_console() {
    #[link(name = "kernel32")]
    extern "system" {
        fn FreeConsole() -> i32;
    }
    unsafe {
        FreeConsole();
    }
}

/// Native error dialog, used when there is no console to print to.
#[cfg(windows)]
pub fn error_dialog(msg: &str) {
    use core::ffi::c_void;
    #[link(name = "user32")]
    extern "system" {
        fn MessageBoxW(hwnd: *mut c_void, text: *const u16, caption: *const u16, flags: u32) -> i32;
    }
    let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let text = wide(msg);
    let caption = wide("LiquidDrop");
    const MB_OK_ICONERROR_TOPMOST: u32 = 0x0000_0010 | 0x0004_0000;
    unsafe {
        MessageBoxW(core::ptr::null_mut(), text.as_ptr(), caption.as_ptr(), MB_OK_ICONERROR_TOPMOST);
    }
}

#[cfg(target_os = "macos")]
pub fn error_dialog(msg: &str) {
    let escaped = msg.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!(
        "display alert \"LiquidDrop\" message \"{}\" as critical",
        escaped
    );
    let _ = std::process::Command::new("osascript").arg("-e").arg(script).status();
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn error_dialog(_msg: &str) {}

pub fn pause_if_double_clicked() {
    if owns_console() {
        let _ = writeln!(std::io::stdout(), "\n  Press Enter to close...");
        let mut s = String::new();
        let _ = std::io::stdin().read_line(&mut s);
    }
}
