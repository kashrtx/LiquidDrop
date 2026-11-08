//! 💧 LiquidDrop v5 — move files between your phone and computer.
//!
//!   liquiddrop              (HTTP)
//!   liquiddrop --secure     (HTTPS)
//!
//! Scan the QR code or enter the PIN.

#[macro_use]
mod term;

mod app;
mod assets;
mod auth;
mod config;
mod events;
mod extensions;
mod files;
mod instance;
#[cfg(feature = "mdns")]
mod mdns;
mod net;
mod pages;
mod preview;
mod qr;
mod routes;
mod server;
#[cfg(feature = "thumbnails")]
mod thumbs;
mod tls;
#[cfg(all(feature = "tray", any(windows, target_os = "macos")))]
mod tray;
mod upload;
mod util;
mod web;
mod zipstream;

use app::{App, NetState};
use config::{Paths, APP_VERSION, DEFAULT_PORT};
use serde_json::json;
use std::io::IsTerminal;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use term::*;

struct Args {
    secure: bool,
    port: u16,
    new_token: bool,
    dir: Option<PathBuf>,
    open_browser: bool,
    bind: IpAddr,
    verbose: bool,
    tray: bool,
}

const HELP: &str = "💧 LiquidDrop — Local File Transfer

USAGE:
    liquiddrop [OPTIONS]

OPTIONS:
    --secure          Enable HTTPS with a self-signed TLS certificate
    --port <PORT>     Port number (default: 7777)
    --new-token       Generate a new token (invalidates old bookmarks)
    --dir <PATH>      Shared folder (default: ~/LiquidDrop)
    --no-browser      Don't open the browser on start
    --bind <ADDR>     Address to listen on (default: 0.0.0.0)
    --verbose         Log every request
    --no-tray         Don't show the system tray / menu bar icon
    -h, --help        Show this help
    -V, --version     Show the version
";

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        secure: false,
        port: DEFAULT_PORT,
        new_token: false,
        dir: None,
        open_browser: true,
        bind: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        verbose: false,
        tray: std::env::var_os("LIQUIDDROP_NO_TRAY").is_none(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (arg.clone(), None),
        };
        let mut value = |name: &str| -> Result<String, String> {
            match inline.clone() {
                Some(v) => Ok(v),
                None => it.next().ok_or_else(|| format!("{} needs a value", name)),
            }
        };
        match flag.as_str() {
            "--secure" => a.secure = true,
            "--new-token" => a.new_token = true,
            "--no-browser" => a.open_browser = false,
            "--verbose" | "-v" => a.verbose = true,
            "--no-tray" => a.tray = false,
            "--port" | "-p" => {
                a.port = value("--port")?
                    .parse()
                    .map_err(|_| "--port must be a number between 1 and 65535".to_string())?
            }
            "--dir" => a.dir = Some(PathBuf::from(value("--dir")?)),
            "--bind" => {
                a.bind = value("--bind")?
                    .parse()
                    .map_err(|_| "--bind must be an IP address".to_string())?
            }
            "-h" | "--help" => {
                print!("{}", HELP);
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("LiquidDrop {}", APP_VERSION);
                std::process::exit(0);
            }
            // macOS adds this when launched from Finder on older systems
            s if s.starts_with("-psn_") => {}
            other => return Err(format!("Unknown option: {}\n\n{}", other, HELP)),
        }
    }
    Ok(a)
}

fn rule() -> String {
    format!("  {}{}{}", DIM, "─".repeat(50), RESET)
}

fn fail(msg: &str) -> ! {
    say!("\n  {}❌ {}{}", RED, msg, RESET);
    if term::on_terminal() {
        term::pause_if_double_clicked();
    } else {
        term::error_dialog(msg);
    }
    std::process::exit(1);
}

/// Tray mode is available on Windows and macOS builds with the `tray` feature.
fn tray_supported() -> bool {
    cfg!(all(feature = "tray", any(windows, target_os = "macos")))
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(2);
        }
    };

    let root = args.dir.clone().unwrap_or_else(config::default_root);
    let paths = Paths::new(root);
    if let Err(e) = paths.ensure() {
        eprintln!("Could not create {}: {}", paths.root.display(), e);
        term::pause_if_double_clicked();
        std::process::exit(1);
    }

    let use_tray = args.tray && tray_supported();

    // Double-clicked on Windows with the tray available: close the console
    // window and live in the tray. Started from a terminal: keep printing.
    #[allow(unused_mut)]
    let mut detached = false;
    #[cfg(windows)]
    {
        if use_tray && term::owns_console() {
            term::detach_console();
            detached = true;
        }
    }

    // Output: colored terminal, plain terminal, or a log file when there's no console.
    if !detached && std::io::stdout().is_terminal() {
        let color = term::enable_windows_ansi() && std::env::var_os("NO_COLOR").is_none();
        term::init_terminal(color);
        if color {
            print!("\x1b]0;LiquidDrop\x07");
        }
    } else {
        term::init_file(&paths.log_file);
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => fail(&format!("Could not start: {}", e)),
    };

    #[cfg(all(feature = "tray", any(windows, target_os = "macos")))]
    {
        if use_tray {
            // UI must own the main thread (required on macOS); the server runs beside it.
            let (tx, rx) = std::sync::mpsc::channel::<Arc<App>>();
            let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let done_flag = done.clone();
            let spawned = std::thread::Builder::new()
                .name("liquiddrop-server".to_string())
                .spawn(move || {
                    runtime.block_on(run(args, paths, Some(tx)));
                    runtime.shutdown_timeout(Duration::from_millis(300));
                    done_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                });
            if spawned.is_err() {
                fail("Could not start the server thread.");
            }
            tray::run(rx, done);
        }
    }
    let _ = use_tray;

    runtime.block_on(run(args, paths, None));
    // Don't wait for idle keep-alive connections.
    runtime.shutdown_timeout(Duration::from_millis(300));
}

async fn run(args: Args, paths: Paths, tray_tx: Option<std::sync::mpsc::Sender<Arc<App>>>) {
    let mut token = auth::load_or_create_token(&paths.token_file, false);
    let interfaces = net::scan();
    let selected = net::best_ip(&interfaces);
    let scheme = if args.secure { "https" } else { "http" };

    let instance_state = |token: &str, status: &str| {
        json!({
            "pid": std::process::id(),
            "port": args.port,
            "secure": args.secure,
            "token": token,
            "local_ip": selected.to_string(),
            "base_url": format!("{}://{}:{}/{}", scheme, selected, args.port, token),
            "host_url": format!("{}://127.0.0.1:{}/{}", scheme, args.port, token),
            "status": status,
            "version": APP_VERSION,
            "started_at": util::now_secs(),
        })
    };

    match instance::claim(&paths.instance_file, &instance_state(&token, "starting")) {
        instance::Claim::Owned => {}
        instance::Claim::Existing(existing) => {
            let url = existing
                .get("host_url")
                .and_then(|v| v.as_str())
                .or_else(|| existing.get("base_url").and_then(|v| v.as_str()))
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("{}://127.0.0.1:{}/{}", scheme, args.port, token));
            say!("");
            say!("  {}⚠ LiquidDrop is already running. Opening the existing host view...{}", YELLOW, RESET);
            if args.new_token {
                say!("  {}Stop the current session before generating a new token.{}", DIM, RESET);
            }
            say!("  {}{}{}\n", DIM, url, RESET);
            if args.open_browser {
                util::open_in_os(&url);
            }
            tokio::time::sleep(Duration::from_millis(1200)).await;
            return;
        }
    }

    if args.new_token {
        token = auth::load_or_create_token(&paths.token_file, true);
        instance::update(&paths.instance_file, &instance_state(&token, "starting"));
    }
    let pin = auth::generate_pin(&token);

    let header = if args.secure {
        format!("  {}💧 LiquidDrop v{} — Secure Mode (HTTPS){}", BOLD_CYAN, APP_VERSION, RESET)
    } else {
        format!("  {}💧 LiquidDrop v{}{}", BOLD_CYAN, APP_VERSION, RESET)
    };
    say!("");
    say!("{}", header);
    say!("{}\n", rule());

    // TLS
    let mut tls_acceptor = None;
    let mut fingerprint = String::new();
    if args.secure {
        let ips: Vec<IpAddr> = interfaces.iter().map(|i| i.ip).collect();
        match tls::setup(&paths, &ips) {
            Ok(t) => {
                if t.generated {
                    say!("  {}🔒 TLS certificate generated (valid 1 year){}", GREEN, RESET);
                } else {
                    say!("  {}🔒 Reusing existing TLS certificate{}", GREEN, RESET);
                }
                fingerprint = t.fingerprint;
                tls_acceptor = Some(t.acceptor);
            }
            Err(e) => {
                instance::release(&paths.instance_file);
                fail(&format!("Could not set up HTTPS: {}", e));
            }
        }
    }

    // Bind before printing the URLs so port problems are reported clearly.
    let addr = SocketAddr::new(args.bind, args.port);
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            instance::release(&paths.instance_file);
            fail(&format!(
                "Port {} is unavailable ({}). Close the other program or run with --port <number>.",
                args.port, e
            ));
        }
    };

    let net_state = NetState {
        interfaces,
        selected,
        pinned: false,
        host_ips: net::host_ips(),
    };
    let app = Arc::new(App::new(
        paths.clone(),
        args.port,
        args.secure,
        token.clone(),
        pin.clone(),
        fingerprint.clone(),
        args.verbose,
        net_state,
    ));
    instance::update(&paths.instance_file, &instance_state(&token, "running"));
    if let Some(tx) = &tray_tx {
        let _ = tx.send(app.clone());
    }

    {
        let app = app.clone();
        tokio::task::spawn_blocking(move || files::cleanup_stale(&app));
    }

    #[cfg(feature = "mdns")]
    let _mdns = {
        let ips: Vec<IpAddr> = app
            .net
            .read()
            .map(|n| n.interfaces.iter().map(|i| i.ip).collect())
            .unwrap_or_default();
        match mdns::start(&ips, args.port) {
            Some((adv, host)) => {
                if let Ok(mut slot) = app.mdns_host.lock() {
                    *slot = Some(host);
                }
                Some(adv)
            }
            None => None,
        }
    };

    // Banner
    let base_url = app.base_url();
    if let Some(code) = qr::make(&base_url) {
        for line in qr::terminal_lines(&code, term::uses_color()) {
            say!("{}", line);
        }
    }
    say!("");
    say!("{}", rule());
    say!("  {}📱 Scan the QR or open:{}", BOLD_WHITE, RESET);
    say!("  {}   {}{}\n", BOLD_GREEN, base_url, RESET);
    say!("  {}🔑 Or enter PIN:  {}{}{}", BOLD_WHITE, BOLD_YELLOW, pin, RESET);
    say!("  {}   at {}{}", DIM, app.pin_url(), RESET);
    if let Some(m) = app.mdns_url() {
        say!("  {}   or {}{}", DIM, m, RESET);
    }
    say!("");
    if args.secure {
        say!("  {}🔒 HTTPS Enabled — TLS Encrypted{}", BOLD_OK, RESET);
        let (a, b) = fingerprint.split_at(fingerprint.len().min(48));
        say!("  {}   Fingerprint: {}{}", DIM, a, RESET);
        say!("  {}   {}{}\n", DIM, b, RESET);
        say!("  {}   ⚠  First visit: tap Advanced → Proceed{}\n", YELLOW, RESET);
    } else {
        say!("  {}🌐 Protected by secret token + WiFi encryption{}", BOLD_OK, RESET);
        say!("  {}   Add --secure for full HTTPS/TLS encryption{}\n", DIM, RESET);
    }
    say!("  {}Files: {}{}", DIM, paths.root.display(), RESET);
    if tray_tx.is_some() {
        say!("  {}Stop from the LiquidDrop tray icon, the host browser tab, or Ctrl+C.{}", DIM, RESET);
    } else {
        say!("  {}Stop with the button in the host browser tab, or press Ctrl+C here.{}", DIM, RESET);
    }
    say!("  {}URL is stable — bookmarks & home screen shortcuts persist{}", DIM, RESET);
    say!("{}\n", rule());

    events::spawn_background(app.clone());

    {
        let app = app.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                app.request_shutdown(&format!("\n  {}⏹  Shutting down...{}\n", YELLOW, RESET));
            }
        });
    }

    if args.open_browser {
        let url = app.host_url();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(400)).await;
            say!("  {}🌐 Opening browser...{}\n", DIM, RESET);
            util::open_in_os(&url);
        });
    }

    server::run(app.clone(), listener, tls_acceptor).await;

    // Let the "shut down" event and the final responses reach browsers.
    tokio::time::sleep(Duration::from_millis(500)).await;
    instance::release(&paths.instance_file);
    say!("  {}💚 LiquidDrop stopped. See you next time.{}", GREEN, RESET);
}
