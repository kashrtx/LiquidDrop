//! System tray (Windows) / menu bar (macOS) icon.
//!
//! The tray owns the main thread (macOS requires UI on the main thread); the
//! server runs on a background thread. The icon appears once the server is
//! up, shows live status, and quitting stops the server cleanly.

use crate::app::App;
use crate::term::{RESET, YELLOW};
use crate::util;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

const ICON_RGBA: &[u8] = include_bytes!("../packaging/tray-64.rgba");
const ICON_SIZE: u32 = 64;

struct Ui {
    tray: TrayIcon,
    status: MenuItem,
    address: MenuItem,
    open: MenuItem,
    copy: MenuItem,
    folder: MenuItem,
    quit: MenuItem,
    tooltip: String,
}

fn build(app: &App) -> Option<Ui> {
    let status = MenuItem::new("LiquidDrop is running", false, None);
    let address = MenuItem::new(app.base_url(), false, None);
    let pin = MenuItem::new(format!("PIN  {}", app.pin), false, None);
    let open = MenuItem::new("Open LiquidDrop", true, None);
    let copy = MenuItem::new("Copy phone link", true, None);
    let folder = MenuItem::new("Open shared folder", true, None);
    let quit = MenuItem::new("Quit LiquidDrop", true, None);

    let menu = Menu::new();
    menu.append_items(&[
        &status,
        &address,
        &pin,
        &PredefinedMenuItem::separator(),
        &open,
        &copy,
        &folder,
        &PredefinedMenuItem::separator(),
        &quit,
    ])
    .ok()?;

    let icon = Icon::from_rgba(ICON_RGBA.to_vec(), ICON_SIZE, ICON_SIZE).ok()?;
    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("LiquidDrop")
        .with_icon(icon)
        .build()
        .ok()?;
    Some(Ui {
        tray,
        status,
        address,
        open,
        copy,
        folder,
        quit,
        tooltip: String::new(),
    })
}

fn refresh(ui: &mut Ui, app: &App) {
    let snap = app.stats.snapshot();
    let others = app
        .stats
        .device_ips()
        .into_iter()
        .filter(|ip| !app.is_host(*ip))
        .count();
    let up = snap.get("upload_bps").and_then(|v| v.as_u64()).unwrap_or(0);
    let down = snap.get("download_bps").and_then(|v| v.as_u64()).unwrap_or(0);
    let status = if others == 0 {
        "Running · waiting for a device".to_string()
    } else if others == 1 {
        "Running · 1 device connected".to_string()
    } else {
        format!("Running · {} devices connected", others)
    };
    let mut tip = format!("LiquidDrop — {}", status.trim_start_matches("Running · "));
    if up > 1024 || down > 1024 {
        tip = format!("{}\n↑ {}  ↓ {}", tip, util::fmt_speed(up), util::fmt_speed(down));
    }
    ui.status.set_text(&status);
    ui.address.set_text(app.base_url());
    if tip != ui.tooltip {
        let _ = ui.tray.set_tooltip(Some(tip.clone()));
        ui.tooltip = tip;
    }
}

/// Runs the tray on the current (main) thread. Never returns.
pub fn run(apps: Receiver<Arc<App>>, done: Arc<AtomicBool>) -> ! {
    #[allow(unused_mut)]
    let mut event_loop = EventLoopBuilder::new().build();
    #[cfg(target_os = "macos")]
    {
        use tao::platform::macos::{ActivationPolicy, EventLoopExtMacOS};
        // Menu bar only: no Dock icon, no app switcher entry.
        event_loop.set_activation_policy(ActivationPolicy::Accessory);
    }

    let mut app: Option<Arc<App>> = None;
    let mut ui: Option<Ui> = None;
    let mut last_refresh = Instant::now();
    let mut quit_requested: Option<Instant> = None;

    event_loop.run(move |_event, _target, control_flow| {
        *control_flow = ControlFlow::WaitUntil(Instant::now() + Duration::from_millis(150));

        if done.load(Ordering::SeqCst) {
            ui = None; // removes the icon before exiting
            *control_flow = ControlFlow::Exit;
            return;
        }
        if let Some(t) = quit_requested {
            // Safety net: never leave a zombie process behind.
            if t.elapsed() > Duration::from_secs(5) {
                std::process::exit(0);
            }
        }
        if app.is_none() {
            if let Ok(a) = apps.try_recv() {
                ui = build(&a);
                if ui.is_none() {
                    say!("  {}Tray icon unavailable; use the browser tab to stop LiquidDrop.{}", YELLOW, RESET);
                }
                app = Some(a);
                last_refresh = Instant::now() - Duration::from_secs(5);
            }
        }
        let (a, u) = match (&app, &mut ui) {
            (Some(a), Some(u)) => (a, u),
            _ => return,
        };
        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            if &ev.id == u.open.id() {
                util::open_in_os(&a.host_url());
            } else if &ev.id == u.copy.id() {
                if util::copy_to_clipboard(&a.base_url()) {
                    u.status.set_text("Phone link copied");
                    last_refresh = Instant::now();
                }
            } else if &ev.id == u.folder.id() {
                util::open_in_os(&a.paths.root.display().to_string());
            } else if &ev.id == u.quit.id() {
                u.status.set_text("Stopping…");
                a.request_shutdown(&format!("  {}⏹  Quit from the tray{}", YELLOW, RESET));
                quit_requested = Some(Instant::now());
            }
        }
        if quit_requested.is_none() && last_refresh.elapsed() >= Duration::from_secs(2) {
            refresh(u, a);
            last_refresh = Instant::now();
        }
    })
}
