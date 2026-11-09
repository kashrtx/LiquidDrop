use crate::auth::PinLimiter;
use crate::config::Paths;
use crate::events::{Hub, LiveEvent, Stats};
use crate::net::{self, Iface};
use crate::qr;
use crate::term::{BOLD_GREEN, DIM, RESET, YELLOW};
use crate::zipstream::ZipTicket;
use bytes::Bytes;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::sync::watch;

pub struct NetState {
    pub interfaces: Vec<Iface>,
    pub selected: IpAddr,
    /// true when the host picked the network by hand (don't auto-switch)
    pub pinned: bool,
    pub host_ips: HashSet<IpAddr>,
}

pub struct App {
    pub paths: Paths,
    pub port: u16,
    pub secure: bool,
    pub token: String,
    pub pin: String,
    pub fingerprint: String,
    pub verbose: bool,
    pub net: RwLock<NetState>,
    pub qr_png: RwLock<Bytes>,
    pub pins: PinLimiter,
    pub stats: Arc<Stats>,
    pub hub: Hub,
    pub ext_lock: Mutex<()>,
    pub upload_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Newest request number per upload. A new request for the same upload
    /// cancels older ones immediately instead of queueing behind them.
    pub upload_gens: Mutex<HashMap<String, Arc<watch::Sender<u64>>>>,
    /// Recently finished uploads (id -> final name, size), for retried "complete" calls.
    pub completed: Mutex<HashMap<String, (String, u64, std::time::Instant)>>,
    pub finalize_lock: tokio::sync::Mutex<()>,
    pub zip_tickets: Mutex<HashMap<String, ZipTicket>>,
    pub shutdown_tx: watch::Sender<bool>,
    pub mdns_host: Mutex<Option<String>>,
    #[cfg(feature = "thumbnails")]
    pub thumb_sem: tokio::sync::Semaphore,
}

impl App {
    pub fn new(
        paths: Paths,
        port: u16,
        secure: bool,
        token: String,
        pin: String,
        fingerprint: String,
        verbose: bool,
        net_state: NetState,
    ) -> App {
        let (shutdown_tx, _rx) = watch::channel(false);
        let app = App {
            paths,
            port,
            secure,
            token,
            pin,
            fingerprint,
            verbose,
            net: RwLock::new(net_state),
            qr_png: RwLock::new(Bytes::new()),
            pins: PinLimiter::new(),
            stats: Arc::new(Stats::new()),
            hub: Hub::new(),
            ext_lock: Mutex::new(()),
            upload_locks: Mutex::new(HashMap::new()),
            completed: Mutex::new(HashMap::new()),
            upload_gens: Mutex::new(HashMap::new()),
            finalize_lock: tokio::sync::Mutex::new(()),
            zip_tickets: Mutex::new(HashMap::new()),
            shutdown_tx,
            mdns_host: Mutex::new(None),
            #[cfg(feature = "thumbnails")]
            thumb_sem: tokio::sync::Semaphore::new(
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(2)
                    .clamp(2, 6),
            ),
        };
        app.regenerate_qr();
        app
    }

    pub fn scheme(&self) -> &'static str {
        if self.secure {
            "https"
        } else {
            "http"
        }
    }

    pub fn selected_ip(&self) -> IpAddr {
        match self.net.read() {
            Ok(n) => n.selected,
            Err(p) => p.into_inner().selected,
        }
    }

    fn host_for_url(ip: IpAddr) -> String {
        match ip {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{}]", v6),
        }
    }

    pub fn base_url(&self) -> String {
        format!(
            "{}://{}:{}/{}",
            self.scheme(),
            App::host_for_url(self.selected_ip()),
            self.port,
            self.token
        )
    }

    pub fn host_url(&self) -> String {
        format!("{}://127.0.0.1:{}/{}", self.scheme(), self.port, self.token)
    }

    pub fn pin_url(&self) -> String {
        format!(
            "{}://{}:{}",
            self.scheme(),
            App::host_for_url(self.selected_ip()),
            self.port
        )
    }

    pub fn mdns_url(&self) -> Option<String> {
        let host = self.mdns_host.lock().ok()?.clone()?;
        Some(format!("{}://{}:{}", self.scheme(), host, self.port))
    }

    pub fn is_host(&self, ip: IpAddr) -> bool {
        if ip.is_loopback() {
            return true;
        }
        match self.net.read() {
            Ok(n) => n.host_ips.contains(&ip),
            Err(_) => false,
        }
    }

    pub fn regenerate_qr(&self) {
        let png = match qr::make(&self.base_url()) {
            Some(q) => qr::png(&q, 10),
            None => Vec::new(),
        };
        if let Ok(mut slot) = self.qr_png.write() {
            *slot = Bytes::from(png);
        }
    }

    pub fn qr_png(&self) -> Bytes {
        match self.qr_png.read() {
            Ok(b) => b.clone(),
            Err(_) => Bytes::new(),
        }
    }

    pub fn network_json(&self) -> serde_json::Value {
        let n = match self.net.read() {
            Ok(n) => n,
            Err(p) => p.into_inner(),
        };
        serde_json::json!({
            "interfaces": n.interfaces.iter().map(|i| i.to_json()).collect::<Vec<_>>(),
            "selected": n.selected.to_string(),
            "pinned": n.pinned,
            "base_url": format!("{}://{}:{}/{}", self.scheme(), App::host_for_url(n.selected), self.port, self.token),
            "pin_url": format!("{}://{}:{}", self.scheme(), App::host_for_url(n.selected), self.port),
            "mdns_url": self.mdns_url(),
        })
    }

    /// Host chose a network in the UI.
    pub fn select_network(&self, ip: IpAddr) -> bool {
        {
            let mut n = match self.net.write() {
                Ok(n) => n,
                Err(p) => p.into_inner(),
            };
            if !n.interfaces.iter().any(|i| i.ip == ip) {
                return false;
            }
            n.selected = ip;
            n.pinned = true;
        }
        self.regenerate_qr();
        say!("  {}📶 Sharing on {} — {}{}", BOLD_GREEN, ip, self.base_url(), RESET);
        self.hub.send(LiveEvent::Network);
        true
    }

    /// Rescan interfaces. Switches automatically if the current address
    /// disappeared (or always on `force`).
    pub fn refresh_network(&self, force: bool) {
        let interfaces = net::scan();
        let host_ips = net::host_ips();
        let mut changed = false;
        let mut address_changed = false;
        {
            let mut n = match self.net.write() {
                Ok(n) => n,
                Err(p) => p.into_inner(),
            };
            let still_there = interfaces.iter().any(|i| i.ip == n.selected);
            let list_changed = interfaces.len() != n.interfaces.len()
                || interfaces.iter().zip(n.interfaces.iter()).any(|(a, b)| a.ip != b.ip);
            if force || !still_there {
                let best = net::best_ip(&interfaces);
                if best != n.selected {
                    n.selected = best;
                    n.pinned = false;
                    changed = true;
                    address_changed = true;
                }
            }
            if list_changed {
                changed = true;
            }
            n.interfaces = interfaces;
            n.host_ips = host_ips;
        }
        if changed {
            if address_changed {
                self.regenerate_qr();
                say!(
                    "  {}📶 Network changed — phones can now use {}{}",
                    YELLOW,
                    self.base_url(),
                    RESET
                );
            }
            self.hub.send(LiveEvent::Network);
        }
    }

    pub fn expire_zip_tickets(&self) {
        if let Ok(mut m) = self.zip_tickets.lock() {
            m.retain(|_, t| t.created.elapsed() < Duration::from_secs(30 * 60));
        }
        if let Ok(mut m) = self.completed.lock() {
            m.retain(|_, (_, _, t)| t.elapsed() < Duration::from_secs(30 * 60));
        }
    }

    pub fn upload_lock(&self, id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut m = match self.upload_locks.lock() {
            Ok(m) => m,
            Err(p) => p.into_inner(),
        };
        m.entry(id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    pub fn forget_upload_lock(&self, id: &str) {
        // The map and the caller's owned guard are the two expected references.
        // Keep the same mutex while other requests hold or wait for it; removing
        // it would let a retry create a second mutex for the same upload.
        if let Ok(mut m) = self.upload_locks.lock() {
            if m.get(id).map(|lock| Arc::strong_count(lock) == 2).unwrap_or(false) {
                m.remove(id);
                if let Ok(mut gens) = self.upload_gens.lock() {
                    gens.remove(id);
                }
            }
        }
    }

    /// Register a new request for this upload. Every older request for the
    /// same upload sees the change and stops at once (see `superseded`).
    pub fn claim_upload(&self, id: &str) -> (u64, watch::Receiver<u64>) {
        let tx = {
            let mut m = match self.upload_gens.lock() {
                Ok(m) => m,
                Err(p) => p.into_inner(),
            };
            m.entry(id.to_string())
                .or_insert_with(|| Arc::new(watch::channel(0u64).0))
                .clone()
        };
        let mut mine = 0u64;
        tx.send_modify(|g| {
            *g += 1;
            mine = *g;
        });
        (mine, tx.subscribe())
    }

    pub fn subscribe_shutdown(&self) -> watch::Receiver<bool> {
        self.shutdown_tx.subscribe()
    }

    pub fn request_shutdown(&self, message: &str) {
        if *self.shutdown_tx.borrow() {
            return;
        }
        if !message.is_empty() {
            say!("{}", message);
        }
        self.hub.send(LiveEvent::Shutdown);
        let _ = self.shutdown_tx.send(true);
    }

    pub fn log_verbose(&self, msg: &str) {
        if self.verbose {
            say!("  {}{}{}", DIM, msg, RESET);
        }
    }
}
