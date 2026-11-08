//! One live connection per device replaces v4's three polling loops. Files
//! appear instantly, the status widget updates without requests, and the
//! extension API can subscribe to changes.

use crate::app::App;
use crate::config::{APP_VERSION, STATUS_CLIENT_TTL_SECS, STATUS_SPEED_WINDOW_SECS};
use crate::files;
use crate::web::{response, set_header, Resp};
use crate::util;
use bytes::Bytes;
use http::StatusCode;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Upload,
    Download,
}

struct StatsInner {
    seen: HashMap<IpAddr, Instant>,
    live: HashMap<IpAddr, usize>,
    buckets: [(u64, u64, u64); 16], // (unix second, up bytes, down bytes)
}

pub struct Stats {
    inner: Mutex<StatsInner>,
}

impl Stats {
    pub fn new() -> Stats {
        Stats {
            inner: Mutex::new(StatsInner {
                seen: HashMap::new(),
                live: HashMap::new(),
                buckets: [(0, 0, 0); 16],
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, StatsInner> {
        match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    pub fn seen(&self, ip: IpAddr) {
        let mut g = self.lock();
        g.seen.insert(ip, Instant::now());
        if g.seen.len() > 128 {
            let ttl = Duration::from_secs(STATUS_CLIENT_TTL_SECS);
            g.seen.retain(|_, t| t.elapsed() <= ttl);
        }
    }

    pub fn live_enter(&self, ip: IpAddr) {
        let mut g = self.lock();
        *g.live.entry(ip).or_insert(0) += 1;
    }

    pub fn live_leave(&self, ip: IpAddr) {
        let mut g = self.lock();
        let remove = match g.live.get_mut(&ip) {
            Some(n) => {
                *n = n.saturating_sub(1);
                *n == 0
            }
            None => false,
        };
        if remove {
            g.live.remove(&ip);
        }
        g.seen.insert(ip, Instant::now());
    }

    pub fn record(&self, kind: Kind, n: u64) {
        if n == 0 {
            return;
        }
        let sec = util::now_secs();
        let mut g = self.lock();
        let idx = (sec % 16) as usize;
        if g.buckets[idx].0 != sec {
            g.buckets[idx] = (sec, 0, 0);
        }
        match kind {
            Kind::Upload => g.buckets[idx].1 += n,
            Kind::Download => g.buckets[idx].2 += n,
        }
    }

    fn devices_locked(g: &StatsInner) -> Vec<IpAddr> {
        let ttl = Duration::from_secs(STATUS_CLIENT_TTL_SECS);
        let mut devices: Vec<IpAddr> = g
            .seen
            .iter()
            .filter(|(_, t)| t.elapsed() <= ttl)
            .map(|(ip, _)| *ip)
            .collect();
        for ip in g.live.keys() {
            if !devices.contains(ip) {
                devices.push(*ip);
            }
        }
        devices
    }

    /// Addresses of devices seen recently or currently connected live.
    pub fn device_ips(&self) -> Vec<IpAddr> {
        let g = self.lock();
        Stats::devices_locked(&g)
    }

    pub fn snapshot(&self) -> Value {
        let now = util::now_secs();
        let g = self.lock();
        let devices = Stats::devices_locked(&g);
        let window = STATUS_SPEED_WINDOW_SECS;
        let mut up = 0u64;
        let mut down = 0u64;
        for (sec, u, d) in g.buckets.iter() {
            if *sec + window > now && *sec <= now {
                up += *u;
                down += *d;
            }
        }
        json!({
            "version": APP_VERSION,
            "active_devices": devices.len(),
            "live_devices": g.live.len(),
            "upload_bps": up / window,
            "download_bps": down / window,
            "window_seconds": window,
        })
    }
}

#[derive(Clone, Debug)]
pub enum LiveEvent {
    Files,
    Status(Arc<String>),
    Settings(String),
    State(String),
    Extensions,
    Network,
    Shutdown,
}

impl LiveEvent {
    fn name(&self) -> &'static str {
        match self {
            LiveEvent::Files => "files",
            LiveEvent::Status(_) => "status",
            LiveEvent::Settings(_) => "settings",
            LiveEvent::State(_) => "state",
            LiveEvent::Extensions => "extensions",
            LiveEvent::Network => "network",
            LiveEvent::Shutdown => "shutdown",
        }
    }

    pub fn to_sse(&self) -> Bytes {
        let data = match self {
            LiveEvent::Status(s) => s.as_str().to_string(),
            LiveEvent::Settings(id) | LiveEvent::State(id) => json!({ "id": id }).to_string(),
            _ => "{}".to_string(),
        };
        Bytes::from(format!("event: {}\ndata: {}\n\n", self.name(), data))
    }
}

pub struct Hub {
    tx: broadcast::Sender<LiveEvent>,
}

impl Hub {
    pub fn new() -> Hub {
        let (tx, _rx) = broadcast::channel(256);
        Hub { tx }
    }

    pub fn send(&self, ev: LiveEvent) {
        let _ = self.tx.send(ev);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<LiveEvent> {
        self.tx.subscribe()
    }

    pub fn listeners(&self) -> usize {
        self.tx.receiver_count()
    }
}

struct LiveGuard {
    app: Arc<App>,
    ip: IpAddr,
}

impl Drop for LiveGuard {
    fn drop(&mut self) {
        self.app.stats.live_leave(self.ip);
    }
}

struct StreamState {
    rx: broadcast::Receiver<LiveEvent>,
    ping: tokio::time::Interval,
    hello: Option<Bytes>,
    done: bool,
    _guard: LiveGuard,
}

fn data_frame(b: Bytes) -> Result<Frame<Bytes>, io::Error> {
    Ok(Frame::data(b))
}

/// GET /{token}/events — a Server-Sent Events stream.
pub fn sse(app: Arc<App>, ip: IpAddr) -> Resp {
    app.stats.live_enter(ip);
    let hello = format!(
        "retry: 2000\nevent: hello\ndata: {}\n\n",
        json!({ "version": APP_VERSION, "status": app.stats.snapshot() })
    );
    let mut ping = tokio::time::interval(Duration::from_secs(15));
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let state = StreamState {
        rx: app.hub.subscribe(),
        ping,
        hello: Some(Bytes::from(hello)),
        done: false,
        _guard: LiveGuard { app: app.clone(), ip },
    };
    let stream = futures_util::stream::unfold(state, |mut st| async move {
        if st.done {
            return None;
        }
        if let Some(h) = st.hello.take() {
            // consume the interval's immediate first tick
            st.ping.tick().await;
            return Some((data_frame(h), st));
        }
        let mut finished = false;
        let out: Option<Bytes> = tokio::select! {
            r = st.rx.recv() => match r {
                Ok(ev) => {
                    if matches!(ev, LiveEvent::Shutdown) {
                        finished = true;
                    }
                    Some(ev.to_sse())
                }
                Err(RecvError::Lagged(_)) => Some(LiveEvent::Files.to_sse()),
                Err(RecvError::Closed) => None,
            },
            _ = st.ping.tick() => Some(Bytes::from_static(b": ping\n\n")),
        };
        if finished {
            st.done = true;
        }
        out.map(|b| (data_frame(b), st))
    });
    let mut r = response(StatusCode::OK, StreamBody::new(stream).boxed_unsync());
    set_header(&mut r, "content-type", "text/event-stream; charset=utf-8");
    set_header(&mut r, "cache-control", "no-cache, no-transform");
    set_header(&mut r, "x-accel-buffering", "no");
    r
}

/// Status ticks, folder watching and network change detection.
pub fn spawn_background(app: Arc<App>) {
    // Status snapshot every 2s, only while someone is listening.
    {
        let app = app.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(2));
            loop {
                t.tick().await;
                if app.hub.listeners() > 0 {
                    let snap = app.stats.snapshot().to_string();
                    app.hub.send(LiveEvent::Status(Arc::new(snap)));
                }
            }
        });
    }
    // Watch the shared folder so files copied in by the desktop show up live.
    {
        let app = app.clone();
        tokio::spawn(async move {
            let mut last: u64 = 0;
            let mut t = tokio::time::interval(Duration::from_millis(1500));
            loop {
                t.tick().await;
                if app.hub.listeners() == 0 {
                    continue;
                }
                let root = app.paths.root.clone();
                let sig = tokio::task::spawn_blocking(move || files::dir_signature(&root))
                    .await
                    .unwrap_or(0);
                if sig != last {
                    if last != 0 {
                        app.hub.send(LiveEvent::Files);
                    }
                    last = sig;
                }
            }
        });
    }
    // Re-check network interfaces (laptop moved to another Wi-Fi, etc.).
    {
        let app = app.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(20));
            t.tick().await;
            loop {
                t.tick().await;
                let app2 = app.clone();
                let _ = tokio::task::spawn_blocking(move || app2.refresh_network(false)).await;
            }
        });
    }
    // Expire old zip download links.
    {
        let app = app.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(60));
            loop {
                t.tick().await;
                app.expire_zip_tickets();
            }
        });
    }
}
