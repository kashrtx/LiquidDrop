//! Picks the address phones should use. Unlike v4 (which only asked the OS
//! for the route to 8.8.8.8) this works offline, on hotspots, and with VPNs or
//! Docker installed, and lets the host switch networks from the web UI.

use serde_json::{json, Value};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};

#[derive(Clone, Debug)]
pub struct Iface {
    pub name: String,
    pub ip: IpAddr,
    pub kind: &'static str,
    pub score: i32,
}

impl Iface {
    pub fn to_json(&self) -> Value {
        json!({"name": self.name, "ip": self.ip.to_string(), "kind": self.kind})
    }
}

/// The address the OS would use for internet traffic (no packets are sent).
pub fn route_ip() -> Option<IpAddr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    let ip = sock.local_addr().ok()?.ip();
    if ip.is_unspecified() || ip.is_loopback() {
        None
    } else {
        Some(ip)
    }
}

fn classify(name: &str) -> &'static str {
    let n = name.to_ascii_lowercase();
    const VIRTUAL_PREFIX: &[&str] = &[
        "docker", "veth", "br-", "virbr", "vbox", "vmnet", "utun", "tun", "tap", "wg", "zt",
        "tailscale", "ham", "lxc", "lxd", "awdl", "llw", "anpi", "gif", "stf", "ppp", "ipsec",
        "nordlynx", "cni", "flannel", "kube", "podman", "vnic",
    ];
    const VIRTUAL_CONTAINS: &[&str] = &[
        "virtual", "vmware", "hyper-v", "vethernet", "docker", "tailscale", "vpn", "wsl",
        "loopback", "bluetooth", "zerotier", "npcap", "teredo", "isatap", "pseudo",
    ];
    if VIRTUAL_PREFIX.iter().any(|p| n.starts_with(p))
        || VIRTUAL_CONTAINS.iter().any(|p| n.contains(p))
    {
        return "virtual";
    }
    if n.starts_with("wl")
        || n.contains("wi-fi")
        || n.contains("wifi")
        || n.contains("wireless")
        || n.contains("wlan")
        || n.contains("802.11")
    {
        return "wifi";
    }
    if n.starts_with("eth") || n.starts_with("en") || n.contains("ethernet") || n.contains("lan") {
        return "ethernet";
    }
    "other"
}

fn v4_score(ip: Ipv4Addr) -> i32 {
    let o = ip.octets();
    if o[0] == 192 && o[1] == 168 {
        30
    } else if o[0] == 10 {
        25
    } else if o[0] == 172 && (16..=31).contains(&o[1]) {
        20
    } else if o[0] == 100 && (64..=127).contains(&o[1]) {
        -20 // carrier-grade NAT / Tailscale
    } else {
        0
    }
}

/// Usable IPv4 interfaces, best first.
pub fn scan() -> Vec<Iface> {
    let route = route_ip();
    let mut out: Vec<Iface> = Vec::new();
    if let Ok(list) = if_addrs::get_if_addrs() {
        for iface in list {
            if iface.is_loopback() {
                continue;
            }
            let ip = iface.ip();
            let v4 = match ip {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => continue,
            };
            if v4.is_link_local() || v4.is_unspecified() {
                continue;
            }
            let kind = classify(&iface.name);
            let mut score = v4_score(v4);
            score += match kind {
                "wifi" => 15,
                "ethernet" => 10,
                "virtual" => -40,
                _ => 0,
            };
            if Some(ip) == route {
                score += 50;
            }
            if out.iter().any(|i| i.ip == ip) {
                continue;
            }
            out.push(Iface {
                name: iface.name.clone(),
                ip,
                kind,
                score,
            });
        }
    }
    if out.is_empty() {
        if let Some(ip) = route {
            out.push(Iface {
                name: "default".to_string(),
                ip,
                kind: "other",
                score: 0,
            });
        }
    }
    out.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.name.cmp(&b.name)));
    out
}

pub fn best_ip(ifaces: &[Iface]) -> IpAddr {
    ifaces
        .first()
        .map(|i| i.ip)
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

/// Every address that belongs to this computer. Requests from these are the
/// "host" and get management controls (same rule as v4).
pub fn host_ips() -> HashSet<IpAddr> {
    let mut set: HashSet<IpAddr> = HashSet::new();
    set.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
    set.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));
    if let Ok(list) = if_addrs::get_if_addrs() {
        for iface in list {
            set.insert(iface.ip());
        }
    }
    if let Some(ip) = route_ip() {
        set.insert(ip);
    }
    set
}

/// Normalise IPv4-mapped IPv6 peers (::ffff:1.2.3.4) to plain IPv4.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}
