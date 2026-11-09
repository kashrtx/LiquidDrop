//! Advertises `liquiddrop.local` so devices can type a name instead of an IP.
//! Works out of the box on iPhone, iPad, Mac and Windows 10+; Android support
//! varies by version, so the QR code always uses the IP address.

use std::collections::HashMap;
use std::net::IpAddr;

pub struct Advertiser {
    _daemon: mdns_sd::ServiceDaemon,
}

pub fn start(ips: &[IpAddr], port: u16) -> Option<(Advertiser, String)> {
    let v4: Vec<String> = ips
        .iter()
        .filter(|ip| ip.is_ipv4() && !ip.is_loopback())
        .map(|ip| ip.to_string())
        .collect();
    if v4.is_empty() {
        return None;
    }
    let daemon = mdns_sd::ServiceDaemon::new().ok()?;
    let host = "liquiddrop.local.";
    let mut props: HashMap<String, String> = HashMap::new();
    props.insert("path".to_string(), "/".to_string());
    let joined = v4.join(",");
    let info = mdns_sd::ServiceInfo::new(
        "_http._tcp.local.",
        "LiquidDrop",
        host,
        joined.as_str(),
        port,
        props,
    )
    .ok()?;
    daemon.register(info).ok()?;
    Some((Advertiser { _daemon: daemon }, "liquiddrop.local".to_string()))
}
