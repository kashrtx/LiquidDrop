//! HTTPS for --secure. Certificates are generated in-process (no OpenSSL, no
//! Python `cryptography`). Existing v4 certificates are reused so the
//! fingerprint people already trusted stays the same.

use crate::config::Paths;
use crate::util;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_rustls::TlsAcceptor;

pub struct Tls {
    pub acceptor: TlsAcceptor,
    pub fingerprint: String,
    pub generated: bool,
}

fn reusable(cert: &Path, key: &Path, meta: &Path, ips: &[IpAddr]) -> bool {
    if !cert.is_file() || !key.is_file() {
        return false;
    }
    let now = util::now_secs();
    if let Some(m) = util::read_json_file(meta) {
        let not_after = m.get("not_after").and_then(|v| v.as_u64()).unwrap_or(0);
        if not_after <= now + 86_400 {
            return false;
        }
        let covered: HashSet<String> = m
            .get("ips")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        return ips.iter().all(|ip| covered.contains(&ip.to_string()));
    }
    // Certificate made by the Python version: valid for 365 days from creation.
    match fs::metadata(cert).and_then(|m| m.modified()) {
        Ok(t) => util::system_time_secs(t) + 360 * 86_400 > now,
        Err(_) => false,
    }
}

fn generate(cert_path: &Path, key_path: &Path, meta_path: &Path, ips: &[IpAddr]) -> Result<(), String> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, SanType};

    let mut params = CertificateParams::new(vec![
        "localhost".to_string(),
        "liquiddrop.local".to_string(),
    ])
    .map_err(|e| e.to_string())?;
    let mut all_ips: Vec<IpAddr> = vec![
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ];
    for ip in ips {
        if !all_ips.contains(ip) {
            all_ips.push(*ip);
        }
    }
    for ip in &all_ips {
        params.subject_alt_names.push(SanType::IpAddress(*ip));
    }
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "LiquidDrop");
    dn.push(DnType::OrganizationName, "LiquidDrop Local Transfer");
    params.distinguished_name = dn;
    params.is_ca = IsCa::ExplicitNoCa;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(365);

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
    let cert = params.self_signed(&key_pair).map_err(|e| e.to_string())?;

    fs::write(cert_path, cert.pem()).map_err(|e| e.to_string())?;
    fs::write(key_path, key_pair.serialize_pem()).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(key_path, fs::Permissions::from_mode(0o600));
    }
    let meta = json!({
        "generator": "liquiddrop",
        "not_after": util::now_secs() + 365 * 86_400,
        "ips": all_ips.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
    });
    let _ = util::write_json_file(meta_path, &meta);
    Ok(())
}

fn format_fingerprint(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    digest
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn setup(paths: &Paths, ips: &[IpAddr]) -> Result<Tls, String> {
    fs::create_dir_all(&paths.certs).map_err(|e| e.to_string())?;
    let cert_path = paths.certs.join("cert.pem");
    let key_path = paths.certs.join("key.pem");
    let meta_path = paths.certs.join("meta.json");

    let mut generated = false;
    if !reusable(&cert_path, &key_path, &meta_path, ips) {
        generate(&cert_path, &key_path, &meta_path, ips)?;
        generated = true;
    }

    let cert_pem = fs::read(&cert_path).map_err(|e| e.to_string())?;
    let key_pem = fs::read(&key_path).map_err(|e| e.to_string())?;

    let mut cert_reader: &[u8] = &cert_pem;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("certificate: {}", e))?;
    if certs.is_empty() {
        return Err("certificate file is empty".to_string());
    }
    let mut key_reader: &[u8] = &key_pem;
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("private key: {}", e))?
        .ok_or_else(|| "no private key found".to_string())?;

    let fingerprint = format_fingerprint(certs[0].as_ref());

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Tls {
        acceptor: TlsAcceptor::from(Arc::new(config)),
        fingerprint,
        generated,
    })
}
