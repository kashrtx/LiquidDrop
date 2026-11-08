//! Black-box tests: start the real binary on a random port with a temporary
//! folder and talk raw HTTP to it. Run with `cargo test --release`.

use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Server {
    child: Child,
    port: u16,
    dir: PathBuf,
    token: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn start(tag: &str) -> Server {
    // Tests run in parallel, so two servers can be handed the same "free"
    // port. Verify we reached *our* server (via its own token) and retry
    // with a new port if another test got there first.
    let dir = std::env::temp_dir().join(format!("liquiddrop-test-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for _attempt in 0..8 {
        let port = free_port();
        let mut child = Command::new(env!("CARGO_BIN_EXE_liquiddrop"))
            .args(["--no-browser", "--no-tray", "--bind", "127.0.0.1", "--port", &port.to_string(), "--dir"])
            .arg(&dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn liquiddrop");
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Ok(Some(_)) = child.try_wait() {
                break; // exited (port taken): try another port
            }
            if let Ok(raw) = std::fs::read_to_string(dir.join(".token")) {
                let token = raw.trim().to_string();
                if !token.is_empty() && TcpStream::connect(("127.0.0.1", port)).is_ok() {
                    match try_request(port, "GET", &format!("/{}/status", token), &[], b"") {
                        Some(r) if r.status == 200 => return Server { child, port, dir, token },
                        Some(r) if r.status == 403 => break, // another test's server has this port
                        _ => {}
                    }
                }
            }
            assert!(Instant::now() < deadline, "server did not start");
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_file(dir.join(".instance.json"));
    }
    panic!("could not start a test server");
}

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("json body")
    }
}

fn dechunk(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let line_end = match data.windows(2).position(|w| w == b"\r\n") {
            Some(i) => i,
            None => return out,
        };
        let size_str = String::from_utf8_lossy(&data[..line_end]).to_string();
        let size = usize::from_str_radix(size_str.split(';').next().unwrap().trim(), 16).unwrap_or(0);
        data = &data[line_end + 2..];
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

fn try_request(port: u16, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Option<Resp> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(20))).ok()?;
    let mut req = format!("{} {} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\n", method, path, body.len());
    for (k, v) in headers {
        req.push_str(&format!("{}: {}\r\n", k, v));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).ok()?;
    s.write_all(body).ok()?;
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut lines = head.split("\r\n");
    let status: u16 = lines.next()?.split(' ').nth(1)?.parse().ok()?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .collect();
    let mut body = raw[split + 4..].to_vec();
    let chunked = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.contains("chunked"));
    if chunked {
        body = dechunk(&body);
    }
    Some(Resp { status, headers, body })
}

fn request(port: u16, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Resp {
    try_request(port, method, path, headers, body).expect("valid HTTP response")
}

fn get(srv: &Server, path: &str) -> Resp {
    request(srv.port, "GET", path, &[], b"")
}

fn post_json(srv: &Server, path: &str, v: serde_json::Value) -> Resp {
    request(srv.port, "POST", path, &[("Content-Type", "application/json")], v.to_string().as_bytes())
}

fn pin_for(token: &str) -> String {
    let d = Sha256::digest(token.as_bytes());
    format!("{:04}", u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 10_000)
}

fn upload(srv: &Server, name: &str, data: &[u8]) -> String {
    let t = &srv.token;
    let id = format!("test-{}", data.len() + name.len() * 7919);
    let r = post_json(srv, &format!("/{}/uploads", t), serde_json::json!({"id": id, "name": name, "size": data.len()}));
    assert_eq!(r.status, 200, "{}", r.text());
    let r = request(srv.port, "PUT", &format!("/{}/uploads/{}?offset=0", t, id), &[], data);
    assert_eq!(r.status, 200, "{}", r.text());
    let r = request(srv.port, "POST", &format!("/{}/uploads/{}/complete", t, id), &[], b"");
    assert_eq!(r.status, 200, "{}", r.text());
    r.json()["name"].as_str().unwrap().to_string()
}

#[test]
fn pin_page_and_token_gate() {
    let srv = start("pin");
    let r = get(&srv, "/");
    assert_eq!(r.status, 200);
    assert!(r.text().contains("pinForm"));
    assert_eq!(get(&srv, "/not-the-token/files").status, 403);

    let pin = pin_for(&srv.token);
    let wrong = if pin == "0000" { "1111" } else { "0000" };
    let form = |p: &str| {
        let c: Vec<char> = p.chars().collect();
        format!("d1={}&d2={}&d3={}&d4={}", c[0], c[1], c[2], c[3])
    };
    let headers = [("Content-Type", "application/x-www-form-urlencoded")];
    let r = request(srv.port, "POST", "/pin", &headers, form(wrong).as_bytes());
    assert!(r.text().contains("Wrong PIN"));
    let r = request(srv.port, "POST", "/pin", &headers, form(&pin).as_bytes());
    assert_eq!(r.status, 302);
    assert_eq!(r.header("location"), Some(format!("/{}/", srv.token).as_str()));

    let page = get(&srv, &format!("/{}/", srv.token));
    assert_eq!(page.status, 200);
    let html = page.text();
    assert!(html.contains("host-view"), "requests from this machine get the host view");
    assert!(!html.contains("{{"), "all template placeholders filled");
    assert!(!html.contains("jszip"), "no CDN zip library");
}

#[test]
fn resumable_upload_range_download_and_delete() {
    let srv = start("upload");
    let t = srv.token.clone();
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let name = "照片 🎉.bin";

    let id = "resume-test-0001";
    let r = post_json(&srv, &format!("/{}/uploads", t), serde_json::json!({"id": id, "name": name, "size": data.len()}));
    assert_eq!(r.json()["offset"], 0);
    // first part, then "lose the connection", ask where we are, continue
    let r = request(srv.port, "PUT", &format!("/{}/uploads/{}?offset=0", t, id), &[], &data[..100_000]);
    assert_eq!(r.json()["offset"], 100_000);
    assert_eq!(get(&srv, &format!("/{}/files", t)).json().as_array().unwrap().len(), 0, "partial uploads stay hidden");
    let r = get(&srv, &format!("/{}/uploads/{}", t, id));
    assert_eq!(r.json()["offset"], 100_000);
    let r = request(srv.port, "PUT", &format!("/{}/uploads/{}?offset=999999", t, id), &[], b"x");
    assert_eq!(r.status, 409, "offset beyond what the server has is rejected");
    let r = request(srv.port, "PUT", &format!("/{}/uploads/{}?offset=100000", t, id), &[], &data[100_000..]);
    assert_eq!(r.json()["offset"], 300_000);
    let r = request(srv.port, "POST", &format!("/{}/uploads/{}/complete", t, id), &[], b"");
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json()["name"], name);

    let files = get(&srv, &format!("/{}/files", t)).json();
    assert_eq!(files[0]["name"], name);
    assert_eq!(files[0]["size"], 300_000);

    let enc = "%E7%85%A7%E7%89%87%20%F0%9F%8E%89.bin";
    let full = get(&srv, &format!("/{}/download/{}", t, enc));
    assert_eq!(full.status, 200);
    assert_eq!(full.body, data);
    assert!(full.header("content-disposition").unwrap().contains("filename*=UTF-8''"));
    assert_eq!(full.header("accept-ranges"), Some("bytes"));

    let part = request(srv.port, "GET", &format!("/{}/download/{}", t, enc), &[("Range", "bytes=1000-1999")], b"");
    assert_eq!(part.status, 206);
    assert_eq!(part.body, &data[1000..2000]);
    assert_eq!(part.header("content-range"), Some("bytes 1000-1999/300000"));
    let bad = request(srv.port, "GET", &format!("/{}/download/{}", t, enc), &[("Range", "bytes=500000-")], b"");
    assert_eq!(bad.status, 416);

    // same name again -> "name (1).ext", never overwritten
    let second = upload(&srv, name, b"second");
    assert_eq!(second, "照片 🎉 (1).bin");

    let r = request(srv.port, "DELETE", &format!("/{}/delete/{}", t, enc), &[], b"");
    assert_eq!(r.status, 200);
    assert_eq!(get(&srv, &format!("/{}/files", t)).json().as_array().unwrap().len(), 1);
}

#[test]
fn legacy_multipart_upload_still_works() {
    let srv = start("multipart");
    let boundary = "----LiquidDropTest";
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"hello.txt\"\r\nContent-Type: text/plain\r\n\r\n", boundary).as_bytes());
    body.extend_from_slice(b"hello\r\n--not-the-boundary\r\nworld");
    body.extend_from_slice(format!("\r\n--{}--\r\n", boundary).as_bytes());
    let ct = format!("multipart/form-data; boundary={}", boundary);
    let r = request(srv.port, "POST", &format!("/{}/upload", srv.token), &[("Content-Type", &ct)], &body);
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json()["count"], 1);
    let got = std::fs::read(srv.dir.join("hello.txt")).unwrap();
    assert_eq!(got, b"hello\r\n--not-the-boundary\r\nworld");
}

#[test]
fn zip_download_is_valid_and_sized() {
    let srv = start("zip");
    upload(&srv, "a.txt", b"alpha");
    upload(&srv, "b.txt", b"bravo!!");
    let r = post_json(&srv, &format!("/{}/zip-ticket", srv.token), serde_json::json!({"names": ["a.txt", "b.txt", "missing.txt"]}));
    assert_eq!(r.status, 200, "{}", r.text());
    let t = r.json();
    assert_eq!(t["count"], 2);
    let z = get(&srv, t["url"].as_str().unwrap());
    assert_eq!(z.status, 200);
    assert_eq!(z.body.len() as u64, t["size"].as_u64().unwrap());
    assert_eq!(z.header("content-length").unwrap(), z.body.len().to_string());
    let eocd = &z.body[z.body.len() - 22..];
    assert_eq!(&eocd[..4], &[0x50, 0x4b, 0x05, 0x06]);
    assert_eq!(u16::from_le_bytes([eocd[10], eocd[11]]), 2);
}

#[test]
fn traversal_and_hidden_files_are_blocked() {
    let srv = start("safety");
    let t = &srv.token;
    for p in ["..%2F..%2Fetc%2Fpasswd", ".token", "%2E%2Etoken", "..%5C.token", ".instance.json"] {
        let r = get(&srv, &format!("/{}/download/{}", t, p));
        assert_eq!(r.status, 404, "{}", p);
    }
}

#[test]
fn extensions_and_previews() {
    let srv = start("ext");
    let t = &srv.token;
    let list = get(&srv, &format!("/{}/extensions", t)).json();
    assert_eq!(list["can_manage"], true);
    let ids: Vec<String> = list["extensions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].as_str().unwrap().to_string())
        .collect();
    for id in ["liquiddrop.background", "liquiddrop.preview", "liquiddrop.status-strip"] {
        assert!(ids.contains(&id.to_string()), "{} bundled", id);
    }
    let r = post_json(
        &srv,
        &format!("/{}/extensions/liquiddrop.status-strip/settings", t),
        serde_json::json!({"settings": {"accentColor": "#112233", "latitude": "999"}}),
    );
    assert_eq!(r.status, 200, "{}", r.text());
    let s = get(&srv, &format!("/{}/extensions/liquiddrop.status-strip/settings", t)).json();
    assert_eq!(s["settings"]["accentColor"], "#112233");
    assert_eq!(s["settings"]["latitude"], 90.0, "numbers are clamped to the schema");
    let script = get(&srv, &format!("/{}/extension-assets/liquiddrop.preview/client.js", t));
    assert_eq!(script.status, 200);
    assert!(script.header("content-type").unwrap().contains("javascript"));

    upload(&srv, "notes.md", b"# Hi\r\nthere");
    let p = get(&srv, &format!("/{}/document-preview/notes.md", t)).json();
    assert_eq!(p["text"], "# Hi\nthere");
    let html = upload(&srv, "page.html", b"<script>alert(1)</script>");
    let r = get(&srv, &format!("/{}/preview/{}", t, html));
    assert_eq!(r.header("content-security-policy"), Some("sandbox"));
}

#[test]
fn live_events_and_shutdown() {
    let mut srv = start("live");
    let mut s = TcpStream::connect(("127.0.0.1", srv.port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(format!("GET /{}/events HTTP/1.1\r\nHost: x\r\n\r\n", srv.token).as_bytes()).unwrap();
    let mut buf = vec![0u8; 4096];
    let n = s.read(&mut buf).unwrap();
    let text = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(text.contains("text/event-stream"), "{}", text);

    let r = request(srv.port, "POST", &format!("/{}/shutdown", srv.token), &[], b"");
    assert_eq!(r.status, 200);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(Some(_)) = srv.child.try_wait() {
            break;
        }
        assert!(Instant::now() < deadline, "server did not exit after shutdown");
        std::thread::sleep(Duration::from_millis(100));
    }
}
