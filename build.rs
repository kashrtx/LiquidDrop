//! Embeds everything in `ui/` and `assets/extensions/` into the executable so
//! LiquidDrop ships as a single file. Optional vendor files (pdf.js) placed in
//! `ui/vendor/` by `scripts/fetch-vendor.*` are picked up automatically.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn collect(base: &Path, dir: &Path, prefix: &str, out: &mut Vec<(String, String)>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            collect(base, &path, prefix, out);
        } else if path.is_file() {
            let rel = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .components()
                .map(|c| c.as_os_str().to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join("/");
            println!("cargo:rerun-if-changed={}", path.display());
            out.push((format!("{}/{}", prefix, rel), path.display().to_string()));
        }
    }
}

fn main() {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let out_file = PathBuf::from(env::var("OUT_DIR").expect("out dir")).join("embedded_assets.rs");

    let mut entries: Vec<(String, String)> = Vec::new();
    for (prefix, dir) in [
        ("ui", root.join("ui")),
        ("extensions", root.join("assets").join("extensions")),
    ] {
        println!("cargo:rerun-if-changed={}", dir.display());
        collect(&dir, &dir, prefix, &mut entries);
    }
    entries.sort();

    // Build id: hash of everything embedded + the version. Open pages compare
    // it with the server's and reload themselves after an update.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |bytes: &[u8]| {
        for b in bytes {
            h ^= *b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    feed(env::var("CARGO_PKG_VERSION").unwrap_or_default().as_bytes());
    for (key, path) in &entries {
        feed(key.as_bytes());
        feed(&fs::read(path).unwrap_or_default());
    }
    println!("cargo:rustc-env=LIQUIDDROP_BUILD_ID={:016x}", h);

    let mut code = String::from("pub static EMBEDDED: &[(&str, &[u8])] = &[\n");
    for (key, path) in &entries {
        code.push_str(&format!("    ({:?}, include_bytes!({:?})),\n", key, path));
    }
    code.push_str("];\n");
    fs::write(&out_file, code).expect("write embedded asset table");

    println!("cargo:rerun-if-changed=packaging/app.ico");
    #[cfg(windows)]
    {
        if env::var("CARGO_CFG_TARGET_OS").map(|v| v == "windows").unwrap_or(false) {
            let mut res = winresource::WindowsResource::new();
            res.set_icon("packaging/app.ico");
            res.set("ProductName", "LiquidDrop");
            res.set("FileDescription", "LiquidDrop - local file transfer");
            if let Err(e) = res.compile() {
                println!("cargo:warning=Could not embed the Windows icon: {}", e);
            }
        }
    }
}
