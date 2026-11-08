use flate2::write::ZlibEncoder;
use flate2::Compression;
use qrcode::{Color, EcLevel, QrCode};
use std::io::Write;

pub struct Qr {
    pub width: usize,
    dark: Vec<bool>,
}

impl Qr {
    fn is_dark(&self, x: usize, y: usize) -> bool {
        self.dark[y * self.width + x]
    }
}

pub fn make(data: &str) -> Option<Qr> {
    let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::M).ok()?;
    let width = code.width();
    let dark: Vec<bool> = code.to_colors().into_iter().map(|c| c == Color::Dark).collect();
    if dark.len() != width * width {
        return None;
    }
    Some(Qr { width, dark })
}

fn png_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(kind);
    hasher.update(data);
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    out.extend_from_slice(&hasher.finalize().to_be_bytes());
}

/// Grayscale PNG, black modules on white, with a 4-module quiet zone.
pub fn png(qr: &Qr, scale: usize) -> Vec<u8> {
    let border = 4usize;
    let n = qr.width;
    let size = (n + 2 * border) * scale;
    let mut raw: Vec<u8> = Vec::with_capacity((size + 1) * size);
    for y in 0..size {
        raw.push(0); // filter: none
        let my = y / scale;
        for x in 0..size {
            let mx = x / scale;
            let dark = my >= border
                && mx >= border
                && my - border < n
                && mx - border < n
                && qr.is_dark(mx - border, my - border);
            raw.push(if dark { 0 } else { 255 });
        }
    }
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
    let _ = enc.write_all(&raw);
    let idat = enc.finish().unwrap_or_default();

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&(size as u32).to_be_bytes());
    ihdr.extend_from_slice(&(size as u32).to_be_bytes());
    ihdr.extend_from_slice(&[8, 0, 0, 0, 0]); // 8-bit grayscale
    png_chunk(&mut out, b"IHDR", &ihdr);
    png_chunk(&mut out, b"IDAT", &idat);
    png_chunk(&mut out, b"IEND", &[]);
    out
}

/// Half-block terminal rendering. Colors are forced (white on black) so it
/// scans correctly on both light and dark terminal themes.
pub fn terminal_lines(qr: &Qr, color: bool) -> Vec<String> {
    let border = 2usize;
    let n = qr.width;
    let total = n + 2 * border;
    let light = |x: usize, y: usize| -> bool {
        if x < border || y < border || x >= border + n || y >= border + n {
            true
        } else {
            !qr.is_dark(x - border, y - border)
        }
    };
    let mut lines = Vec::new();
    let mut y = 0;
    while y < total {
        let mut s = String::from("  ");
        if color {
            s.push_str("\x1b[97;40m");
        }
        for x in 0..total {
            let top = light(x, y);
            let bottom = if y + 1 < total { light(x, y + 1) } else { false };
            s.push(match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        if color {
            s.push_str("\x1b[0m");
        }
        lines.push(s);
        y += 2;
    }
    lines
}
