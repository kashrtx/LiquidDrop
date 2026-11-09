//! Small cached JPEG thumbnails for the file list. v4 made phones download
//! every full-size photo just to draw a 54px preview.

use crate::app::App;
use crate::files;
use crate::web::{self, error_page, not_found, Disposition, Resp, ServeOpts};
use crate::util;
use http::StatusCode;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const SUPPORTED: &[&str] = &["jpg", "jpeg", "jfif", "png", "gif", "webp", "bmp"];
const MAX_SOURCE_BYTES: u64 = 80 * 1024 * 1024;
const THUMB_PX: u32 = 180;

pub fn supported(name: &str) -> bool {
    SUPPORTED.contains(&util::extension_of(name).as_str())
}

fn tiff_orientation(t: &[u8]) -> Option<u16> {
    let le = match t.get(0..2)? {
        b"II" => true,
        b"MM" => false,
        _ => return None,
    };
    let rd16 = |o: usize| -> Option<u16> {
        let b = t.get(o..o + 2)?;
        Some(if le {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        })
    };
    let rd32 = |o: usize| -> Option<u32> {
        let b = t.get(o..o + 4)?;
        Some(if le {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        })
    };
    let ifd = rd32(4)? as usize;
    let count = rd16(ifd)? as usize;
    for k in 0..count.min(256) {
        let e = ifd + 2 + k * 12;
        if rd16(e)? == 0x0112 {
            return rd16(e + 8);
        }
    }
    None
}

/// EXIF orientation (1-8) from a JPEG, defaulting to 1.
pub fn jpeg_orientation(data: &[u8]) -> u16 {
    if data.len() < 4 || data[0] != 0xFF || data[1] != 0xD8 {
        return 1;
    }
    let mut i = 2usize;
    while i + 4 <= data.len() {
        if data[i] != 0xFF {
            return 1;
        }
        let marker = data[i + 1];
        if marker == 0xD8 || marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            i += 2;
            continue;
        }
        if marker == 0xDA || marker == 0xD9 {
            return 1;
        }
        let len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        if len < 2 || i + 2 + len > data.len() {
            return 1;
        }
        if marker == 0xE1 {
            let seg = &data[i + 4..i + 2 + len];
            if seg.len() > 6 && &seg[..6] == b"Exif\0\0" {
                return tiff_orientation(&seg[6..]).unwrap_or(1);
            }
        }
        i += 2 + len;
    }
    1
}

fn make_thumb(src: &Path, dst: &Path) -> Result<(), String> {
    let data = std::fs::read(src).map_err(|e| e.to_string())?;
    let orientation = jpeg_orientation(&data);
    let img = image::load_from_memory(&data).map_err(|e| e.to_string())?;
    let img = match orientation {
        2 => img.fliph(),
        3 => img.rotate180(),
        4 => img.flipv(),
        5 => img.rotate90().fliph(),
        6 => img.rotate90(),
        7 => img.rotate270().fliph(),
        8 => img.rotate270(),
        _ => img,
    };
    let thumb = img.resize_to_fill(THUMB_PX, THUMB_PX, image::imageops::FilterType::Triangle);
    let rgb = if thumb.color().has_alpha() {
        let rgba = thumb.to_rgba8();
        let (w, h) = rgba.dimensions();
        let mut flat = image::RgbImage::new(w, h);
        const BG: [f32; 3] = [30.0, 34.0, 62.0];
        for (x, y, p) in rgba.enumerate_pixels() {
            let a = p[3] as f32 / 255.0;
            let mix = |c: u8, bg: f32| (c as f32 * a + bg * (1.0 - a)).round() as u8;
            flat.put_pixel(x, y, image::Rgb([mix(p[0], BG[0]), mix(p[1], BG[1]), mix(p[2], BG[2])]));
        }
        image::DynamicImage::ImageRgb8(flat)
    } else {
        image::DynamicImage::ImageRgb8(thumb.to_rgb8())
    };
    let mut out = std::io::Cursor::new(Vec::new());
    rgb.write_to(&mut out, image::ImageFormat::Jpeg)
        .map_err(|e| e.to_string())?;
    if let Some(parent) = dst.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    util::write_bytes_atomic(dst, &out.into_inner()).map_err(|e| e.to_string())
}

fn cache_path(app: &App, name: &str, size: u64, mtime: u128) -> PathBuf {
    let digest = Sha256::digest(format!("{}\0{}\0{}", name, size, mtime).as_bytes());
    let key: String = digest.iter().take(16).map(|b| format!("{:02x}", b)).collect();
    app.paths.thumbs.join(format!("{}.jpg", key))
}

/// GET /{token}/thumb/{name}
pub async fn serve(app: &Arc<App>, headers: &http::HeaderMap, name: &str) -> Resp {
    let path = match files::safe_path(&app.paths.root, name) {
        Some(p) => p,
        None => return not_found(),
    };
    if !supported(name) {
        return error_page(StatusCode::UNSUPPORTED_MEDIA_TYPE, "No thumbnail for this type.");
    }
    let meta = match tokio::fs::metadata(&path).await {
        Ok(m) => m,
        Err(_) => return not_found(),
    };
    if meta.len() > MAX_SOURCE_BYTES {
        return error_page(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Image is too large for a thumbnail.");
    }
    let mtime = meta.modified().map(util::system_time_nanos).unwrap_or(0);
    let cache = cache_path(app, name, meta.len(), mtime);
    if !cache.is_file() {
        let _permit = app.thumb_sem.acquire().await.ok();
        if !cache.is_file() {
            let src = path.clone();
            let dst = cache.clone();
            let made = tokio::task::spawn_blocking(move || make_thumb(&src, &dst)).await;
            match made {
                Ok(Ok(())) => {}
                _ => {
                    return error_page(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Thumbnail failed.");
                }
            }
        }
    }
    web::serve_path(
        headers,
        &cache,
        ServeOpts {
            content_type: "image/jpeg",
            cache: "private, max-age=604800",
            disposition: Disposition::None,
            count_download: false,
            sandbox: false,
            max_range_len: None,
        },
        None,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orientation_parsing() {
        // Minimal JPEG: SOI, APP1(Exif, big-endian TIFF, one IFD entry 0x0112 = 6), EOI
        let mut tiff = Vec::new();
        tiff.extend_from_slice(b"MM\x00\x2a\x00\x00\x00\x08");
        tiff.extend_from_slice(&[0x00, 0x01]);
        tiff.extend_from_slice(&[0x01, 0x12, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00]);
        tiff.extend_from_slice(&[0, 0, 0, 0]);
        let mut seg = b"Exif\0\0".to_vec();
        seg.extend_from_slice(&tiff);
        let mut jpg = vec![0xFF, 0xD8, 0xFF, 0xE1];
        jpg.extend_from_slice(&((seg.len() + 2) as u16).to_be_bytes());
        jpg.extend_from_slice(&seg);
        jpg.extend_from_slice(&[0xFF, 0xD9]);
        assert_eq!(jpeg_orientation(&jpg), 6);
        assert_eq!(jpeg_orientation(b"not a jpeg"), 1);
    }
}
