//! Streaming ZIP for "download selected" and "bundle as zip".
//!
//! Files are stored without compression (photos/videos are already
//! compressed), so the archive starts streaming instantly, uses no memory on
//! the phone, and its exact size is known up front (real progress bars).
//! Layout: UTF-8 names, data descriptors, Unix timestamp extra field, and
//! ZIP64 records when anything crosses 4 GiB. The byte layout was validated
//! against Info-ZIP `unzip -t` and Python's `zipfile`, including >4 GiB.

use std::io;
use std::path::PathBuf;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

const U32_MAX: u64 = 0xFFFF_FFFF;
const FLAGS: u16 = 0x0808; // bit 3: data descriptor, bit 11: UTF-8 names
const MADE_BY: u16 = (3 << 8) | 45; // Unix, spec 4.5

#[derive(Clone, Debug)]
pub struct ZipEntry {
    pub name: String,
    pub path: PathBuf,
    pub size: u64,
    pub mtime: u64,
}

pub struct ZipTicket {
    pub names: Vec<String>,
    pub filename: String,
    pub created: Instant,
}

fn central_extra_len(size: u64, offset: u64) -> u64 {
    let mut fields = 0u64;
    if size >= U32_MAX {
        fields += 2;
    }
    if offset >= U32_MAX {
        fields += 1;
    }
    9 + if fields > 0 { 4 + 8 * fields } else { 0 }
}

/// Exact number of bytes `write_zip` will produce.
pub fn total_size(entries: &[ZipEntry]) -> u64 {
    let mut offset = 0u64;
    let mut cd = 0u64;
    for e in entries {
        let n = e.name.as_bytes().len() as u64;
        let big = e.size >= U32_MAX;
        let local = 30 + n + 9;
        let desc = if big { 24 } else { 16 };
        cd += 46 + n + central_extra_len(e.size, offset);
        offset += local + e.size + desc;
    }
    let count = entries.len() as u64;
    let needs64 = count >= 0xFFFF || cd >= U32_MAX || offset >= U32_MAX;
    offset + cd + if needs64 { 56 + 20 } else { 0 } + 22
}

fn put16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn put32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn put64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn ut_extra(v: &mut Vec<u8>, mtime: u64) {
    put16(v, 0x5455);
    put16(v, 5);
    v.push(1);
    put32(v, mtime.min(U32_MAX) as u32);
}

struct Written {
    name: Vec<u8>,
    size: u64,
    mtime: u64,
    crc: u32,
    offset: u64,
    time: u16,
    date: u16,
}

/// Write the archive. `progress` receives byte counts as file data is sent.
pub async fn write_zip<W: AsyncWrite + Unpin>(
    entries: &[ZipEntry],
    w: &mut W,
    mut progress: impl FnMut(u64),
) -> io::Result<()> {
    let mut offset = 0u64;
    let mut written: Vec<Written> = Vec::with_capacity(entries.len());
    let mut buf = vec![0u8; 256 * 1024];

    for e in entries {
        let name = e.name.as_bytes().to_vec();
        let big = e.size >= U32_MAX;
        let (time, date) = crate::util::dos_datetime(e.mtime);

        let mut h: Vec<u8> = Vec::with_capacity(30 + name.len() + 9);
        put32(&mut h, 0x0403_4b50);
        put16(&mut h, if big { 45 } else { 20 });
        put16(&mut h, FLAGS);
        put16(&mut h, 0); // stored
        put16(&mut h, time);
        put16(&mut h, date);
        put32(&mut h, 0); // crc (in descriptor)
        put32(&mut h, 0); // compressed size
        put32(&mut h, 0); // uncompressed size
        put16(&mut h, name.len() as u16);
        put16(&mut h, 9);
        h.extend_from_slice(&name);
        ut_extra(&mut h, e.mtime);
        w.write_all(&h).await?;

        let mut file = if e.name.ends_with('/') { None } else { Some(tokio::fs::File::open(&e.path).await?) };
        let mut hasher = crc32fast::Hasher::new();
        let mut left = e.size;
        while left > 0 {
            let want = (buf.len() as u64).min(left) as usize;
            let n = file.as_mut().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Directory has data"))?.read(&mut buf[..want]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("{} changed while zipping", e.name),
                ));
            }
            hasher.update(&buf[..n]);
            w.write_all(&buf[..n]).await?;
            progress(n as u64);
            left -= n as u64;
        }
        let crc = hasher.finalize();

        let mut d: Vec<u8> = Vec::with_capacity(24);
        put32(&mut d, 0x0807_4b50);
        put32(&mut d, crc);
        if big {
            put64(&mut d, e.size);
            put64(&mut d, e.size);
        } else {
            put32(&mut d, e.size as u32);
            put32(&mut d, e.size as u32);
        }
        w.write_all(&d).await?;

        let local_len = h.len() as u64;
        let desc_len = d.len() as u64;
        written.push(Written {
            name,
            size: e.size,
            mtime: e.mtime,
            crc,
            offset,
            time,
            date,
        });
        offset += local_len + e.size + desc_len;
    }

    let cd_start = offset;
    let mut cd: Vec<u8> = Vec::new();
    for e in &written {
        let big = e.size >= U32_MAX;
        let big_off = e.offset >= U32_MAX;
        let mut z: Vec<u8> = Vec::new();
        if big {
            put64(&mut z, e.size);
            put64(&mut z, e.size);
        }
        if big_off {
            put64(&mut z, e.offset);
        }
        let mut extra: Vec<u8> = Vec::new();
        ut_extra(&mut extra, e.mtime);
        if !z.is_empty() {
            put16(&mut extra, 0x0001);
            put16(&mut extra, z.len() as u16);
            extra.extend_from_slice(&z);
        }
        put32(&mut cd, 0x0201_4b50);
        put16(&mut cd, MADE_BY);
        put16(&mut cd, if big || big_off { 45 } else { 20 });
        put16(&mut cd, FLAGS);
        put16(&mut cd, 0);
        put16(&mut cd, e.time);
        put16(&mut cd, e.date);
        put32(&mut cd, e.crc);
        put32(&mut cd, if big { U32_MAX as u32 } else { e.size as u32 });
        put32(&mut cd, if big { U32_MAX as u32 } else { e.size as u32 });
        put16(&mut cd, e.name.len() as u16);
        put16(&mut cd, extra.len() as u16);
        put16(&mut cd, 0); // comment
        put16(&mut cd, 0); // disk
        put16(&mut cd, 0); // internal attrs
        put32(&mut cd, if e.name.ends_with(b"/") { (0o040755u32 << 16) | 0x10 } else { 0o100644u32 << 16 }); // external attrs: regular file rw-r--r--
        put32(&mut cd, if big_off { U32_MAX as u32 } else { e.offset as u32 });
        cd.extend_from_slice(&e.name);
        cd.extend_from_slice(&extra);
        if cd.len() > 1 << 20 {
            w.write_all(&cd).await?;
            offset += cd.len() as u64;
            cd.clear();
        }
    }
    offset += cd.len() as u64;
    w.write_all(&cd).await?;
    let cd_size = offset - cd_start;
    let count = written.len() as u64;
    let needs64 = count >= 0xFFFF || cd_size >= U32_MAX || cd_start >= U32_MAX;

    let mut end: Vec<u8> = Vec::new();
    if needs64 {
        let z64_offset = cd_start + cd_size;
        put32(&mut end, 0x0606_4b50);
        put64(&mut end, 44);
        put16(&mut end, MADE_BY);
        put16(&mut end, 45);
        put32(&mut end, 0);
        put32(&mut end, 0);
        put64(&mut end, count);
        put64(&mut end, count);
        put64(&mut end, cd_size);
        put64(&mut end, cd_start);
        put32(&mut end, 0x0706_4b50);
        put32(&mut end, 0);
        put64(&mut end, z64_offset);
        put32(&mut end, 1);
    }
    put32(&mut end, 0x0605_4b50);
    put16(&mut end, 0);
    put16(&mut end, 0);
    put16(&mut end, count.min(0xFFFF) as u16);
    put16(&mut end, count.min(0xFFFF) as u16);
    put32(&mut end, cd_size.min(U32_MAX) as u32);
    put32(&mut end, cd_start.min(U32_MAX) as u32);
    put16(&mut end, 0);
    w.write_all(&end).await?;
    w.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn size_matches_output() {
        let dir = std::env::temp_dir().join(format!("ldzip-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut entries = Vec::new();
        for (i, (name, data)) in [("a.txt", &b"hello"[..]), ("照片.jpg", &b"xyz"[..]), ("empty", &b""[..])]
            .iter()
            .enumerate()
        {
            let p = dir.join(format!("f{}", i));
            std::fs::write(&p, data).unwrap();
            entries.push(ZipEntry {
                name: name.to_string(),
                path: p,
                size: data.len() as u64,
                mtime: 1_700_000_000,
            });
        }
        let mut out: Vec<u8> = Vec::new();
        write_zip(&entries, &mut out, |_| {}).await.unwrap();
        assert_eq!(out.len() as u64, total_size(&entries));
        assert_eq!(&out[..4], &[0x50, 0x4b, 0x03, 0x04]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
