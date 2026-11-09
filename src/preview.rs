use crate::config::MAX_DOCUMENT_PREVIEW;
use crate::util;
use serde_json::{json, Value};
use std::fs::File;
use std::io::Read;
use std::path::Path;

const TEXT_PREVIEW_EXTS: &[&str] = &[
    "txt", "text", "md", "markdown", "csv", "tsv", "json", "jsonl", "xml", "html", "htm", "css",
    "js", "mjs", "cjs", "ts", "tsx", "jsx", "py", "rb", "go", "rs", "java", "c", "cpp", "h", "hpp",
    "cs", "php", "swift", "kt", "kts", "sh", "bash", "zsh", "ps1", "bat", "cmd", "sql", "yaml",
    "yml", "toml", "ini", "cfg", "conf", "log", "env", "gitignore", "rtf", "srt", "vtt",
];
const TEXT_PREVIEW_NAMES: &[&str] = &["dockerfile", "makefile", "license", "readme", ".env"];

const CP1252: [char; 32] = [
    '€', '\u{81}', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u{8D}', 'Ž', '\u{8F}',
    '\u{90}', '‘', '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', '\u{9D}', 'ž', 'Ÿ',
];

fn decode_text(raw: &[u8], truncated: bool) -> String {
    let body = raw.strip_prefix(&b"\xEF\xBB\xBF"[..]).unwrap_or(raw);
    match std::str::from_utf8(body) {
        Ok(s) => return s.to_string(),
        Err(e) => {
            if truncated && e.error_len().is_none() {
                return String::from_utf8_lossy(&body[..e.valid_up_to()]).into_owned();
            }
        }
    }
    if raw.len() >= 2 && (raw[0] == 0xFF && raw[1] == 0xFE || raw[0] == 0xFE && raw[1] == 0xFF) {
        let le = raw[0] == 0xFF;
        let units: Vec<u16> = raw[2..]
            .chunks_exact(2)
            .map(|c| {
                if le {
                    u16::from_le_bytes([c[0], c[1]])
                } else {
                    u16::from_be_bytes([c[0], c[1]])
                }
            })
            .collect();
        return char::decode_utf16(units)
            .map(|r| r.unwrap_or('\u{FFFD}'))
            .collect();
    }
    raw.iter()
        .map(|&b| {
            if (0x80..0xA0).contains(&b) {
                CP1252[(b - 0x80) as usize]
            } else {
                b as char
            }
        })
        .collect()
}

fn read_text(path: &Path) -> Result<(String, bool), String> {
    let f = File::open(path).map_err(|_| "File could not be read.".to_string())?;
    let mut raw = Vec::new();
    f.take(MAX_DOCUMENT_PREVIEW as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "File could not be read.".to_string())?;
    let truncated = raw.len() > MAX_DOCUMENT_PREVIEW;
    raw.truncate(MAX_DOCUMENT_PREVIEW);
    if raw.is_empty() {
        return Ok((String::new(), false));
    }
    let text = decode_text(&raw, truncated)
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    Ok((text, truncated))
}

// ── DOCX ──────────────────────────────────────────────────────────────

fn rd16(b: &[u8], at: usize) -> Option<usize> {
    let s = b.get(at..at + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]) as usize)
}

fn rd32(b: &[u8], at: usize) -> Option<usize> {
    let s = b.get(at..at + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize)
}

/// Read one entry out of a ZIP container (enough for word/document.xml).
fn zip_entry(data: &[u8], wanted: &str, max_out: usize) -> Result<Vec<u8>, String> {
    let bad = || "DOCX preview could not be read.".to_string();
    if data.len() < 22 {
        return Err(bad());
    }
    let search_from = data.len().saturating_sub(22 + 65_535);
    let mut eocd = None;
    let mut i = data.len() - 22;
    loop {
        if data[i..i + 4] == [0x50, 0x4b, 0x05, 0x06] {
            eocd = Some(i);
            break;
        }
        if i == search_from {
            break;
        }
        i -= 1;
    }
    let eocd = eocd.ok_or_else(bad)?;
    let count = rd16(data, eocd + 10).ok_or_else(bad)?;
    let mut p = rd32(data, eocd + 16).ok_or_else(bad)?;
    for _ in 0..count {
        if data.get(p..p + 4) != Some(&[0x50, 0x4b, 0x01, 0x02][..]) {
            return Err(bad());
        }
        let method = rd16(data, p + 10).ok_or_else(bad)?;
        let csize = rd32(data, p + 20).ok_or_else(bad)?;
        let usize_ = rd32(data, p + 24).ok_or_else(bad)?;
        let nlen = rd16(data, p + 28).ok_or_else(bad)?;
        let elen = rd16(data, p + 30).ok_or_else(bad)?;
        let clen = rd16(data, p + 32).ok_or_else(bad)?;
        let local = rd32(data, p + 42).ok_or_else(bad)?;
        let name = data.get(p + 46..p + 46 + nlen).ok_or_else(bad)?;
        let rtfd_match = wanted == "@rtfd" && {
            let n = String::from_utf8_lossy(name).to_ascii_lowercase();
            !n.starts_with("__macosx/") && (n == "txt.rtf" || n.ends_with(".rtfd/txt.rtf"))
        };
        if name == wanted.as_bytes() || rtfd_match {
            if usize_ > max_out || (method == 0 && csize > max_out) {
                return Err("DOCX is too large to preview.".to_string());
            }
            if data.get(local..local + 4) != Some(&[0x50, 0x4b, 0x03, 0x04][..]) {
                return Err(bad());
            }
            let lnlen = rd16(data, local + 26).ok_or_else(bad)?;
            let lelen = rd16(data, local + 28).ok_or_else(bad)?;
            let start = local + 30 + lnlen + lelen;
            let raw = data.get(start..start + csize).ok_or_else(bad)?;
            return match method {
                0 => Ok(raw.to_vec()),
                8 => {
                    let mut out = Vec::new();
                    flate2::read::DeflateDecoder::new(raw)
                        .take(max_out as u64 + 1)
                        .read_to_end(&mut out)
                        .map_err(|_| bad())?;
                    if out.len() > max_out { return Err("Document text is too large to preview.".into()); }
                    Ok(out)
                }
                _ => Err(bad()),
            };
        }
        p += 46 + nlen + elen + clen;
    }
    Err(bad())
}

fn xml_unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        match tail.find(';') {
            Some(j) if j <= 10 => {
                let ent = &tail[1..j];
                let ch = match ent {
                    "lt" => Some('<'),
                    "gt" => Some('>'),
                    "amp" => Some('&'),
                    "quot" => Some('"'),
                    "apos" => Some('\''),
                    _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                        u32::from_str_radix(&ent[2..], 16).ok().and_then(char::from_u32)
                    }
                    _ if ent.starts_with('#') => ent[1..].parse::<u32>().ok().and_then(char::from_u32),
                    _ => None,
                };
                match ch {
                    Some(c) => {
                        out.push(c);
                        rest = &tail[j + 1..];
                    }
                    None => {
                        out.push('&');
                        rest = &tail[1..];
                    }
                }
            }
            _ => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Same output as v4's ElementTree walk: paragraphs and "a | b" table rows.
fn docx_text(xml: &str) -> String {
    let b = xml.as_bytes();
    let mut parts: Vec<String> = Vec::new();
    let mut p_depth = 0usize;
    let mut para = String::new();
    let mut in_t = false;
    let mut tbl_depth = 0usize;
    let mut in_cell = false;
    let mut cell_paras: Vec<String> = Vec::new();
    let mut row: Vec<String> = Vec::new();

    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'<' {
            let end = match memchr::memchr(b'>', &b[i..]) {
                Some(e) => i + e,
                None => break,
            };
            let tag = &xml[i + 1..end];
            i = end + 1;
            if tag.starts_with('?') || tag.starts_with('!') {
                continue;
            }
            let closing = tag.starts_with('/');
            let self_closing = tag.ends_with('/');
            let body = if closing { &tag[1..] } else { tag };
            let name_end = body
                .find(|c: char| c.is_whitespace() || c == '/')
                .unwrap_or(body.len());
            let full = &body[..name_end];
            let local = full.rsplit(':').next().unwrap_or(full);
            match local {
                "p" => {
                    if closing {
                        if p_depth > 0 {
                            p_depth -= 1;
                            if p_depth == 0 {
                                let text = para.trim().to_string();
                                if !text.is_empty() {
                                    if tbl_depth > 0 {
                                        if in_cell {
                                            cell_paras.push(text);
                                        }
                                    } else {
                                        parts.push(text);
                                    }
                                }
                                para.clear();
                            }
                        }
                    } else if !self_closing {
                        if p_depth == 0 {
                            para.clear();
                        }
                        p_depth += 1;
                    }
                }
                "t" => {
                    if closing {
                        in_t = false;
                    } else if !self_closing && p_depth > 0 {
                        in_t = true;
                    }
                }
                "tab" if p_depth > 0 && !closing => para.push('\t'),
                "br" | "cr" if p_depth > 0 && !closing => para.push('\n'),
                "tbl" => {
                    if closing {
                        tbl_depth = tbl_depth.saturating_sub(1);
                    } else if !self_closing {
                        tbl_depth += 1;
                    }
                }
                "tr" if tbl_depth == 1 => {
                    if closing {
                        if row.iter().any(|c| !c.is_empty()) {
                            parts.push(row.join(" | "));
                        }
                        row.clear();
                    } else if !self_closing {
                        row.clear();
                    }
                }
                "tc" if tbl_depth == 1 => {
                    if closing {
                        row.push(cell_paras.join(" "));
                        cell_paras.clear();
                        in_cell = false;
                    } else if !self_closing {
                        cell_paras.clear();
                        in_cell = true;
                    }
                }
                _ => {}
            }
        } else {
            let next = memchr::memchr(b'<', &b[i..]).map(|e| i + e).unwrap_or(b.len());
            if in_t && p_depth > 0 {
                para.push_str(&xml_unescape(&xml[i..next]));
            }
            i = next;
        }
    }
    parts.join("\n").trim().to_string()
}

fn read_docx(path: &Path) -> Result<(String, bool), String> {
    let meta = std::fs::metadata(path).map_err(|_| "DOCX preview could not be read.".to_string())?;
    if meta.len() > 200 * 1024 * 1024 {
        return Err("DOCX is too large to preview.".to_string());
    }
    let data = std::fs::read(path).map_err(|_| "DOCX preview could not be read.".to_string())?;
    let xml_bytes = zip_entry(&data, "word/document.xml", MAX_DOCUMENT_PREVIEW * 12)?;
    let xml = String::from_utf8_lossy(&xml_bytes);
    let mut text = docx_text(&xml);
    let truncated = text.chars().count() > MAX_DOCUMENT_PREVIEW;
    if truncated {
        text = util::truncate_chars(&text, MAX_DOCUMENT_PREVIEW);
    }
    if text.is_empty() {
        text = "No readable document text was found.".to_string();
    }
    Ok((text, truncated))
}


/// Extract a plain-text view; keep original rich text and attachments unchanged.
fn rtf_text(raw: &[u8]) -> String {
    let mut out: Vec<u16> = Vec::new();
    let mut stack = Vec::new();
    let (mut skip, mut uc, mut fallback) = (false, 1usize, 0usize);
    let mut i = 0;
    while i < raw.len() {
        let c = raw[i]; i += 1;
        match c {
            b'{' => { stack.push((skip, uc)); }
            b'}' => {
                if let Some((s,u)) = stack.pop() { skip=s; uc=u; }
                if stack.is_empty() { break; }
            }
            b'\\' => {
                if i >= raw.len() { break; }
                let c = raw[i]; i += 1;
                if c == b'*' { skip=true; continue; }
                if c == b'\'' {
                    if i + 2 > raw.len() { break; }
                    let hex=std::str::from_utf8(&raw[i..i+2]).unwrap_or(""); i+=2;
                    if fallback > 0 { fallback-=1; continue; }
                    if !skip { if let Ok(b)=u8::from_str_radix(hex,16) { out.extend(decode_text(&[b],false).encode_utf16()); } }
                } else if c.is_ascii_alphabetic() {
                    let start=i-1;
                    while i < raw.len() && raw[i].is_ascii_alphabetic() { i+=1; }
                    let word=&raw[start..i];
                    let number_start=i;
                    if raw.get(i)==Some(&b'-') { i+=1; }
                    while i < raw.len() && raw[i].is_ascii_digit() { i+=1; }
                    let n=std::str::from_utf8(&raw[number_start..i]).unwrap_or("").parse::<i32>().unwrap_or(0);
                    if raw.get(i)==Some(&b' ') { i+=1; }
                    if word==b"bin" { i=i.saturating_add(n.max(0) as usize).min(raw.len()); continue; }
                    if [b"fonttbl".as_slice(),b"colortbl",b"stylesheet",b"info",b"pict",b"object",b"NeXTGraphic",b"fldinst"].contains(&word) { skip=true; }
                    if skip { continue; }
                    match word {
                        b"uc" => uc=n.clamp(0,16) as usize,
                        b"u" => { out.push(n as u16); fallback=uc; }
                        b"par" | b"line" => out.push(10),
                        b"tab" => out.push(9),
                        b"emdash" => out.push(0x2014), b"endash" => out.push(0x2013),
                        b"lquote" | b"rquote" => out.push(0x27),
                        b"ldblquote" | b"rdblquote" => out.push(0x22),
                        _ => {},
                    }
                } else if fallback > 0 { fallback-=1; }
                else if !skip {
                    match c { b'\\'|b'{'|b'}' => out.push(c as u16), b'~' => out.push(0xa0), b'_' => out.push(0x2011), _=>{} }
                }
            }
            b'\r' | b'\n' => {},
            _ if fallback > 0 => { fallback-=1; },
            _ if !skip => out.extend(decode_text(&[c],false).encode_utf16()),
            _ => {},
        }
        if out.len() >= MAX_DOCUMENT_PREVIEW { break; }
    }
    String::from_utf16_lossy(&out)
}

fn read_rtfd(path: &Path) -> Result<(String,bool),String> {
    let f=File::open(path).map_err(|_| "RTFD could not be read.")?;
    let mut data=Vec::new();
    f.take(200*1024*1024+1).read_to_end(&mut data).map_err(|_| "RTFD could not be read.")?;
    if data.is_empty() { return Err("This received RTFD contains no data. Send the original note again as RTF/PDF or a compressed package.".into()); }
    if data.len()>200*1024*1024 { return Err("RTFD is too large to preview; download the original.".into()); }
    let raw=if data.starts_with(b"PK") {
        zip_entry(&data,"@rtfd",MAX_DOCUMENT_PREVIEW*4).map_err(|_| "RTFD package text could not be read. Download the original to open it in an Apple app.")?
    } else { data };
    let start=memchr::memmem::find(&raw,b"{\\rtf").ok_or("RTFD contains no supported rich-text document.")?;
    let text=rtf_text(&raw[start..]);
    let truncated=text.len()>=MAX_DOCUMENT_PREVIEW;
    Ok((text,truncated))
}

/// Payload for GET /{token}/document-preview/{name}. Err = HTTP 415 message.
pub fn document_preview(name: &str, path: &Path) -> Result<Value, String> {
    let ext = util::extension_of(name);
    let lower = name.to_lowercase();
    let (kind, (text, truncated)) = if ext == "rtfd" || ext == "rtf" || lower.ends_with(".rtfd.zip") {
        ("rtfd", read_rtfd(path)?)
    } else if ext == "docx" {
        ("docx", read_docx(path)?)
    } else if TEXT_PREVIEW_EXTS.contains(&ext.as_str()) || TEXT_PREVIEW_NAMES.contains(&lower.as_str()) {
        ("text", read_text(path)?)
    } else {
        return Err("This file type cannot be previewed as a document.".to_string());
    };
    Ok(json!({
        "name": name,
        "kind": kind,
        "extension": ext,
        "text": text,
        "truncated": truncated,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apple_rich_text_extracts_content_without_formatting_tables() {
        let rtf=br"{\rtf1\ansi{\fonttbl{\f0 Helvetica;}}Hello \b note\b0\par Unicode \u-10179?\u-8704? {\*\NeXTGraphic photo.png}end}";
        assert_eq!(rtf_text(rtf), "Hello note\nUnicode 😀 end");
        assert_eq!(rtf_text(br"{\rtf1 caf\'e9 \{ok\}}"), "café {ok}");
    }

    #[tokio::test]
    async fn zipped_rtfd_preview_preserves_the_original_package() {
        let dir=std::env::temp_dir().join(format!("ld-rtfd-{}",std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let source=dir.join("text");
        std::fs::write(&source,br"{\rtf1\ansi Hello from Notes\par second line}").unwrap();
        let entry=crate::zipstream::ZipEntry {name:"Memo.rtfd/TXT.rtf".into(),path:source.clone(),size:std::fs::metadata(&source).unwrap().len(),mtime:1_700_000_000};
        let mut zip=Vec::new();
        crate::zipstream::write_zip(&[entry],&mut zip, |_|{}).await.unwrap();
        let target=dir.join("Memo.rtfd.zip");
        std::fs::write(&target,&zip).unwrap();
        let result=document_preview("Memo.rtfd.zip",&target).unwrap();
        assert_eq!(result["text"],"Hello from Notes\nsecond line");
        assert_eq!(std::fs::read(&target).unwrap(),zip);
        assert!(document_preview("Memo.rtfd",&source).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn docx_walk() {
        let xml = r#"<?xml version="1.0"?><w:document><w:body>
            <w:p><w:pPr/><w:r><w:t>Hello</w:t></w:r><w:r><w:tab/><w:t xml:space="preserve"> &amp; world</w:t></w:r></w:p>
            <w:tbl><w:tr><w:tc><w:p><w:r><w:t>A</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>B</w:t></w:r></w:p></w:tc></w:tr></w:tbl>
            <w:p/></w:body></w:document>"#;
        assert_eq!(docx_text(xml), "Hello\t & world\nA | B");
    }

    #[test]
    fn decoding() {
        assert_eq!(decode_text(b"\xEF\xBB\xBFhi", false), "hi");
        assert_eq!(decode_text(b"caf\xE9", false), "café");
        assert_eq!(decode_text(b"\xFF\xFEh\x00i\x00", false), "hi");
    }
}
