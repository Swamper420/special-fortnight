//! Headless installer extraction (Linux host boundary, no GUI).
//!
//! Drives the installer image directly: PE `.rsrc` walk to the Inno
//! `TSetupLdrOffsetTable` (RCDATA 11111), setup-0 block decode (CRC +
//! LZMA1), table walk (header counts in `Struct5507u.pas` order), setup-1
//! solid-chunk decode, per-file slice, 5309 CALL-filter undo, SHA1
//! verify, write under the target dir (`{app}` mapped to it).
//!
//! Boundary code only: no reconstructed `fn_*` is modified or called.
//! Formats follow public Inno Setup 5.5.7 sources (`Struct5507u.pas`,
//! innoextract `stream/exefilter.hpp`); every byte written is SHA1-
//! verified against the installer's own location entries, and the same
//! bytes were cross-checked against an independent Python decode
//! (58/58 SHA1 match, see `analysis/oracle_*.py`, scratch, not shipped).

use std::path::{Path, PathBuf};

/// Installer-facing error.
#[derive(Debug)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

fn fail(s: impl Into<String>) -> Error {
    Error(s.into())
}

fn u16_at(b: &[u8], o: usize) -> Result<u16> {
    b.get(o..o + 2)
        .ok_or_else(|| fail("truncated u16"))
        .map(|w| u16::from_le_bytes([w[0], w[1]]))
}

fn u32_at(b: &[u8], o: usize) -> Result<u32> {
    b.get(o..o + 4)
        .ok_or_else(|| fail("truncated u32"))
        .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
}

/// zlib CRC32.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// SHA1 (FIPS 180-4), returns 20-byte digest.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..20 => ((b & c) | ((!b) & d), 0x5a827999),
                20..40 => (b ^ c ^ d, 0x6ed9eba1),
                40..60 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, &v) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

fn hex20(d: &[u8; 20]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

// ---- LZMA1 raw decode (Inno 5-byte props + EOS, no size header) ----
// Delegated to lzma-rs (pure Rust). A hand-rolled range decoder lived
// here; it mis-decoded rep/match lanes and was replaced rather than
// patched a seventh time. The 1:1 reconstruction chain (fn_0040d33c)
// remains the verified record; this is host-boundary tooling.
fn lzma_decode(props: &[u8], body: &[u8]) -> Result<Vec<u8>> {
    if props.len() != 5 {
        return Err(fail("lzma: props must be 5 bytes"));
    }
    let mut input = Vec::with_capacity(props.len() + body.len());
    input.extend_from_slice(props);
    input.extend_from_slice(body);
    let mut output = Vec::new();
    let options = lzma_rs::decompress::Options {
        unpacked_size: lzma_rs::decompress::UnpackedSize::UseProvided(None),
        ..Default::default()
    };
    lzma_rs::lzma_decompress_with_options(&mut input.as_slice(), &mut output, &options)
        .map_err(|e| fail(format!("lzma: {e}")))?;
    Ok(output)
}


// ---- 5309 CALL-filter undo (innoextract stream/exefilter.hpp, flip=true) ----

/// Undo the Inno ≥5.3.9 CALL/JMP transform on one file's bytes.
fn unfilter_5309(data: &[u8]) -> Vec<u8> {
    const BS: u64 = 0x10000;
    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    let mut pos = 0usize;
    let mut offset = 0u64;
    while pos < data.len() {
        let byte = data[pos];
        pos += 1;
        offset += 1;
        out.push(byte);
        if byte != 0xe8 && byte != 0xe9 {
            continue;
        }
        if BS - ((offset - 1) % BS) < 5 {
            continue;
        }
        if pos + 4 > data.len() {
            out.extend_from_slice(&data[pos..]);
            break;
        }
        let mut ab = [data[pos], data[pos + 1], data[pos + 2], data[pos + 3]];
        pos += 4;
        offset += 4;
        if ab[3] == 0x00 || ab[3] == 0xff {
            let addr = (offset & 0xff_ffff) as u32;
            let rel = (u32::from(ab[0]) | (u32::from(ab[1]) << 8) | (u32::from(ab[2]) << 16))
                .wrapping_sub(addr)
                & 0xff_ffff;
            ab[0] = (rel & 0xff) as u8;
            ab[1] = ((rel >> 8) & 0xff) as u8;
            ab[2] = ((rel >> 16) & 0xff) as u8;
            if rel & 0x80_0000 != 0 {
                ab[3] ^= 0xff;
            }
        }
        out.extend_from_slice(&ab);
    }
    out
}

// ---- PE / resource / setup-0 parsing ----

struct PeSections {
    image_base: u32,
}

fn parse_pe(img: &[u8]) -> Result<(PeSections, usize, usize)> {
    if img.len() < 64 || &img[0..2] != b"MZ" {
        return Err(fail("not a PE file"));
    }
    let pe = u32_at(img, 0x3c)? as usize;
    if img.len() < pe + 6 || &img[pe..pe + 4] != b"PE\0\0" {
        return Err(fail("bad PE signature"));
    }
    let nsec = u16_at(img, pe + 6)? as usize;
    let opt = pe + 24;
    let optsz = u16_at(img, pe + 20)? as usize;
    if u16_at(img, opt)? != 0x10b {
        return Err(fail("not a PE32 image"));
    }
    let image_base = u32_at(img, opt + 28)?;
    let stab = opt + optsz;
    let mut rsrc = None;
    for i in 0..nsec {
        let s = stab + i * 40;
        let vma = u32_at(img, s + 12)? as usize;
        let rawptr = u32_at(img, s + 20)? as usize;
        if &img[s..s + 8] == b".rsrc\0\0\0" {
            rsrc = Some((rawptr, image_base as usize + vma));
        }
    }
    let (roff, rva) = rsrc.ok_or_else(|| fail("no .rsrc section"))?;
    Ok((PeSections { image_base }, roff, rva))
}

/// Walk `.rsrc` for (type, id); return (data_rva, size).
fn find_resource(img: &[u8], roff: usize, want_type: u32, want_id: u32) -> Result<(u32, u32)> {
    let rd = |o: usize| u32_at(img, roff + o);
    let rw = |o: usize| u16_at(img, roff + o);
    let total = rw(12)? as usize + rw(14)? as usize;
    for i in 0..total {
        let e = 16 + i * 8;
        if rd(e)? != want_type {
            continue;
        }
        let tdir = (rd(e + 4)? & 0x7fff_ffff) as usize;
        let ttotal = rw(tdir + 12)? as usize + rw(tdir + 14)? as usize;
        for j in 0..ttotal {
            let f = tdir + 16 + j * 8;
            if rd(f)? != want_id {
                continue;
            }
            let leaf = (rd(f + 4)? & 0x7fff_ffff) as usize;
            let data_off = if rd(f + 4)? & 0x8000_0000 != 0 {
                let ltotal = rw(leaf + 12)? as usize + rw(leaf + 14)? as usize;
                if ltotal == 0 {
                    continue;
                }
                (rd(leaf + 16 + 4)? & 0x7fff_ffff) as usize
            } else {
                leaf
            };
            return Ok((rd(data_off)?, rd(data_off + 4)?));
        }
    }
    Err(fail("resource not found"))
}

/// One decompressed setup-0 block.
fn read_block(img: &[u8], pos: usize) -> Result<(bool, Vec<u8>, usize)> {
    let hcrc = u32_at(img, pos)?;
    let stored = u32_at(img, pos + 4)? as usize;
    let comp = *img.get(pos + 8).ok_or_else(|| fail("truncated block header"))?;
    if crc32(&img[pos + 4..pos + 9]) != hcrc {
        return Err(fail("block header CRC mismatch"));
    }
    let inner = img.get(pos + 9..pos + 9 + stored).ok_or_else(|| fail("truncated block"))?;
    let mut out = Vec::new();
    let mut p = 0;
    while p < inner.len() {
        let c = u32::from_le_bytes([inner[p], inner[p + 1], inner[p + 2], inner[p + 3]]);
        let n = (0x1000usize).min(inner.len() - p - 4);
        let chunk = &inner[p + 4..p + 4 + n];
        if crc32(chunk) != c {
            return Err(fail("block chunk CRC mismatch"));
        }
        out.extend_from_slice(chunk);
        p += 4 + n;
    }
    let raw = if comp != 0 {
        let (props, body) = out.split_at(5.min(out.len()));
        lzma_decode(props, body)?
    } else {
        out
    };
    Ok((comp != 0, raw, pos + 9 + stored))
}

// ---- table walk ----

struct Cursor<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let s = self.b.get(self.p..self.p + n).ok_or_else(|| fail("truncated table"))?;
        self.p += n;
        Ok(s)
    }
    fn i32(&mut self) -> Result<i32> {
        Ok(i32::from_le_bytes(self.take(4)?[..4].try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?[..4].try_into().unwrap()))
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?[..2].try_into().unwrap()))
    }
    fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(self.take(8)?[..8].try_into().unwrap()))
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(*self.take(1)?.first().unwrap())
    }
    fn wstr(&mut self) -> Result<String> {
        let ln = self.i32()? as usize;
        let raw = self.take(ln)?;
        if raw.len() % 2 != 0 {
            return Err(fail("odd widestring length"));
        }
        let v: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16(&v).map_err(|_| fail("bad utf-16 in table"))
    }
    fn astr(&mut self) -> Result<Vec<u8>> {
        let ln = self.i32()? as usize;
        Ok(self.take(ln)?.to_vec())
    }
}

struct FileEntry {
    dest: String,
    loc: i32,
    opts: u32,
    ftype: u8,
}

struct FileLoc {
    start: i64,
    suboff: i64,
    size: i64,
    csize: i64,
    sha1: [u8; 20],
    flags: u16,
    timestamp: i64,
}

/// Parse setup-0 block1 (header + all entry tables). Returns (files, counts).
fn parse_tables(dec: &[u8]) -> Result<(Vec<FileEntry>, usize)> {
    let mut c = Cursor { b: dec, p: 0 };
    for _ in 0..28 {
        c.wstr()?;
    }
    for _ in 0..4 {
        c.astr()?;
    }
    let mut counts = [0u32; 16];
    for v in counts.iter_mut() {
        *v = c.u32()?;
    }
    // header fixed tail: 10+10+4+4+1+20+8+8+4+6+1+1+1+1+8+6 = 93
    c.take(93)?;
    let table_start = c.p;
    // language entries: 6 wide + 4 ansi + 21 tail
    for _ in 0..counts[0] {
        for _ in 0..6 {
            c.wstr()?;
        }
        for _ in 0..4 {
            c.astr()?;
        }
        c.take(21)?;
    }
    // custom messages: 2 wide + i32
    for _ in 0..counts[1] {
        c.wstr()?;
        c.wstr()?;
        c.i32()?;
    }
    // permissions: 1 ansi
    for _ in 0..counts[2] {
        c.astr()?;
    }
    // types: 4 wide + 10 + 10 + 1 + 1 + 8
    for _ in 0..counts[3] {
        for _ in 0..4 {
            c.wstr()?;
        }
        c.take(10 + 10 + 1 + 1 + 8)?;
    }
    // components: 5 wide + 8 + 4 + 1 + 10 + 10 + 1 + 8
    for _ in 0..counts[4] {
        for _ in 0..5 {
            c.wstr()?;
        }
        c.take(8 + 4 + 1 + 10 + 10 + 1 + 8)?;
    }
    // tasks: 6 wide + 4 + 1 + 10 + 10 + 1
    for _ in 0..counts[5] {
        for _ in 0..6 {
            c.wstr()?;
        }
        c.take(4 + 1 + 10 + 10 + 1)?;
    }
    // dirs: 7 wide + 4 + 10 + 10 + 2 + 1
    for _ in 0..counts[6] {
        for _ in 0..7 {
            c.wstr()?;
        }
        c.take(4 + 10 + 10 + 2 + 1)?;
    }
    // files: 10 wide + 10 + 10 + 4 + 4 + 8 + 2 + 4 + 1
    let mut files = Vec::new();
    for _ in 0..counts[7] {
        let mut ws = Vec::new();
        for _ in 0..10 {
            ws.push(c.wstr()?);
        }
        c.take(10 + 10)?;
        let loc = c.i32()?;
        c.take(4)?; // attribs
        let _esz = c.i64()?;
        c.take(2)?; // permissions
        let opts = c.u32()?;
        let ftype = c.u8()?;
        files.push(FileEntry { dest: ws[1].clone(), loc, opts, ftype });
        let _ = (&ws, _esz);
    }
    Ok((files, table_start))
}

/// Parse setup-0 block2 (file-location entries, 74 bytes each).
fn parse_locs(dec: &[u8]) -> Result<Vec<FileLoc>> {
    if dec.len() % 74 != 0 {
        return Err(fail("fileloc block size not a multiple of 74"));
    }
    let mut out = Vec::new();
    let mut c = Cursor { b: dec, p: 0 };
    while c.p < dec.len() {
        let _first = c.i32()?;
        let _last = c.i32()?;
        let start = c.i32()? as i64;
        let suboff = c.i64()?;
        let size = c.i64()?;
        let csize = c.i64()?;
        let sha_raw = c.take(20)?;
        let mut sha1 = [0u8; 20];
        sha1.copy_from_slice(sha_raw);
        let timestamp = c.i64()?;
        let _ms = c.u32()?;
        let _ls = c.u32()?;
        let flags = c.u16()?;
        out.push(FileLoc { start, suboff, size, csize, sha1, flags, timestamp });
    }
    Ok(out)
}

/// Map `{app}\...` dest names onto the output dir.
fn dest_path(outdir: &Path, dest: &str) -> Result<PathBuf> {
    let rel = dest
        .strip_prefix("{app}\\")
        .or_else(|| dest.strip_prefix("{app}"))
        .ok_or_else(|| fail(format!("unsupported dest prefix: {dest}")))?;
    let mut p = PathBuf::from(outdir);
    for part in rel.split('\\') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(fail(format!("bad dest component: {dest}")));
        }
        p.push(part);
    }
    Ok(p)
}

fn filetime_to_systemtime(ft: i64) -> Option<std::time::SystemTime> {
    // FILETIME: 100ns ticks since 1601-01-01. Clamp negatives to epoch.
    const DIFF: i64 = 11_644_473_600; // seconds 1601 -> 1970
    let secs = ft.div_euclid(10_000_000) - DIFF;
    if secs < 0 {
        return None;
    }
    std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(secs as u64))
}

/// Extract the installer image at `image_path` into `outdir`.
/// Returns the number of files written.
pub fn extract(image_path: &Path, outdir: &Path) -> Result<usize> {
    let img = std::fs::read(image_path)
        .map_err(|e| fail(format!("cannot read {}: {e}", image_path.display())))?;
    let (_sections, roff, rva_base) = parse_pe(&img)?;
    let (data_rva, _size) = find_resource(&img, roff, 10, 11111)?;
    // data_rva is image-relative; convert to file offset via section map.
    let to_file_off = |rva: u32| -> Result<usize> {
        // section with lowest file offset mapping: res implied in .rsrc;
        // compute from the resource dir base.
        let rva = rva as usize;
        let base_rva = rva_base - _sections.image_base as usize;
        Ok(roff + (rva - base_rva))
    };
    let tab_off = to_file_off(data_rva)?;
    let tab = img.get(tab_off..tab_off + 44).ok_or_else(|| fail("truncated offset table"))?;
    if &tab[0..6] != b"rDlPtS" {
        return Err(fail("bad offset-table id"));
    }
    let ver = u32::from_le_bytes(tab[12..16].try_into().unwrap());
    let off_exe = u32::from_le_bytes(tab[20..24].try_into().unwrap()) as usize;
    let off0 = u32::from_le_bytes(tab[32..36].try_into().unwrap()) as usize;
    let off1 = u32::from_le_bytes(tab[36..40].try_into().unwrap()) as usize;
    let tcrc = u32::from_le_bytes(tab[40..44].try_into().unwrap());
    if ver != 1 {
        return Err(fail(format!("unsupported offset-table version {ver}")));
    }
    if crc32(&tab[..40]) != tcrc {
        return Err(fail("offset-table CRC mismatch"));
    }
    let sid = img.get(off0..off0 + 64).ok_or_else(|| fail("truncated setup id"))?;
    if !sid.starts_with(b"Inno Setup Setup Data (5.5.7)") {
        return Err(fail("unsupported setup id"));
    }
    // setup-0 blocks: header+tables, then file locations.
    let (_, dec1, next) = read_block(&img, off0 + 64)?;
    let (_, dec2, _) = read_block(&img, next)?;
    let (files, _tstart) = parse_tables(&dec1)?;
    let locs = parse_locs(&dec2)?;
    let _ = off_exe;
    // setup-1 chunk.
    if &img[off1..off1 + 4] != b"zlb\x1a" {
        return Err(fail("bad chunk magic"));
    }
    // chunk length: max over entries (all share one chunk here).
    let csize = locs.iter().map(|l| l.start as usize + l.csize as usize).max().unwrap_or(0);
    let payload = img.get(off1 + 4..off1 + 4 + csize).ok_or_else(|| fail("truncated chunk"))?;
    if payload.len() < 5 {
        return Err(fail("truncated chunk props"));
    }
    let chunk = lzma_decode(&payload[..5], &payload[5..])?;
    let mut written = 0usize;
    for (i, f) in files.iter().enumerate() {
        if f.loc < 0 {
            println!("skip [{i}] {} (generated at install, type {})", f.dest, f.ftype);
            continue;
        }
        let loc = locs
            .get(f.loc as usize)
            .ok_or_else(|| fail(format!("file {i} bad location {}", f.loc)))?;
        let abs = loc.start as usize + loc.suboff as usize;
        let size = loc.size as usize;
        let mut data: Vec<u8> = chunk
            .get(abs..abs + size)
            .ok_or_else(|| fail(format!("file {i} slice out of range")))?
            .to_vec();
        if loc.flags & 0x10 != 0 {
            data = unfilter_5309(&data);
        }
        if sha1(&data) != loc.sha1 {
            return Err(fail(format!(
                "file {i} {} SHA1 mismatch (got {})",
                f.dest,
                hex20(&sha1(&data))
            )));
        }
        let path = dest_path(outdir, &f.dest)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| fail(format!("mkdir {}: {e}", parent.display())))?;
        }
        std::fs::write(&path, &data).map_err(|e| fail(format!("write {}: {e}", path.display())))?;
        #[cfg(target_os = "linux")]
        if let Some(mtime) = filetime_to_systemtime(loc.timestamp) {
            // Best-effort mtime parity; a failure never fails the extract.
            if let Ok(fd) = std::fs::File::options().write(true).open(&path) {
                let _ = fd.set_modified(mtime);
            }
        }
        println!("ok [{i}] {} ({} bytes, sha1 {})", path.display(), size, hex20(&loc.sha1));
        written += 1;
        let _ = f.opts;
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::{crc32, hex20, lzma_decode, sha1, unfilter_5309};

    #[test]
    fn crc32_known() {
        assert_eq!(crc32(b"123456789"), 0xcbf43926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn sha1_known() {
        let d = sha1(b"abc");
        assert_eq!(
            d,
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
    }

    // Compressed with Python lzma (FORMAT_RAW, lc=3 lp=0 pb=2 dict=2MiB):
    // plain = b'Hello, Deluxe Ski Jump 3! ' * 40 + bytes(range(256)) * 3 (1808 B).
    const LZMA_BLOB: [u8; 282] = [
        0x5d, 0x00, 0x00, 0x20, 0x00, 0x00, 0x24, 0x19, 0x49, 0x98, 0x6f, 0x16,
        0x02, 0x86, 0xc7, 0x9f, 0x4b, 0x84, 0x0b, 0xc4, 0xf7, 0xc6, 0xf0, 0x01,
        0x6e, 0x52, 0x35, 0x03, 0x1e, 0x71, 0x30, 0xf9, 0x44, 0x33, 0x36, 0xc7,
        0x15, 0xd1, 0x7e, 0x3a, 0xd3, 0x05, 0xa3, 0x21, 0x5a, 0x5f, 0x2c, 0x32,
        0xb1, 0x0d, 0xf5, 0x30, 0x70, 0xd3, 0x5d, 0xce, 0x91, 0xcd, 0xa7, 0x90,
        0xdf, 0xb4, 0xfe, 0x69, 0x50, 0x76, 0x4b, 0xd1, 0x71, 0xf7, 0xd7, 0xb8,
        0xaa, 0x69, 0xa2, 0xc8, 0x08, 0x7f, 0x75, 0x20, 0xde, 0x24, 0x20, 0x4e,
        0x68, 0x1e, 0xc6, 0x13, 0xa9, 0x5c, 0xcd, 0x42, 0xab, 0x14, 0xcf, 0x33,
        0x1b, 0x60, 0x6f, 0x77, 0x7c, 0xe4, 0x67, 0xe0, 0x06, 0xb0, 0xde, 0x12,
        0x8d, 0xee, 0xbf, 0xc0, 0xed, 0xe6, 0xd7, 0xbe, 0x9b, 0x4d, 0x83, 0x58,
        0xd6, 0x9d, 0xdb, 0xac, 0x2f, 0x67, 0x45, 0x53, 0xdb, 0x68, 0xe4, 0x0a,
        0xfe, 0xe4, 0xcb, 0x49, 0x95, 0x70, 0x25, 0x8b, 0x71, 0x85, 0x13, 0x1f,
        0xfb, 0x8f, 0xe5, 0x99, 0xc5, 0x78, 0x0a, 0x45, 0x4b, 0x4e, 0x14, 0x43,
        0xa1, 0x1c, 0xbf, 0xc3, 0xd6, 0x6a, 0x30, 0x96, 0x8a, 0x47, 0x27, 0x79,
        0x96, 0xc3, 0x4c, 0x98, 0xac, 0xef, 0xbb, 0x00, 0xd6, 0x09, 0x03, 0x2d,
        0x07, 0xc6, 0x14, 0x09, 0x08, 0x09, 0x9e, 0xc1, 0x31, 0x35, 0x77, 0x7c,
        0xbf, 0xc1, 0x54, 0xee, 0x93, 0x01, 0x56, 0x4e, 0x33, 0xd3, 0x29, 0xa3,
        0xa2, 0xd0, 0xed, 0x5f, 0xe7, 0xe5, 0x69, 0x44, 0xc1, 0x12, 0x03, 0x6f,
        0xcb, 0x4b, 0xe0, 0xd0, 0x3c, 0x82, 0x93, 0x3c, 0xa0, 0x0f, 0x5c, 0x6f,
        0x18, 0x55, 0xe2, 0x1b, 0xd0, 0xaa, 0x91, 0xf7, 0x90, 0x7c, 0x51, 0x60,
        0xd2, 0xb6, 0x09, 0x4b, 0x2d, 0x3c, 0x31, 0x80, 0xc1, 0x3f, 0x5b, 0x16,
        0x65, 0x68, 0x77, 0xb6, 0x14, 0xe1, 0x78, 0x48, 0xe0, 0x4a, 0xfc, 0x11,
        0xac, 0x93, 0xc7, 0x25, 0x8a, 0xa4, 0x7d, 0x17, 0x9b, 0xf7, 0xd9, 0x70,
        0xba, 0xbf, 0xfc, 0xbd, 0x9c, 0x40,
    ];

    const LZMA_PLAIN_LEN: usize = 1808;
    const LZMA_PLAIN_SHA1: &str = "8c1df7d996c6ae42579c44ab010401b980c3ba14";

    const F5309_IN: [u8; 512] = [
        0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0xff, 0xff, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x18, 0x01, 0x00, 0x00, 0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd,
        0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70,
        0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f,
        0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e, 0x20, 0x69, 0x6e, 0x20,
        0x44, 0x4f, 0x53, 0x20, 0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d, 0x0d, 0x0a,
        0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8f, 0x5f, 0x65, 0xfe,
        0xcb, 0x3e, 0x0b, 0xad, 0xcb, 0x3e, 0x0b, 0xad, 0xcb, 0x3e, 0x0b, 0xad,
        0xb0, 0x22, 0x07, 0xad, 0xc9, 0x3e, 0x0b, 0xad, 0x48, 0x22, 0x05, 0xad,
        0xe2, 0x3e, 0x0b, 0xad, 0xa4, 0x21, 0x00, 0xad, 0xc8, 0x3e, 0x0b, 0xad,
        0xfd, 0x18, 0x01, 0xad, 0x0f, 0x3e, 0x0b, 0xad, 0x45, 0x36, 0x54, 0xad,
        0xc9, 0x3e, 0x0b, 0xad, 0xcb, 0x3e, 0x0b, 0xad, 0xc3, 0x3e, 0x0b, 0xad,
        0x37, 0x1e, 0x19, 0xad, 0xca, 0x3e, 0x0b, 0xad, 0x11, 0x1d, 0x16, 0xad,
        0x82, 0x3e, 0x0b, 0xad, 0x11, 0x1d, 0x17, 0xad, 0xc9, 0x3e, 0x0b, 0xad,
        0x31, 0x1d, 0x12, 0xad, 0xcd, 0x3e, 0x0b, 0xad, 0x08, 0x31, 0x6b, 0xad,
        0xca, 0x3e, 0x0b, 0xad, 0xcb, 0x3e, 0x0a, 0xad, 0x0c, 0x3e, 0x0b, 0xad,
        0x48, 0x36, 0x56, 0xad, 0xda, 0x3e, 0x0b, 0xad, 0xfd, 0x18, 0x00, 0xad,
        0xa7, 0x3f, 0x0b, 0xad, 0x0c, 0x38, 0x0d, 0xad, 0xca, 0x3e, 0x0b, 0xad,
        0x52, 0x69, 0x63, 0x68, 0xcb, 0x3e, 0x0b, 0xad, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x50, 0x45, 0x00, 0x00, 0x4c, 0x01, 0x05, 0x00,
        0x4f, 0x79, 0x1b, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xe0, 0x00, 0x0f, 0x01, 0x0b, 0x01, 0x06, 0x00, 0x00, 0xc0, 0x1c, 0x00,
        0x00, 0x20, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0xf0, 0x19, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0xd0, 0x1c, 0x00, 0x00, 0x00, 0x40, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x22, 0x00, 0x00, 0x10, 0x00, 0x00, 0x47, 0xd4, 0x22, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x10, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xa0, 0x3e, 0x20, 0x00, 0xdc, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x21, 0x00,
        0xe8, 0xc2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xf0, 0x21, 0x00, 0x98, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x1c, 0x00, 0xb8, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    const F5309_OUT: [u8; 512] = [
        0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0xff, 0xff, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x18, 0x01, 0x00, 0x00, 0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd,
        0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70,
        0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f,
        0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e, 0x20, 0x69, 0x6e, 0x20,
        0x44, 0x4f, 0x53, 0x20, 0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d, 0x0d, 0x0a,
        0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8f, 0x5f, 0x65, 0xfe,
        0xcb, 0x3e, 0x0b, 0xad, 0xcb, 0x3e, 0x0b, 0xad, 0xcb, 0x3e, 0x0b, 0xad,
        0xb0, 0x22, 0x07, 0xad, 0xc9, 0x3e, 0x0b, 0xad, 0x48, 0x22, 0x05, 0xad,
        0xe2, 0x3e, 0x0b, 0xad, 0xa4, 0x21, 0x00, 0xad, 0xc8, 0x3e, 0x0b, 0xad,
        0xfd, 0x18, 0x01, 0xad, 0x0f, 0x3e, 0x0b, 0xad, 0x45, 0x36, 0x54, 0xad,
        0xc9, 0x3e, 0x0b, 0xad, 0xcb, 0x3e, 0x0b, 0xad, 0xc3, 0x3e, 0x0b, 0xad,
        0x37, 0x1e, 0x19, 0xad, 0xca, 0x3e, 0x0b, 0xad, 0x11, 0x1d, 0x16, 0xad,
        0x82, 0x3e, 0x0b, 0xad, 0x11, 0x1d, 0x17, 0xad, 0xc9, 0x3e, 0x0b, 0xad,
        0x31, 0x1d, 0x12, 0xad, 0xcd, 0x3e, 0x0b, 0xad, 0x08, 0x31, 0x6b, 0xad,
        0xca, 0x3e, 0x0b, 0xad, 0xcb, 0x3e, 0x0a, 0xad, 0x0c, 0x3e, 0x0b, 0xad,
        0x48, 0x36, 0x56, 0xad, 0xda, 0x3e, 0x0b, 0xad, 0xfd, 0x18, 0x00, 0xad,
        0xa7, 0x3f, 0x0b, 0xad, 0x0c, 0x38, 0x0d, 0xad, 0xca, 0x3e, 0x0b, 0xad,
        0x52, 0x69, 0x63, 0x68, 0xcb, 0x3e, 0x0b, 0xad, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x50, 0x45, 0x00, 0x00, 0x4c, 0x01, 0x05, 0x00,
        0x4f, 0x79, 0x1b, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xe0, 0x00, 0x0f, 0x01, 0x0b, 0x01, 0x06, 0x00, 0x00, 0xc0, 0x1c, 0x00,
        0x00, 0x20, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0xf0, 0x19, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0xd0, 0x1c, 0x00, 0x00, 0x00, 0x40, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x22, 0x00, 0x00, 0x10, 0x00, 0x00, 0x47, 0xd4, 0x22, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x10, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xa0, 0x3e, 0x20, 0x00, 0xdc, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x21, 0x00,
        0xe8, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xf0, 0x21, 0x00, 0x98, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x1c, 0x00, 0xb8, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn lzma_roundtrip_vector() {
        let dec = lzma_decode(&LZMA_BLOB[..5], &LZMA_BLOB[5..]).expect("decode");
        assert_eq!(dec.len(), LZMA_PLAIN_LEN);
        assert_eq!(hex20(&sha1(&dec)).as_str(), LZMA_PLAIN_SHA1);
        let mut expect = b"Hello, Deluxe Ski Jump 3! ".repeat(40);
        expect.extend((0..768).map(|v| (v % 256) as u8));
        assert_eq!(dec, expect);
    }

    #[test]
    fn lzma_corpus() {
        const B_UNIQUE16: &[u8] = &[0x5d, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x52, 0x50, 0x0a, 0x84, 0xf9, 0x9b, 0xb2, 0x80, 0x21, 0xa9, 0x69, 0xd6, 0x27, 0xe0, 0xcf, 0xe8, 0x6f, 0xff, 0xff, 0xb7, 0x24, 0x00, 0x00];
        assert_eq!(hex20(&sha1(&lzma_decode(&B_UNIQUE16[..5], &B_UNIQUE16[5..]).unwrap())).as_str(), "56178b86a57fac22899a9964185c2cc96e7da589", "unique16");
        const B_RUNA: &[u8] = &[0x5d, 0x00, 0x00, 0x20, 0x00, 0x00, 0x20, 0xee, 0x57, 0x07, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00];
        assert_eq!(hex20(&sha1(&lzma_decode(&B_RUNA[..5], &B_RUNA[5..]).unwrap())).as_str(), "30b86e44e6001403827a62c58b08893e77cf121f", "runA");
        const B_ABAB: &[u8] = &[0x5d, 0x00, 0x00, 0x20, 0x00, 0x00, 0x20, 0x90, 0xa9, 0xb0, 0x18, 0x3d, 0xff, 0xff, 0xff, 0xfc, 0x20, 0x00, 0x00];
        assert_eq!(hex20(&sha1(&lzma_decode(&B_ABAB[..5], &B_ABAB[5..]).unwrap())).as_str(), "e5c434864e9101926692af0c2f8540079aec02c8", "abab");
        const B_HELLO: &[u8] = &[0x5d, 0x00, 0x00, 0x20, 0x00, 0x00, 0x24, 0x19, 0x49, 0x98, 0x6f, 0x16, 0x02, 0x86, 0xc7, 0x9f, 0x4b, 0x84, 0x0b, 0xc4, 0xf7, 0xc6, 0xf0, 0x01, 0x6e, 0x52, 0x35, 0x03, 0x1e, 0x71, 0x30, 0xfa, 0x55, 0x0c, 0x8d, 0xff, 0xff, 0x7c, 0x38, 0x00, 0x00];
        assert_eq!(hex20(&sha1(&lzma_decode(&B_HELLO[..5], &B_HELLO[5..]).unwrap())).as_str(), "48da1f5f9bed40a118674fdaab391db0abf64e79", "hello");
    }

    #[test]
    fn exefilter_5309_vector() {
        assert_eq!(unfilter_5309(&F5309_IN), F5309_OUT.to_vec());
    }

    #[test]
    fn live_image_extracts() {
        let img = std::path::Path::new("dsj3v171.exe");
        if !img.exists() {
            return;
        }
        let dir = std::env::temp_dir().join("dsj3-extract-test");
        let _ = std::fs::remove_dir_all(&dir);
        let n = super::extract(img, &dir).expect("extract");
        assert_eq!(n, 58);
        let exe = std::fs::read(dir.join("DSJ3.exe")).expect("DSJ3.exe");
        assert_eq!(&exe[0..2], b"MZ");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
