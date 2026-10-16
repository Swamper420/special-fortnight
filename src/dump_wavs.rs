//! `--dump-wavs` backend: dump `Sounds\*.ogg` to listenable `.wav`.
//!
//! Reads `<install>/Data Files/Resources/Resource.000` (manifest) +
//! `Resource.001` (payload), decrypts with `K_RES_HEX`, splits via
//! `engine::manifest`, decodes each `*.ogg` via `engine::audio`,
//! writes `<basename>.wav` (44-byte RIFF header + interleaved i16 LE,
//! hand-rolled, no new deps). `Ok(n)` counts sounds; any `Err` is
//! corrupt input or I/O (caller exits 1, like `--extract`).

use std::path::Path;

fn res_dir(install: &Path) -> std::path::PathBuf {
    install.join("Data Files").join("Resources")
}

fn basename(id: &str) -> &str {
    id.rsplit(['/', '\\']).next().unwrap_or(id)
}

fn stem_of(file: &str) -> &str {
    file.strip_suffix(".ogg")
        .or_else(|| file.strip_suffix(".OGG"))
        .or_else(|| file.strip_suffix(".Ogg"))
        .unwrap_or(file)
}

pub fn wav_bytes(a: &dsj3_engine::audio::Audio) -> Vec<u8> {
    let data_bytes = (a.samples.len() * 2) as u32;
    let mut out = Vec::with_capacity(44 + data_bytes as usize);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&(36u32.wrapping_add(data_bytes)).to_le_bytes());
    out.extend_from_slice(b"WAVE");
    out.extend_from_slice(b"fmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&(a.channels as u16).to_le_bytes());
    out.extend_from_slice(&a.sample_rate.to_le_bytes());
    out.extend_from_slice(&(a.sample_rate * a.channels as u32 * 2).to_le_bytes());
    out.extend_from_slice(&((a.channels as u16) * 2).to_le_bytes());
    out.extend_from_slice(&16u16.to_le_bytes());
    out.extend_from_slice(b"data");
    out.extend_from_slice(&data_bytes.to_le_bytes());
    for s in &a.samples {
        out.extend_from_slice(&s.to_le_bytes());
    }
    out
}

pub fn dump_wavs(install: &Path, out: &Path) -> Result<usize, String> {
    std::fs::create_dir_all(out).map_err(|e| format!("mkdir {}: {e}", out.display()))?;
    let dir = res_dir(install);
    let raw0 =
        std::fs::read(dir.join("Resource.000")).map_err(|e| format!("read Resource.000: {e}"))?;
    let raw1 =
        std::fs::read(dir.join("Resource.001")).map_err(|e| format!("read Resource.001: {e}"))?;
    let plain0 = dsj3_engine::decrypt::decrypt(&raw0, dsj3_engine::decrypt::K_RES_HEX)
        .ok_or_else(|| "corrupt Resource.000: decrypt failed".to_string())?;
    let plain1 = dsj3_engine::decrypt::decrypt(&raw1, dsj3_engine::decrypt::K_RES_HEX)
        .ok_or_else(|| "corrupt Resource.001: decrypt failed".to_string())?;
    let m = dsj3_engine::manifest::parse(&String::from_utf16le_lossy(&plain0))
        .map_err(|e| format!("corrupt Resource.000: {e}"))?;
    let entries =
        dsj3_engine::manifest::split(&m, &plain1).map_err(|e| format!("corrupt Resource.001: {e}"))?;
    let oggs: Vec<(&str, &[u8])> = entries
        .iter()
        .filter(|(id, _)| id.to_lowercase().ends_with(".ogg"))
        .map(|(id, blob)| (*id, *blob))
        .collect();
    if oggs.is_empty() {
        return Err("corrupt Resource.000: no *.ogg".to_string());
    }
    let mut n = 0;
    for (id, blob) in &oggs {
        let audio =
            dsj3_engine::audio::decode(blob).map_err(|e| format!("corrupt {id}: {e}"))?;
        let stem = stem_of(basename(id));
        let dst = out.join(format!("{stem}.wav"));
        std::fs::write(&dst, wav_bytes(&audio))
            .map_err(|e| format!("write {}: {e}", dst.display()))?;
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    fn parse_wav(buf: &[u8]) -> (u16, u32, Vec<i16>) {
        assert!(buf.len() >= 44, "short wav");
        assert_eq!(&buf[0..4], b"RIFF");
        assert_eq!(&buf[8..12], b"WAVE");
        assert_eq!(&buf[12..16], b"fmt ");
        assert_eq!(&buf[36..40], b"data");
        let ch = u16::from_le_bytes([buf[22], buf[23]]);
        let sr = u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]);
        let n = u32::from_le_bytes([buf[40], buf[41], buf[42], buf[43]]) as usize / 2;
        let mut s = Vec::with_capacity(n);
        for i in 0..n {
            s.push(i16::from_le_bytes([buf[44 + 2 * i], buf[44 + 2 * i + 1]]));
        }
        (ch, sr, s)
    }

    #[test]
    fn header_exact_plus_live_shape() {
        // Fixture: header bytes exact, no original bytes.
        let a = dsj3_engine::audio::Audio {
            channels: 1,
            sample_rate: 8000,
            samples: vec![0, 1, -1, 32767, -32768],
        };
        let w = super::wav_bytes(&a);
        assert_eq!(w.len(), 44 + 10);
        let mut head = Vec::new();
        head.extend_from_slice(b"RIFF");
        head.extend_from_slice(&46u32.to_le_bytes());
        head.extend_from_slice(b"WAVEfmt ");
        head.extend_from_slice(&16u32.to_le_bytes());
        head.extend_from_slice(&1u16.to_le_bytes());
        head.extend_from_slice(&1u16.to_le_bytes());
        head.extend_from_slice(&8000u32.to_le_bytes());
        head.extend_from_slice(&16000u32.to_le_bytes());
        head.extend_from_slice(&2u16.to_le_bytes());
        head.extend_from_slice(&16u16.to_le_bytes());
        head.extend_from_slice(b"data");
        head.extend_from_slice(&10u32.to_le_bytes());
        assert_eq!(&w[..44], &head[..]);
        assert_eq!(&w[44..], &[0, 0, 1, 0, 255, 255, 255, 127, 0, 128]);
        let (ch, sr, s) = parse_wav(&w);
        assert_eq!((ch, sr), (1, 8000));
        assert_eq!(s, a.samples);
        // Missing install tree is an error (exit-1 path), not a panic.
        assert!(super::dump_wavs(
            std::path::Path::new("/nonexistent-dsj3-dir"),
            &std::env::temp_dir()
        )
        .is_err());
        // Live run shape: real install tree when present, else skip.
        let src = ["/tmp/dsj3-wrap", "dsj3-installed"]
            .iter()
            .map(std::path::PathBuf::from)
            .find(|p| p.join("Data Files/Resources/Resource.001").exists());
        let src = match src {
            Some(p) => p,
            None => return,
        };
        let base = std::env::temp_dir().join(format!("dsj3-wavs-{}", std::process::id()));
        let (a, b) = (base.join("a"), base.join("b"));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let n = super::dump_wavs(&src, &a).unwrap();
        assert_eq!(n, 21, "want all 21 embedded OGGs");
        assert_eq!(super::dump_wavs(&src, &b).unwrap(), n);
        let mut files: Vec<_> = std::fs::read_dir(&a)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(files.len(), n, "one .wav per ogg");
        files.sort();
        for f in &files {
            assert!(
                f.to_string_lossy().ends_with(".wav"),
                "{f:?}: want .wav"
            );
            let (x, y) = (
                std::fs::read(a.join(f)).unwrap(),
                std::fs::read(b.join(f)).unwrap(),
            );
            assert_eq!(x, y, "{f:?}: dump not diff-stable");
            let (ch, sr, s) = parse_wav(&x);
            assert!((1..=2).contains(&(ch as u8)), "{f:?}: {ch}ch");
            assert!((8_000..=96_000).contains(&sr), "{f:?}: {sr}Hz");
            assert!(!s.is_empty(), "{f:?}: empty");
            assert_eq!(s.len() % ch as usize, 0, "{f:?}: torn frame");
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}
