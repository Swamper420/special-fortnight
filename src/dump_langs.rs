//! `--dump-langs` backend: dump all 6 `.lan` string tables to text.
//!
//! Reads encrypted blobs from `<install>/Data Files/Languages/*.lan`
//! (installed/extracted tree, same layout `engine::assets::inventory`
//! expects), decrypts with `K_LAN_HEX`, parses via `engine::lang`, and
//! writes `<Stem>.txt` canonical dumps (`id=content` lines in parse
//! order, diff-stable by construction). `Ok(n)` counts languages (6);
//! any `Err` is corrupt input or I/O (caller exits 1, like `--extract`).

use std::path::Path;

pub const LANGS: [&str; 6] = [
    "English",
    "Finnish",
    "German",
    "Norwegian",
    "Polish",
    "Slovenian",
];

fn blob_dir(install: &Path) -> std::path::PathBuf {
    install.join("Data Files").join("Languages")
}

pub fn dump_langs(install: &Path, out: &Path) -> Result<usize, String> {
    std::fs::create_dir_all(out).map_err(|e| format!("mkdir {}: {e}", out.display()))?;
    let mut n = 0;
    for stem in LANGS {
        let src = blob_dir(install).join(format!("{stem}.lan"));
        let img =
            std::fs::read(&src).map_err(|e| format!("read {}: {e}", src.display()))?;
        let plain = dsj3_engine::decrypt::decrypt(&img, dsj3_engine::decrypt::K_LAN_HEX)
            .ok_or_else(|| format!("corrupt {stem}.lan: decrypt failed"))?;
        if !plain.starts_with(b"\xef\xbb\xbf<") {
            return Err(format!("corrupt {stem}.lan: bad header"));
        }
        let text = String::from_utf8_lossy(&plain).into_owned();
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
        let s =
            dsj3_engine::lang::parse(text).map_err(|e| format!("corrupt {stem}.lan: {e}"))?;
        let dst = out.join(format!("{stem}.txt"));
        std::fs::write(&dst, s.dump())
            .map_err(|e| format!("write {}: {e}", dst.display()))?;
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_dump_plus_live_shape() {
        // Generated fixture: parse/dump path, no original bytes.
        let s = dsj3_engine::lang::parse(
            "<language><string id=\"B\" content=\"y\"/><string id=\"A\" content=\"x|z\"/></language>",
        )
        .unwrap();
        assert_eq!(s.dump(), "B=y\nA=x|z\n");
        assert!(dsj3_engine::lang::parse("<language/>").is_err());
        // Missing install tree is an error (exit-1 path), not a panic.
        assert!(super::dump_langs(
            std::path::Path::new("/nonexistent-dsj3-dir"),
            &std::env::temp_dir()
        )
        .is_err());
        // Live run shape: real install tree when present, else skip.
        let src = ["/tmp/dsj3-wrap", "dsj3-installed"]
            .iter()
            .map(std::path::PathBuf::from)
            .find(|p| p.join("Data Files/Languages/English.lan").exists());
        let src = match src {
            Some(p) => p,
            None => return,
        };
        let base = std::env::temp_dir().join(format!("dsj3-langs-{}", std::process::id()));
        let (a, b) = (base.join("a"), base.join("b"));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        assert_eq!(super::dump_langs(&src, &a).unwrap(), 6);
        assert_eq!(super::dump_langs(&src, &b).unwrap(), 6);
        for stem in super::LANGS {
            let (x, y) = (
                std::fs::read(a.join(format!("{stem}.txt"))).unwrap(),
                std::fs::read(b.join(format!("{stem}.txt"))).unwrap(),
            );
            assert_eq!(x, y, "{stem}: dump not diff-stable");
        }
        let en = std::fs::read_to_string(a.join("English.txt")).unwrap();
        assert!(en.lines().any(|l| l == "Hill01=Norway"), "Hill01 spot value");
        let _ = std::fs::remove_dir_all(&base);
    }
}
