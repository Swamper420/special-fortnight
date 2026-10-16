//! `--dump-pngs` backend: dump embedded `*.png` textures verbatim.
//!
//! Reads `<install>/Data Files/Resources/Resource.000` (manifest) +
//! `Resource.001` (payload), decrypts with `K_RES_HEX`, splits via
//! `engine::manifest`, validates each `*.png` via `engine::png::decode`,
//! writes `<relpath>.png` (verbatim decrypted blob bytes, already PNG;
//! `Ok(n)` counts PNGs; any `Err` is corrupt input or I/O
//! (caller exits 1, like `--extract`).

use std::path::Path;

fn res_dir(install: &Path) -> std::path::PathBuf {
    install.join("Data Files").join("Resources")
}

/// Output path preserves the entry's relative dirs (`Sprites\a.png` ->
/// `<out>/Sprites/a.png`) so same-basename entries in different dirs
/// (e.g. `Sprites\mediamond.png` vs `Textures\mediamond.png`) don't
/// collide. Flat basename would drop one of 101 PNGs to 100 files.
fn out_path(out: &Path, id: &str) -> std::path::PathBuf {
    out.join(id.replace('\\', "/"))
}

pub fn dump_pngs(install: &Path, out: &Path) -> Result<usize, String> {
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
    let pngs: Vec<(&str, &[u8])> = entries
        .iter()
        .filter(|(id, _)| id.to_lowercase().ends_with(".png"))
        .map(|(id, blob)| (*id, *blob))
        .collect();
    if pngs.is_empty() {
        return Err("corrupt Resource.000: no *.png".to_string());
    }
    let mut n = 0;
    for (id, blob) in &pngs {
        dsj3_engine::png::decode(blob).map_err(|e| format!("corrupt {id}: {e}"))?;
        let dst = out_path(out, id);
        if let Some(p) = dst.parent() {
            std::fs::create_dir_all(p).map_err(|e| format!("mkdir {}: {e}", p.display()))?;
        }
        std::fs::write(&dst, blob).map_err(|e| format!("write {}: {e}", dst.display()))?;
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    #[test]
    fn verbatim_plus_live_shape() {
        // Missing install tree is an error (exit-1 path), not a panic.
        assert!(super::dump_pngs(
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
        let base = std::env::temp_dir().join(format!("dsj3-pngs-{}", std::process::id()));
        let (a, b) = (base.join("a"), base.join("b"));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let n = super::dump_pngs(&src, &a).unwrap();
        assert_eq!(n, 101, "want all 101 embedded PNGs");
        assert_eq!(super::dump_pngs(&src, &b).unwrap(), n);
        fn walk(dir: &std::path::Path, acc: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    walk(&p, acc);
                } else {
                    acc.push(p);
                }
            }
        }
        let mut files = Vec::new();
        walk(&a, &mut files);
        assert_eq!(files.len(), n, "one .png per png");
        files.sort();
        for f in &files {
            let rel = f.strip_prefix(&a).unwrap();
            assert!(
                rel.to_string_lossy().to_lowercase().ends_with(".png"),
                "{rel:?}: want .png"
            );
            let (x, y) = (
                std::fs::read(f).unwrap(),
                std::fs::read(b.join(rel)).unwrap(),
            );
            assert_eq!(x, y, "{f:?}: dump not diff-stable");
            assert_eq!(&x[..8], b"\x89PNG\r\n\x1a\n", "{f:?}: bad magic");
            let img = dsj3_engine::png::decode(&x).unwrap();
            assert_eq!(img.pixels.len(), img.width as usize * img.height as usize * 4, "{f:?}");
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}
