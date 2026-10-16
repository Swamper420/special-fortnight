//! `--dump-materials` backend: dump embedded `Materials\*` files verbatim.
//!
//! Reads `<install>/Data Files/Resources/Resource.000` (manifest) +
//! `Resource.001` (payload), decrypts with `K_RES_HEX`, splits via
//! `engine::manifest`, sanity-checks each `Materials\*` blob is BOM
//! XML with a `<material>` root (no semantic parse: no `material`
//! engine module exists, and none is evidenced yet), writes
//! `<relpath>` verbatim bytes; `Ok(n)` counts materials; any `Err`
//! is corrupt input or I/O (caller exits 1, like `--extract`).

use std::path::Path;

fn res_dir(install: &Path) -> std::path::PathBuf {
    install.join("Data Files").join("Resources")
}

/// Output path preserves the entry's relative dirs (`Materials\a.txt`
/// -> `<out>/Materials/a.txt`), same as `--dump-pngs`.
fn out_path(out: &Path, id: &str) -> std::path::PathBuf {
    out.join(id.replace('\\', "/"))
}

fn is_material(blob: &[u8]) -> bool {
    let t = String::from_utf8_lossy(blob);
    t.contains("<material>")
}

pub fn dump_materials(install: &Path, out: &Path) -> Result<usize, String> {
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
    let mats: Vec<(&str, &[u8])> = entries
        .iter()
        .filter(|(id, _)| id.starts_with("Materials\\"))
        .map(|(id, blob)| (*id, *blob))
        .collect();
    if mats.is_empty() {
        return Err("corrupt Resource.000: no Materials\\*".to_string());
    }
    let mut n = 0;
    for (id, blob) in &mats {
        if !is_material(blob) {
            return Err(format!("corrupt {id}: no <material> root"));
        }
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
        assert!(super::dump_materials(
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
        let base = std::env::temp_dir().join(format!("dsj3-mats-{}", std::process::id()));
        let (a, b) = (base.join("a"), base.join("b"));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let n = super::dump_materials(&src, &a).unwrap();
        assert_eq!(n, 5, "want all 5 embedded Materials\\* files");
        assert_eq!(super::dump_materials(&src, &b).unwrap(), n);
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
        assert_eq!(files.len(), n, "one file per material");
        files.sort();
        for f in &files {
            let rel = f.strip_prefix(&a).unwrap();
            let (x, y) = (std::fs::read(f).unwrap(), std::fs::read(b.join(rel)).unwrap());
            assert_eq!(x, y, "{f:?}: dump not diff-stable");
            let t = String::from_utf8_lossy(&x).into_owned();
            assert!(t.contains("<material>"), "{f:?}: no <material> root");
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}
