//! `--dump-hills` backend: dump `*.hil` hill profiles to text.
//!
//! Reads `<install>/Data Files/Resources/Resource.000` (manifest) +
//! `Resource.001` (payload), decrypts with `K_RES_HEX`, splits via
//! `engine::manifest`, parses each `*.hil` via `engine::hill`,
//! writes `<basename>.txt` parse-level dumps (`version=` + one
//! `key=value` line per profile key per section in sorted order +
//! `trees`/`judgetower` lines, diff-stable by construction, no pixels).
//! `Ok(n)` counts hills; any `Err` is corrupt input or I/O
//! (caller exits 1, like `--extract`).

use std::path::Path;

fn res_dir(install: &Path) -> std::path::PathBuf {
    install.join("Data Files").join("Resources")
}

fn basename(id: &str) -> &str {
    id.rsplit(['/', '\\']).next().unwrap_or(id)
}

fn section(out: &mut String, name: &str, profile: &std::collections::HashMap<String, f32>) {
    out.push_str(&format!("[{name}]\n"));
    let mut keys: Vec<&String> = profile.keys().collect();
    keys.sort();
    for k in keys {
        out.push_str(&format!("{k}={}\n", profile[k]));
    }
}

pub fn dump_text(hill: &dsj3_engine::hill::Hill) -> String {
    let mut out = format!("version={}\n", hill.version);
    section(&mut out, "inrun", &hill.profile_inrun);
    section(&mut out, "dhill", &hill.profile_dhill);
    section(&mut out, "terrain", &hill.profile_terrain);
    out.push_str(&format!(
        "judgetower d={} z={}\ntrees n={}\n",
        hill.judgetower_d, hill.judgetower_z, hill.trees_n
    ));
    out
}

pub fn dump_hills(install: &Path, out: &Path) -> Result<usize, String> {
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
    let hills: Vec<(&str, &[u8])> = entries
        .iter()
        .filter(|(id, _)| id.ends_with(".hil"))
        .map(|(id, blob)| (*id, *blob))
        .collect();
    if hills.is_empty() {
        return Err("corrupt Resource.000: no *.hil".to_string());
    }
    let mut n = 0;
    for (id, blob) in &hills {
        let text = String::from_utf8_lossy(blob).into_owned();
        let hill =
            dsj3_engine::hill::parse(&text).map_err(|e| format!("corrupt {id}: {e}"))?;
        let stem = basename(id);
        let stem = stem.strip_suffix(".hil").unwrap_or(stem);
        let dst = out.join(format!("{stem}.txt"));
        std::fs::write(&dst, dump_text(&hill))
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
        let h = dsj3_engine::hill::parse("<hill version=\"1.4\"><inrun><profile lz=\"3.0\" ls=\"42.0\"/></inrun><dhill><profile a0=\"10.0\" ak=\"44.0\"/><judgetower d=\"76.3\" z=\"1.5\"/></dhill><terrain><profile in=\"0.87\" dh=\"0.4\"/><trees n=\"260\"/></terrain></hill>").unwrap();
        assert_eq!(
            super::dump_text(&h),
            "version=1.4\n[inrun]\nls=42\nlz=3\n[dhill]\na0=10\nak=44\n[terrain]\ndh=0.4\nin=0.87\njudgetower d=76.3 z=1.5\ntrees n=260\n"
        );
        assert!(dsj3_engine::hill::parse("<hill/>").is_err());
        // Missing install tree is an error (exit-1 path), not a panic.
        assert!(super::dump_hills(
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
        let base = std::env::temp_dir().join(format!("dsj3-hills-{}", std::process::id()));
        let (a, b) = (base.join("a"), base.join("b"));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let n = super::dump_hills(&src, &a).unwrap();
        assert!(n > 0, "no *.hil dumped");
        assert_eq!(super::dump_hills(&src, &b).unwrap(), n);
        let mut files: Vec<_> = std::fs::read_dir(&a)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(files.len(), n, "one .txt per hill");
        files.sort();
        for f in &files {
            let (x, y) = (
                std::fs::read(a.join(f)).unwrap(),
                std::fs::read(b.join(f)).unwrap(),
            );
            assert_eq!(x, y, "{f:?}: dump not diff-stable");
            let t = String::from_utf8_lossy(&x).into_owned();
            assert!(t.starts_with("version="), "{f:?}: missing header");
            assert!(t.lines().any(|l| l.starts_with("trees n=")), "{f:?}: missing trees");
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}
