//! `--dump-models` backend: dump `*-model.txt` batches to text.
//!
//! Reads `<install>/Data Files/Resources/Resource.000` (manifest) +
//! `Resource.001` (payload), decrypts with `K_RES_HEX`, splits via
//! `engine::manifest`, parses each `*-model.txt` via `engine::model`,
//! writes `<basename>.txt` parse-level dumps (`batches=N` + one
//! `batch id=.. vertices=.. faces=.. texture=..` line per batch in
//! parse order, diff-stable by construction, no pixels).
//! `Ok(n)` counts models; any `Err` is corrupt input or I/O
//! (caller exits 1, like `--extract`).

use std::path::Path;

fn res_dir(install: &Path) -> std::path::PathBuf {
    install.join("Data Files").join("Resources")
}

fn basename(id: &str) -> &str {
    id.rsplit(['/', '\\']).next().unwrap_or(id)
}

pub fn dump_text(batches: &[dsj3_engine::model::Batch]) -> String {
    let mut out = format!("batches={}\n", batches.len());
    for b in batches {
        out.push_str(&format!(
            "batch id={} vertices={} faces={} texture={}\n",
            b.id,
            b.vertices.len(),
            b.faces.len(),
            b.texture
        ));
    }
    out
}

pub fn dump_models(install: &Path, out: &Path) -> Result<usize, String> {
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
    let models: Vec<(&str, &[u8])> = entries
        .iter()
        .filter(|(id, _)| id.ends_with("model.txt"))
        .map(|(id, blob)| (*id, *blob))
        .collect();
    if models.is_empty() {
        return Err("corrupt Resource.000: no *-model.txt".to_string());
    }
    let mut n = 0;
    for (id, blob) in &models {
        let text = String::from_utf8_lossy(blob).into_owned();
        let batches =
            dsj3_engine::model::parse(&text).map_err(|e| format!("corrupt {id}: {e}"))?;
        let dst = out.join(basename(id));
        std::fs::write(&dst, dump_text(&batches))
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
        let b = dsj3_engine::model::parse("<3dmodel><batch id=\"front\" texture1=\"a.png\" material=\"%m\" fvf=\"274\" order=\"0\">\n<vertex id=\"1\" x=\"0.0\" y=\"-4.0\" z=\"0.0\" u1=\"0.0\" v1=\"-4.0\"/>\n<vertex id=\"2\" x=\"0.0\" y=\"1.0\" z=\"0.0\" u1=\"0.0\" v1=\"1.0\"/>\n<face v1=\"1\" v2=\"2\" v3=\"1\"/>\n</batch></3dmodel>").unwrap();
        assert_eq!(
            super::dump_text(&b),
            "batches=1\nbatch id=front vertices=2 faces=1 texture=a.png\n"
        );
        assert!(dsj3_engine::model::parse("<3dmodel/>").is_err());
        // Missing install tree is an error (exit-1 path), not a panic.
        assert!(super::dump_models(
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
        let base = std::env::temp_dir().join(format!("dsj3-models-{}", std::process::id()));
        let (a, b) = (base.join("a"), base.join("b"));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let n = super::dump_models(&src, &a).unwrap();
        assert!(n > 0, "no *-model.txt dumped");
        assert_eq!(super::dump_models(&src, &b).unwrap(), n);
        let mut files: Vec<_> = std::fs::read_dir(&a)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(files.len(), n, "one .txt per model");
        files.sort();
        for f in &files {
            let (x, y) = (
                std::fs::read(a.join(f)).unwrap(),
                std::fs::read(b.join(f)).unwrap(),
            );
            assert_eq!(x, y, "{f:?}: dump not diff-stable");
            let t = String::from_utf8_lossy(&x).into_owned();
            assert!(t.starts_with("batches="), "{f:?}: missing header");
            assert!(t.lines().any(|l| l.contains("texture=")), "{f:?}: missing texture ref");
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}
