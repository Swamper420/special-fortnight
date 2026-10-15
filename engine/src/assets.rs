//! Install-dir inventory: enumerate hills/languages/resources.
//!
//! Pure std, no OS calls beyond file reads. Callers pass the install
//! dir (the `{app}` mapping target). Original bytes are only sized,
//! never parsed here — parsing is Phase 1 per format.

use std::path::{Path, PathBuf};

/// One installed data file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub size: u64,
}

/// What the engine needs from an install dir.
#[derive(Debug, Clone, Default)]
pub struct Inventory {
    pub hills: Vec<Entry>,
    pub languages: Vec<Entry>,
    pub resources: Vec<Entry>,
    pub exe_bytes: u64,
}

fn list_dir(dir: &Path, pred: &dyn Fn(&str) -> bool) -> Result<Vec<Entry>, String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("read {}: {e}", dir.display()))?;
    let mut out = Vec::new();
    for e in rd {
        let e = e.map_err(|e| format!("entry {}: {e}", dir.display()))?;
        let name = e.file_name().to_string_lossy().into_owned();
        if !pred(&name) {
            continue;
        }
        let size = e.metadata().map_err(|e| format!("stat {name}: {e}"))?.len();
        out.push(Entry { name, size });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Build the inventory. Missing dirs are an error (caller points at
/// the wrong dir); wrong counts are reported via [`check_counts`].
pub fn inventory(install_dir: &Path) -> Result<Inventory, String> {
    let base: PathBuf = install_dir.join("Data Files");
    let hills = list_dir(&base.join("Hills"), &|n| n.ends_with(".hil"))?;
    let languages = list_dir(&base.join("Languages"), &|n| n.ends_with(".lan"))?;
    let resources = list_dir(&base.join("Resources"), &|n| n.starts_with("Resource."))?;
    let exe_bytes = std::fs::metadata(install_dir.join("DSJ3.exe"))
        .map_err(|e| format!("stat DSJ3.exe: {e}"))?
        .len();
    Ok(Inventory { hills, languages, resources, exe_bytes })
}

/// Expected payload shape for the 1.7.1 image: 40 hills, 6 languages,
/// 3 resource blobs. Returns a message per mismatch, empty when clean.
pub fn check_counts(inv: &Inventory) -> Vec<String> {
    let mut problems = Vec::new();
    if inv.hills.len() != 40 {
        problems.push(format!("hills: want 40, got {}", inv.hills.len()));
    }
    if inv.languages.len() != 6 {
        problems.push(format!("languages: want 6, got {}", inv.languages.len()));
    }
    if inv.resources.len() != 3 {
        problems.push(format!("resources: want 3, got {}", inv.resources.len()));
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_dir_errors() {
        let d = std::env::temp_dir().join("dsj3-engine-empty-test");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        assert!(inventory(&d).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
