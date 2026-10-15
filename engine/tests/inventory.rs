//! Inventory over generated fixtures only — never original bytes.

use std::path::PathBuf;

fn fixture_tree(tag: &str, hills: &[&str]) -> PathBuf {
    let base = std::env::temp_dir().join(format!("dsj3-engine-inv-{tag}"));
    let _ = std::fs::remove_dir_all(&base);
    for sub in ["Hills", "Languages", "Resources"] {
        std::fs::create_dir_all(base.join("Data Files").join(sub)).unwrap();
    }
    for h in hills {
        std::fs::write(base.join("Data Files").join("Hills").join(h), b"fixture").unwrap();
    }
    for l in ["English.lan", "Finnish.lan", "German.lan", "Norwegian.lan", "Polish.lan", "Slovenian.lan"] {
        std::fs::write(base.join("Data Files").join("Languages").join(l), b"fixture").unwrap();
    }
    for r in ["Resource.000", "Resource.001", "Resource.002"] {
        std::fs::write(base.join("Data Files").join("Resources").join(r), b"fixture").unwrap();
    }
    std::fs::write(base.join("DSJ3.exe"), b"MZfixture").unwrap();
    base
}

#[test]
fn full_shape_passes() {
    let hills: Vec<String> = (1..=40).map(|i| format!("Hill{i:02}.hil")).collect();
    let refs: Vec<&str> = hills.iter().map(String::as_str).collect();
    let base = fixture_tree("full", &refs);
    let inv = dsj3_engine::assets::inventory(&base).unwrap();
    assert_eq!(inv.hills.len(), 40);
    assert!(dsj3_engine::assets::check_counts(&inv).is_empty());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn short_shape_reports() {
    let base = fixture_tree("short", &["Hill01.hil"]);
    let inv = dsj3_engine::assets::inventory(&base).unwrap();
    let problems = dsj3_engine::assets::check_counts(&inv);
    assert!(problems.iter().any(|p| p.starts_with("hills:")));
    let _ = std::fs::remove_dir_all(&base);
}
