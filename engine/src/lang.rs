//! `Languages\*.lan` string tables (decrypted).
//!
//! Observed (English.lan, 36150 B UTF-8 with BOM):
//! `<language version="1.7" name="...">` (or similar root) with
//! `<string id="..." content="..."/>` entries. Values may contain
//! `|` (line breaks) and `<!-- x.y -->` version comments.

use crate::xml;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Strings {
    pub entries: Vec<(String, String)>,
}

pub fn parse(text: &str) -> Result<Strings, String> {
    let mut entries = Vec::new();
    for e in xml::collect(text, "string") {
        let id = e.get("id").ok_or("string missing @id")?.to_string();
        let content = e.get("content").ok_or("string missing @content")?.to_string();
        entries.push((id, content));
    }
    if entries.is_empty() {
        return Err("no <string> entries".to_string());
    }
    Ok(Strings { entries })
}

impl Strings {
    pub fn get(&self, id: &str) -> Option<&str> {
        self.entries.iter().find(|(k, _)| k == id).map(|(_, v)| v.as_str())
    }

    /// Canonical text dump: one `id=content` line per entry, parse
    /// order. Diff-stable by construction (no map iteration).
    pub fn dump(&self) -> String {
        let mut out = String::new();
        for (k, v) in &self.entries {
            out.push_str(k);
            out.push('=');
            out.push_str(v);
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_strings() {
        let s = parse("<language><string id=\"A\" content=\"x\"/><string id=\"B\" content=\"y|z\"/></language>")
            .unwrap();
        assert_eq!(s.entries.len(), 2);
        assert_eq!(s.get("B"), Some("y|z"));
        assert!(parse("<language/>").is_err());
    }

    #[test]
    fn dump_canonical() {
        let s = parse("<language><string id=\"B\" content=\"y\"/><string id=\"A\" content=\"x|z\"/></language>")
            .unwrap();
        // Parse order kept, one id=content line each.
        assert_eq!(s.dump(), "B=y\nA=x|z\n");
        assert_eq!(s.dump(), s.dump());
    }

    /// Live check: decrypt all 6 `.lan` blobs (runtime `--extract`
    /// output, never committed), dump each to canonical text, assert
    /// the dump is byte-identical across runs. Skips when absent.
    #[test]
    fn live_all_six_diff_stable() {
        const LANGS: [&str; 6] = [
            "English",
            "Finnish",
            "German",
            "Norwegian",
            "Polish",
            "Slovenian",
        ];
        let dir = std::path::Path::new("/tmp/dsj3-wrap/Data Files/Languages");
        if !dir.join("English.lan").exists() {
            return;
        }
        for name in LANGS {
            let img = std::fs::read(dir.join(format!("{name}.lan"))).unwrap();
            let plain =
                crate::decrypt::decrypt(&img, crate::decrypt::K_LAN_HEX).expect("decrypt lan");
            assert!(plain.starts_with(b"\xef\xbb\xbf<"), "{name}: BOM");
            let text = String::from_utf8_lossy(&plain).into_owned();
            let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
            let s = parse(text).expect("lang parse");
            let a = s.dump();
            let b = parse(text).expect("reparse").dump();
            assert_eq!(a, b, "{name}: dump not deterministic");
            assert_eq!(s.entries.len(), 610, "{name}");
            eprintln!("{name}: {} strings", s.entries.len());
        }
        // Spot value from formats.md.
        let img = std::fs::read(dir.join("English.lan")).unwrap();
        let plain = crate::decrypt::decrypt(&img, crate::decrypt::K_LAN_HEX).unwrap();
        let text = String::from_utf8_lossy(&plain).into_owned();
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
        assert_eq!(parse(text).unwrap().get("Hill01"), Some("Norway"));
    }
}
