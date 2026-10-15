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
}
