//! `Resource.000` manifest: `<resourcelist version file>` + entries.
//!
//! Observed (decrypted `Resource.000`, 18984 B UTF-16):
//! `<resourcelist version="1.7" file="Data Files\Resources\Resource.001">`
//! with 145 `<file id size offset/>` entries slicing `Resource.001`.

use crate::xml;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub id: String,
    pub size: u64,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct Manifest {
    pub version: String,
    pub file: String,
    pub entries: Vec<Entry>,
}

pub fn parse(text: &str) -> Result<Manifest, String> {
    let root = xml::root_attrs(text, "resourcelist");
    let get = |k: &str| {
        root.iter()
            .find(|(kk, _)| *kk == k)
            .map(|(_, v)| v.clone())
            .ok_or_else(|| format!("resourcelist missing @{k}"))
    };
    let mut entries = Vec::new();
    for e in xml::collect(text, "file") {
        let id = e.get("id").ok_or("file missing @id")?.to_string();
        let size = e
            .get("size")
            .ok_or("file missing @size")?
            .parse::<u64>()
            .map_err(|_| format!("bad @size for {id}"))?;
        let offset = e
            .get("offset")
            .ok_or("file missing @offset")?
            .parse::<u64>()
            .map_err(|_| format!("bad @offset for {id}"))?;
        entries.push(Entry { id, size, offset });
    }
    if entries.is_empty() {
        return Err("no <file> entries".to_string());
    }
    Ok(Manifest { version: get("version")?, file: get("file")?, entries })
}

/// Slice entries out of a (decrypted) `Resource.001` image.
pub fn split<'a>(m: &'a Manifest, blob: &'a [u8]) -> Result<Vec<(&'a str, &'a [u8])>, String> {
    let mut out = Vec::new();
    for e in &m.entries {
        let (s, len) = (e.offset as usize, e.size as usize);
        let d = blob
            .get(s..s + len)
            .ok_or_else(|| format!("entry {} out of range", e.id))?;
        out.push((e.id.as_str(), d));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEMO: &str = "\u{feff}<resourcelist version=\"1.7\" file=\"Data Files\\Resources\\Resource.001\">\n\t<file id=\"a.txt\" size=\"3\" offset=\"8\"/>\n\t<file id=\"b.txt\" size=\"2\" offset=\"11\"/>\n</resourcelist>";

    #[test]
    fn manifest_roundtrip() {
        let m = parse(DEMO).unwrap();
        assert_eq!(m.version, "1.7");
        assert_eq!(m.entries.len(), 2);
        let blob = b"12345678abcdefg";
        let parts = split(&m, blob).unwrap();
        assert_eq!(parts[0], ("a.txt", b"abc".as_slice()));
        assert_eq!(parts[1], ("b.txt", b"de".as_slice()));
    }

    #[test]
    fn rejects_empty() {
        assert!(parse("<resourcelist/>").is_err());
    }
}
