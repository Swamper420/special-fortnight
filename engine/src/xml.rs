//! Minimal attribute reader for the game's decrypted XML files.
//!
//! The payload XML is machine-generated with a fixed shape
//! (`<tag k="v" .../>`, no namespaces, no entities except `&amp;`
//! in path-like values which we pass through untouched).
//! This is deliberately not a general XML parser (ponytail: std only,
//! no new dependency for three fixed schemas).

/// One `<tag .../>` element: name + attributes in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Elem {
    pub name: String,
    pub attrs: Vec<(String, String)>,
}

impl Elem {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Collect all self-closing `<tag .../>` elements with the given name.
/// Also handles `<tag ...>text</tag>` by ignoring the text.
pub fn collect(xml: &str, name: &str) -> Vec<Elem> {
    let mut out = Vec::new();
    let open = format!("<{name}");
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        let after = &rest[i + open.len()..];
        // Name must end (space, '/', or '>'), not a longer prefix.
        if !after
            .chars()
            .next()
            .map(|c| c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '/' || c == '>')
            .unwrap_or(false)
        {
            rest = after;
            continue;
        }
        let end = after.find('>').map(|e| i + open.len() + e);
        let Some(e) = end else { break };
        let body = &rest[i + open.len()..e];
        out.push(Elem { name: name.to_string(), attrs: parse_attrs(body) });
        rest = &rest[e + 1..];
    }
    out
}

fn parse_attrs(body: &str) -> Vec<(String, String)> {
    let mut attrs = Vec::new();
    let b = body.as_bytes();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        let ks = i;
        while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'.') {
            i += 1;
        }
        if ks == i {
            break;
        }
        let key = &body[ks..i];
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= b.len() || b[i] != b'=' {
            break;
        }
        i += 1;
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= b.len() || (b[i] != b'"' && b[i] != b'\'') {
            break;
        }
        let q = b[i];
        i += 1;
        let vs = i;
        while i < b.len() && b[i] != q {
            i += 1;
        }
        attrs.push((key.to_string(), body[vs..i].to_string()));
        if i < b.len() {
            i += 1;
        }
    }
    attrs
}

/// Elements with bodies: `<tag ...>inner</tag>`. Returns attrs + inner.
pub fn collect_nested<'a>(xml: &'a str, name: &str) -> Vec<(Vec<(String, String)>, &'a str)> {
    let mut out = Vec::new();
    let open = format!("<{name}");
    let close = format!("</{name}>");
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        let after = &rest[i + open.len()..];
        if !after
            .chars()
            .next()
            .map(|c| c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '>')
            .unwrap_or(false)
        {
            rest = after;
            continue;
        }
        let Some(e) = after.find('>') else { break };
        let inner_start = &rest[i + open.len() + e + 1..];
        let Some(c) = inner_start.find(&close) else { break };
        let attrs = parse_attrs(&after[..e]);
        out.push((attrs, &inner_start[..c]));
        rest = &inner_start[c + close.len()..];
    }
    out
}
pub fn root_attrs(xml: &str, name: &str) -> Vec<(String, String)> {
    let open = format!("<{name}");
    let Some(i) = xml.find(&open) else { return Vec::new() };
    let after = &xml[i + open.len()..];
    let Some(e) = after.find('>') else { return Vec::new() };
    parse_attrs(&after[..e])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_entry() {
        let e = &collect(
            r#"<resourcelist version="1.7"><file id="a.txt" size="12" offset="8"/></resourcelist>"#,
            "file",
        );
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].get("id"), Some("a.txt"));
        assert_eq!(e[0].get("size"), Some("12"));
        // Prefix names don't match.
        assert!(collect(r#"<files><filex id="q"/></files>"#, "file").is_empty());
    }
}
