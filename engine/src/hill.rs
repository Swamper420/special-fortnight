//! `.hil` hill files (decrypted).
//!
//! Observed (demo hills embedded in `Resource.001`, e.g. offset
//! 247684 size 1889; UTF-8 with BOM): `<hill version copyright
//! date>` with three sections. Standalone `Data Files\Hills\*.hil`
//! (40 files, HS69–HS281) use the same schema but license-derived
//! keys (`REGHILL` gate) — only the 4 in-blob demo hills parse
//! without a license (see `engine/doc/formats.md`).
//!
//! - `<inrun><profile lz ls lg as rc lt at ht tz ws/>` + scenery
//!   (`startgate/startbanner/flag/railing/frame/stairs/pillar`).
//! - `<dhill><profile a0 ak hk nk rl l1 l2 rs lb hr nr ar w0 wk
//!   wb/>` + `fence` + `judgetower`.
//! - `<terrain><profile in dh a0 l0 y0 az ax l1 l2 d1 d2 rs/>` +
//!   `trees`.
//!
//! All profile fields are `f32` (game reads them as floats;
//! `rs`/`lb`-style ints stay `f32` here — the engine converts at
//! use). Scenery entries keep raw strings + colors (`0xRRGGBB`).

use crate::xml;
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct Hill {
    pub version: String,
    pub profile_inrun: HashMap<String, f32>,
    pub profile_dhill: HashMap<String, f32>,
    pub profile_terrain: HashMap<String, f32>,
    pub judgetower_d: f32,
    pub judgetower_z: f32,
    pub trees_n: u32,
}

fn num(e: &xml::Elem, k: &str, ctx: &str) -> Result<f32, String> {
    // Some numeric fields carry an 'f' suffix (e.g. az="1.7f").
    let raw = e.get(k).ok_or_else(|| format!("{ctx} missing @{k}"))?;
    let raw = raw.strip_suffix('f').unwrap_or(raw);
    raw.parse::<f32>().map_err(|_| format!("{ctx} bad @{k}={raw}"))
}

fn profile(inner: &str, ctx: &str) -> Result<HashMap<String, f32>, String> {
    let ps = xml::collect(inner, "profile");
    let p = ps.first().ok_or_else(|| format!("{ctx} missing <profile>"))?;
    let mut out = HashMap::new();
    for (k, _) in &p.attrs {
        out.insert(k.clone(), num(p, k, ctx)?);
    }
    Ok(out)
}

fn section(text: &str, name: &str) -> Result<String, String> {
    let parts = xml::collect_nested(text, name);
    parts
        .first()
        .map(|(_, inner)| inner.to_string())
        .ok_or_else(|| format!("missing <{name}>"))
}

pub fn parse(text: &str) -> Result<Hill, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let root = xml::root_attrs(text, "hill");
    let version = root
        .iter()
        .find(|(k, _)| *k == "version")
        .map(|(_, v)| v.clone())
        .ok_or("hill missing @version")?;
    let inrun = section(text, "inrun")?;
    let dhill = section(text, "dhill")?;
    let terrain = section(text, "terrain")?;
    let jt = xml::collect(&dhill, "judgetower");
    let jt = jt.first().ok_or("dhill missing <judgetower>")?;
    let trees = xml::collect(&terrain, "trees");
    let trees = trees.first().ok_or("terrain missing <trees>")?;
    Ok(Hill {
        version,
        profile_inrun: profile(&inrun, "inrun")?,
        profile_dhill: profile(&dhill, "dhill")?,
        profile_terrain: profile(&terrain, "terrain")?,
        judgetower_d: num(jt, "d", "judgetower")?,
        judgetower_z: num(jt, "z", "judgetower")?,
        trees_n: trees
            .get("n")
            .ok_or("trees missing @n")?
            .parse::<u32>()
            .map_err(|_| "trees bad @n".to_string())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shape mirrors the observed demo hills (generated values).
    const DEMO: &str = "<hill version=\"1.4\"><inrun><profile lz=\"3.0\" ls=\"42.0\"/></inrun><dhill><profile a0=\"10.0\" ak=\"44.0\"/><judgetower d=\"76.3\" z=\"1.5\"/></dhill><terrain><profile in=\"0.87\" dh=\"0.4\"/><trees n=\"260\"/></terrain></hill>";

    #[test]
    fn demo_shape() {
        let h = parse(DEMO).unwrap();
        assert_eq!(h.version, "1.4");
        assert_eq!(h.profile_inrun["lz"], 3.0);
        assert_eq!(h.profile_dhill["ak"], 44.0);
        assert_eq!(h.profile_terrain["in"], 0.87);
        assert_eq!(h.judgetower_d, 76.3);
        assert_eq!(h.trees_n, 260);
    }

    #[test]
    fn rejects_bare() {
        assert!(parse("<hill/>").is_err());
    }

    /// Live check against the real demo hill embedded in
    /// `Resource.001` (runs only with user-supplied files present).
    #[test]
    fn live_demo_hill() {
        use crate::decrypt;
        let img = std::path::Path::new(
            "/tmp/dsj3-wrap/Data Files/Resources/Resource.001",
        );
        if !img.exists() {
            return;
        }
        let raw = std::fs::read(img).unwrap();
        let blob = decrypt::decrypt(&raw, decrypt::K_RES_HEX).expect("r001");
        // Hill01 entry (offset/size from the decrypted manifest).
        let d = &blob[247684..247684 + 1889];
        let t = std::str::from_utf8(d).unwrap();
        let h = parse(t).unwrap();
        assert_eq!(h.version, "1.4");
        assert_eq!(h.profile_inrun["ls"], 42.0);
        assert_eq!(h.profile_dhill["hk"], 65.0);
        assert_eq!(h.profile_terrain["y0"], -46.0);
        assert_eq!(h.trees_n, 260);
        assert_eq!(h.judgetower_d, 76.3);
    }
}
