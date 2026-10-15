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

    /// Live check over all 4 in-blob demo hills (Phase 2 demo scope):
    /// located via the decrypted `Resource.000` manifest, each must
    /// parse with the full profile key sets (10/15/12). Skips when
    /// user-supplied files are absent; never commits original bytes.
    #[test]
    fn live_all_demo_hills() {
        use crate::decrypt;
        let r000 = std::path::Path::new(
            "/tmp/dsj3-wrap/Data Files/Resources/Resource.000",
        );
        let r001 = std::path::Path::new(
            "/tmp/dsj3-wrap/Data Files/Resources/Resource.001",
        );
        if !r000.exists() || !r001.exists() {
            return;
        }
        let mraw = std::fs::read(r000).unwrap();
        let mplain = decrypt::decrypt(&mraw, decrypt::K_RES_HEX).expect("r000");
        let mtext = String::from_utf16le_lossy(&mplain);
        let m = crate::manifest::parse(&mtext).expect("manifest");
        let raw = std::fs::read(r001).unwrap();
        let blob = decrypt::decrypt(&raw, decrypt::K_RES_HEX).expect("r001");
        let hills: Vec<_> =
            m.entries.iter().filter(|e| e.id.ends_with(".hil")).collect();
        assert_eq!(hills.len(), 4);
        for e in hills {
            let (s, len) = (e.offset as usize, e.size as usize);
            let t = std::str::from_utf8(&blob[s..s + len])
                .unwrap_or_else(|_| panic!("{} utf8", e.id));
            let h = parse(t).unwrap_or_else(|_| panic!("{} parse", e.id));
            assert_eq!(h.version, "1.4", "{}", e.id);
            assert_eq!(h.profile_inrun.len(), 10, "{}", e.id);
            assert_eq!(h.profile_dhill.len(), 15, "{}", e.id);
            assert_eq!(h.profile_terrain.len(), 12, "{}", e.id);
            for k in ["lz", "ls", "lg", "as", "rc", "lt", "at", "ht", "tz", "ws"] {
                assert!(h.profile_inrun.contains_key(k), "{} inrun @{k}", e.id);
            }
            for k in [
                "a0", "ak", "hk", "nk", "rl", "l1", "l2", "rs", "lb", "hr",
                "nr", "ar", "w0", "wk", "wb",
            ] {
                assert!(h.profile_dhill.contains_key(k), "{} dhill @{k}", e.id);
            }
            for k in [
                "in", "dh", "a0", "l0", "y0", "az", "ax", "l1", "l2", "d1",
                "d2", "rs",
            ] {
                assert!(h.profile_terrain.contains_key(k), "{} terrain @{k}", e.id);
            }
            for v in h
                .profile_inrun
                .values()
                .chain(h.profile_dhill.values())
                .chain(h.profile_terrain.values())
            {
                assert!(v.is_finite(), "{} non-finite", e.id);
            }
            assert!(h.trees_n > 0, "{}", e.id);
        }
    }

    // Full-shape generated fixture: all observed profile keys with
    // generated values (mirrors the 10/15/12 key sets live).
    const DEMO_FULL: &str = "<hill version=\"1.4\"><inrun><profile lz=\"3.0\" ls=\"42.0\" lg=\"1.0\" as=\"2.0\" rc=\"4.0\" lt=\"5.0\" at=\"6.0\" ht=\"7.0\" tz=\"8.0\" ws=\"9.0\"/></inrun><dhill><profile a0=\"10.0\" ak=\"44.0\" hk=\"65.0\" nk=\"1.0\" rl=\"2.0\" l1=\"3.0\" l2=\"4.0\" rs=\"5.0\" lb=\"6.0\" hr=\"7.0\" nr=\"8.0\" ar=\"9.0\" w0=\"11.0\" wk=\"12.0\" wb=\"13.0\"/><judgetower d=\"76.3\" z=\"1.5\"/></dhill><terrain><profile in=\"0.87\" dh=\"0.4\" a0=\"1.0\" l0=\"2.0\" y0=\"-46.0\" az=\"1.7f\" ax=\"3.0\" l1=\"4.0\" l2=\"5.0\" d1=\"6.0\" d2=\"7.0\" rs=\"8.0\"/><trees n=\"260\"/></terrain></hill>";

    #[test]
    fn full_profile_keys() {
        let h = parse(DEMO_FULL).unwrap();
        assert_eq!(h.profile_inrun.len(), 10);
        assert_eq!(h.profile_dhill.len(), 15);
        assert_eq!(h.profile_terrain.len(), 12);
        // 'f'-suffixed floats (e.g. az="1.7f") parse as floats.
        assert!((h.profile_terrain["az"] - 1.7).abs() < 1e-6);
    }
}
