//! `3DModels\*.txt` meshes from `Resource.001` (decrypted).
//!
//! Observed (e.g. `judgetower-summer-model.txt`, UTF-8 with BOM):
//! `<3dmodel>` of `<batch id texture1 material fvf order>` with
//! `<vertex id x y z u1 v1/>` and `<face v1 v2 v3/>`. All numbers
//! parse as `f32`/`u32`; unknown attributes are ignored.

use crate::xml;

#[derive(Debug, Clone, PartialEq)]
pub struct Vertex {
    pub x: f32,
    pub y: f32,
    pub z: f32,
    pub u: f32,
    pub v: f32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Face {
    pub v1: u32,
    pub v2: u32,
    pub v3: u32,
}

#[derive(Debug, Clone)]
pub struct Batch {
    pub id: String,
    pub texture: String,
    pub material: String,
    pub vertices: Vec<Vertex>,
    pub faces: Vec<Face>,
}

fn f(e: &xml::Elem, k: &str, ctx: &str) -> Result<f32, String> {
    e.get(k)
        .ok_or_else(|| format!("{ctx} missing @{k}"))?
        .parse::<f32>()
        .map_err(|_| format!("{ctx} bad @{k}"))
}

fn u(e: &xml::Elem, k: &str, ctx: &str) -> Result<u32, String> {
    // Face indices are 1-based in file; keep file values (renderer
    // subtracts 1). `order`/`fvf` use the same reader.
    e.get(k)
        .ok_or_else(|| format!("{ctx} missing @{k}"))?
        .parse::<u32>()
        .map_err(|_| format!("{ctx} bad @{k}"))
}

pub fn parse(text: &str) -> Result<Vec<Batch>, String> {
    let mut batches = Vec::new();
    for (attrs, inner) in xml::collect_nested(text, "batch") {
        let get = |k: &str| {
            attrs.iter().find(|(kk, _)| *kk == k).map(|(_, v)| v.clone()).unwrap_or_default()
        };
        let mut batch = Batch {
            id: get("id"),
            texture: get("texture1"),
            material: get("material"),
            vertices: Vec::new(),
            faces: Vec::new(),
        };
        for v in xml::collect(inner, "vertex") {
            batch.vertices.push(Vertex {
                x: f(&v, "x", "vertex")?,
                y: f(&v, "y", "vertex")?,
                z: f(&v, "z", "vertex")?,
                u: f(&v, "u1", "vertex")?,
                v: f(&v, "v1", "vertex")?,
            });
        }
        for fc in xml::collect(inner, "face") {
            batch.faces.push(Face {
                v1: u(&fc, "v1", "face")?,
                v2: u(&fc, "v2", "face")?,
                v3: u(&fc, "v3", "face")?,
            });
        }
        batches.push(batch);
    }
    if batches.is_empty() {
        return Err("no <batch>".to_string());
    }
    Ok(batches)
}

/// Resolve a batch `texture1` reference (e.g. `Textures\wood1.png`)
/// to decoded RGBA8 pixels. `entries` is `manifest::split` output over
/// the decrypted `Resource.001`; match is exact on the entry id, with
/// a `/`→`\` fallback for slash variants. Decode via `png::decode`.
pub fn texture_pixels(
    entries: &[(&str, &[u8])],
    texture: &str,
) -> Result<crate::png::Image, String> {
    let norm = texture.replace('/', "\\");
    let (_, blob) = entries
        .iter()
        .find(|(id, _)| *id == texture || *id == norm)
        .ok_or_else(|| format!("texture {texture} not in manifest"))?;
    crate::png::decode(blob).map_err(|e| format!("texture {texture}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEMO: &str = "<3dmodel><batch id=\"front\" texture1=\"a.png\" material=\"%m\" fvf=\"274\" order=\"0\">\n<vertex id=\"1\" x=\"0.0\" y=\"-4.0\" z=\"0.0\" u1=\"0.0\" v1=\"-4.0\"/>\n<vertex id=\"2\" x=\"0.0\" y=\"1.0\" z=\"0.0\" u1=\"0.0\" v1=\"1.0\"/>\n<face v1=\"1\" v2=\"2\" v3=\"1\"/>\n</batch></3dmodel>";

    #[test]
    fn quad_batch() {
        let b = parse(DEMO).unwrap();
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].texture, "a.png");
        assert_eq!(b[0].vertices.len(), 2);
        assert_eq!(b[0].vertices[0].y, -4.0);
        assert_eq!(b[0].faces, vec![Face { v1: 1, v2: 2, v3: 1 }]);
    }

    /// Generated fixture PNG (never original bytes): resolve by entry
    /// id, accept `/` variant, miss otherwise.
    #[test]
    fn texture_resolves_to_pixels() {
        let rgba = [255, 0, 0, 255];
        let mut enc = Vec::new();
        let mut e = png::Encoder::new(&mut enc, 1, 1);
        e.set_color(png::ColorType::Rgba);
        e.set_depth(png::BitDepth::Eight);
        e.write_header().unwrap().write_image_data(&rgba).unwrap();
        let entries = vec![("Textures\\a.png", enc.as_slice())];
        let img = texture_pixels(&entries, "Textures\\a.png").unwrap();
        assert_eq!((img.width, img.height), (1, 1));
        assert_eq!(img.pixels, rgba);
        let img2 = texture_pixels(&entries, "Textures/a.png").unwrap();
        assert_eq!(img2.pixels, rgba);
        assert!(texture_pixels(&entries, "Textures\\missing.png").is_err());
    }

    /// Live check: every `judgetower-summer-model.txt` batch texture
    /// resolves to non-empty RGBA8. Skips when install dir absent.
    /// (`sj-model.txt` not used: its `x=" 0.00"` leading-space values
    /// predate this helper and fail `model::parse`; out of scope.)
    #[test]
    fn live_batch_textures_decode() {
        let res = std::path::Path::new("/tmp/dsj3-wrap/Data Files/Resources");
        if !res.join("Resource.000").exists() || !res.join("Resource.001").exists() {
            return;
        }
        let img0 = std::fs::read(res.join("Resource.000")).unwrap();
        let plain0 =
            crate::decrypt::decrypt(&img0, crate::decrypt::K_RES_HEX).unwrap();
        let m =
            crate::manifest::parse(&String::from_utf16le_lossy(&plain0)).unwrap();
        let img1 = std::fs::read(res.join("Resource.001")).unwrap();
        let plain1 =
            crate::decrypt::decrypt(&img1, crate::decrypt::K_RES_HEX).unwrap();
        let entries = crate::manifest::split(&m, &plain1).unwrap();
        let (_, model_blob) = entries
            .iter()
            .find(|(id, _)| *id == "3DModels\\judgetower-summer-model.txt")
            .expect("judgetower-summer-model.txt in manifest");
        let text = String::from_utf8_lossy(model_blob).into_owned();
        let batches = parse(&text).unwrap();
        assert!(!batches.is_empty());
        for b in &batches {
            let img = texture_pixels(&entries, &b.texture)
                .unwrap_or_else(|e| panic!("{}: {e}", b.texture));
            assert!(img.width > 0 && img.height > 0, "{}", b.texture);
            assert_eq!(
                img.pixels.len(),
                img.width as usize * img.height as usize * 4,
                "{}",
                b.texture
            );
        }
    }
}
