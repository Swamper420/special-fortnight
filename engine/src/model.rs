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
}
