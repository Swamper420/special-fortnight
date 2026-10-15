//! Software wireframe renderer (headless proof, no GPU/window).
//!
//! Orthographic projection + Bresenham segments into a byte buffer.
//! Exists so Phase 1's viewer milestone is asserted in CI
//! (`cargo test -p engine`); GPU backends only add presentation.

use crate::model::Batch;

/// Orthographic camera: looks down -z, x right, y up.
pub struct Cam {
    pub scale: f32,
    pub cx: f32,
    pub cy: f32,
}

pub fn project(v: &crate::model::Vertex, cam: &Cam, w: u32, h: u32) -> (i32, i32) {
    let x = (w as f32 / 2.0 + (v.x - cam.cx) * cam.scale) as i32;
    let y = (h as f32 / 2.0 - (v.y - cam.cy) * cam.scale) as i32;
    let _ = h;
    (x, y)
}

/// Draw all batch faces as segments. Returns lit-pixel count.
pub fn wireframe(buf: &mut [u8], w: u32, h: u32, batches: &[Batch], cam: &Cam) -> usize {
    let mut lit = 0usize;
    let mut dot = |x: i32, y: i32| {
        if x >= 0 && y >= 0 && (x as u32) < w && (y as u32) < h {
            let i = (y as u32 * w + x as u32) as usize;
            if buf[i] == 0 {
                buf[i] = 1;
                lit += 1;
            }
        }
    };
    for b in batches {
        for f in &b.faces {
            // Face indices are 1-based in file.
            let idx = [f.v1 as usize, f.v2 as usize, f.v3 as usize, f.v1 as usize];
            let pts: Vec<(i32, i32)> = idx
                .iter()
                .filter_map(|&k| b.vertices.get(k.wrapping_sub(1)))
                .map(|v| project(v, cam, w, h))
                .collect();
            for w2 in pts.windows(2) {
                let ((mut x0, mut y0), (x1, y1)) = (w2[0], w2[1]);
                let (dx, dy) = ((x1 - x0).abs(), -(y1 - y0).abs());
                let (sx, sy) = (if x0 < x1 { 1 } else { -1 }, if y0 < y1 { 1 } else { -1 });
                let mut err = dx + dy;
                loop {
                    dot(x0, y0);
                    if x0 == x1 && y0 == y1 {
                        break;
                    }
                    let e2 = 2 * err;
                    if e2 >= dy {
                        err += dy;
                        x0 += sx;
                    }
                    if e2 <= dx {
                        err += dx;
                        y0 += sy;
                    }
                }
            }
        }
    }
    lit
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quad() -> Vec<Batch> {
        vec![Batch {
            id: "q".into(),
            texture: String::new(),
            material: String::new(),
            vertices: vec![
                crate::model::Vertex { x: 0.0, y: 0.0, z: 0.0, u: 0.0, v: 0.0 },
                crate::model::Vertex { x: 10.0, y: 0.0, z: 0.0, u: 0.0, v: 0.0 },
                crate::model::Vertex { x: 10.0, y: 10.0, z: 0.0, u: 0.0, v: 0.0 },
                crate::model::Vertex { x: 0.0, y: 10.0, z: 0.0, u: 0.0, v: 0.0 },
            ],
            faces: vec![
                crate::model::Face { v1: 1, v2: 2, v3: 3 },
                crate::model::Face { v1: 1, v2: 3, v3: 4 },
            ],
        }]
    }

    #[test]
    fn draws_quad_stably() {
        let cam = Cam { scale: 4.0, cx: 5.0, cy: 5.0 };
        let (w, h) = (100, 100);
        let mut buf = vec![0u8; (w * h) as usize];
        let n = wireframe(&mut buf, w, h, &quad(), &cam);
        // 40x40 Fel edges: perimeter-ish pixel count, stable across runs.
        assert!(n > 100 && n < 400, "lit={n}");
        let mut buf2 = vec![0u8; (w * h) as usize];
        let n2 = wireframe(&mut buf2, w, h, &quad(), &cam);
        assert_eq!((n, buf), (n2, buf2));
    }

    /// Live check: real judgetower model renders non-empty.
    #[test]
    fn live_judgetower_renders() {
        use crate::{decrypt, manifest, model};
        let img = std::path::Path::new(
            "/tmp/dsj3-wrap/Data Files/Resources/Resource.001",
        );
        if !img.exists() {
            return;
        }
        let raw = std::fs::read(img).unwrap();
        let blob = decrypt::decrypt(&raw, decrypt::K_RES_HEX).unwrap();
        // Find judgetower entry via manifest.
        let r0 = std::fs::read("/tmp/dsj3-wrap/Data Files/Resources/Resource.000").unwrap();
        let p0 = decrypt::decrypt(&r0, decrypt::K_RES_HEX).unwrap();
        let m = manifest::parse(&String::from_utf16le_lossy(&p0)).unwrap();
        let e = m.entries.iter().find(|e| e.id.contains("judgetower-summer-model")).unwrap();
        let data = &blob[e.offset as usize..e.offset as usize + e.size as usize];
        let batches = model::parse(String::from_utf8_lossy(data).as_ref()).unwrap();
        let cam = Cam { scale: 6.0, cx: 0.75, cy: -1.5 };
        let (w, h) = (160, 120);
        let mut buf = vec![0u8; (w * h) as usize];
        let n = wireframe(&mut buf, w, h, &batches, &cam);
        assert!(n > 50, "lit={n}");
    }
}
