//! Software wireframe renderer (headless proof, no GPU/window).
//!
//! Orthographic projection + Bresenham segments into a byte buffer.
//! Exists so Phase 1's viewer milestone is asserted in CI
//! (`cargo test -p engine`); GPU backends only add presentation.

use crate::model::{Batch, Face, Vertex};

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

/// Pack an X-monotone strip polyline (e.g. inrun b50 emits) as
/// degenerate faces (`a,b,b` draws segment `a-b`) so the existing
/// `wireframe` rasterizes it with no new draw code.
pub fn strip_batch(points: &[(f32, f32)]) -> Batch {
    Batch {
        id: "strip".into(),
        texture: String::new(),
        material: String::new(),
        vertices: points
            .iter()
            .map(|&(x, y)| Vertex { x, y, z: 0.0, u: 0.0, v: 0.0 })
            .collect(),
        faces: (1..points.len() as u32).map(|i| Face { v1: i, v2: i + 1, v3: i + 1 }).collect(),
    }
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

/// Nearest-neighbor textured fill for all batch faces into an RGB
/// buffer (`buf.len() == w*h*3`). Reuses `project`; barycentric UV
/// interpolation, clamped to edge. One texture for all faces — the
/// caller resolves per-batch pixels with `model::texture_pixels`.
/// `v = 0` is the texture top row (`png::Image` order); the original
/// V orientation is unproven (see open unknowns in report). Returns
/// covered-pixel count.
pub fn textured_rgb(
    buf: &mut [u8],
    w: u32,
    h: u32,
    batches: &[Batch],
    tex: &crate::png::Image,
    cam: &Cam,
) -> usize {
    assert_eq!(buf.len(), (w * h * 3) as usize);
    if tex.width == 0 || tex.height == 0 || tex.pixels.is_empty() {
        return 0;
    }
    let edge = |ax: i32, ay: i32, bx: i32, by: i32, cx: i32, cy: i32| -> i32 {
        (cx - ax) * (by - ay) - (cy - ay) * (bx - ax)
    };
    let mut seen = vec![false; (w * h) as usize];
    let mut n = 0usize;
    for b in batches {
        for f in &b.faces {
            let vs = [f.v1, f.v2, f.v3].iter().filter_map(|k| b.vertices.get(k.wrapping_sub(1) as usize)).collect::<Vec<_>>();
            if vs.len() != 3 {
                continue;
            }
            let ps = [project(vs[0], cam, w, h), project(vs[1], cam, w, h), project(vs[2], cam, w, h)];
            let area = edge(ps[0].0, ps[0].1, ps[1].0, ps[1].1, ps[2].0, ps[2].1);
            if area == 0 {
                continue;
            }
            let (mut lox, mut hix) = (ps[0].0.min(ps[1].0).min(ps[2].0), ps[0].0.max(ps[1].0).max(ps[2].0));
            let (mut loy, mut hiy) = (ps[0].1.min(ps[1].1).min(ps[2].1), ps[0].1.max(ps[1].1).max(ps[2].1));
            lox = lox.max(0);
            loy = loy.max(0);
            hix = hix.min(w as i32 - 1);
            hiy = hiy.min(h as i32 - 1);
            let af = area as f32;
            for y in loy..=hiy {
                for x in lox..=hix {
                    let w0 = edge(ps[1].0, ps[1].1, ps[2].0, ps[2].1, x, y);
                    let w1 = edge(ps[2].0, ps[2].1, ps[0].0, ps[0].1, x, y);
                    let w2 = edge(ps[0].0, ps[0].1, ps[1].0, ps[1].1, x, y);
                    let inside = if area > 0 { w0 >= 0 && w1 >= 0 && w2 >= 0 } else { w0 <= 0 && w1 <= 0 && w2 <= 0 };
                    if !inside {
                        continue;
                    }
                    let u = (w0 as f32 * vs[0].u + w1 as f32 * vs[1].u + w2 as f32 * vs[2].u) / af;
                    let v = (w0 as f32 * vs[0].v + w1 as f32 * vs[1].v + w2 as f32 * vs[2].v) / af;
                    let tx = ((u * tex.width as f32).floor() as i32).clamp(0, tex.width as i32 - 1);
                    let ty = ((v * tex.height as f32).floor() as i32).clamp(0, tex.height as i32 - 1);
                    let ti = ((ty as u32 * tex.width + tx as u32) as usize) * 4;
                    let di = ((y as u32 * w + x as u32) as usize) * 3;
                    buf[di..di + 3].copy_from_slice(&tex.pixels[ti..ti + 3]);
                    if !seen[(y as u32 * w + x as u32) as usize] {
                        seen[(y as u32 * w + x as u32) as usize] = true;
                        n += 1;
                    }
                }
            }
        }
    }
    n
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

    /// Textured-quad proof: 2x2 generated RGBA fixture fills a batch
    /// quad; each quadrant samples its texel + re-render deterministic.
    #[test]
    fn textured_quad_samples_colors() {
        // Generated fixture (never original bytes): top row
        // red/green, bottom row blue/white; v=0 is the top row.
        let tex = crate::png::Image {
            width: 2,
            height: 2,
            pixels: vec![
                255, 0, 0, 255, 0, 255, 0, 255,
                0, 0, 255, 255, 255, 255, 255, 255,
            ],
        };
        let batches = vec![Batch {
            id: "q".into(),
            texture: "Textures\\q.png".into(),
            material: String::new(),
            vertices: vec![
                Vertex { x: 0.0, y: 0.0, z: 0.0, u: 0.0, v: 0.0 },
                Vertex { x: 1.0, y: 0.0, z: 0.0, u: 1.0, v: 0.0 },
                Vertex { x: 1.0, y: 1.0, z: 0.0, u: 1.0, v: 1.0 },
                Vertex { x: 0.0, y: 1.0, z: 0.0, u: 0.0, v: 1.0 },
            ],
            faces: vec![Face { v1: 1, v2: 2, v3: 3 }, Face { v1: 1, v2: 3, v3: 4 }],
        }];
        // Quad exactly covers the 64x64 frame; world y=1 (v=1) is up.
        let cam = Cam { scale: 64.0, cx: 0.5, cy: 0.5 };
        let (w, h) = (64, 64);
        let px = |buf: &[u8], x: u32, y: u32| -> [u8; 3] {
            let i = ((y * w + x) as usize) * 3;
            [buf[i], buf[i + 1], buf[i + 2]]
        };
        let mut buf = vec![0u8; (w * h * 3) as usize];
        let n = textured_rgb(&mut buf, w, h, &batches, &tex, &cam);
        assert!(n > 3000, "n={n}");
        // Screen top (y=0) is v=1: blue/white; bottom is v=0: red/green.
        assert_eq!(px(&buf, 16, 16), [0, 0, 255]);
        assert_eq!(px(&buf, 48, 16), [255, 255, 255]);
        assert_eq!(px(&buf, 16, 48), [255, 0, 0]);
        assert_eq!(px(&buf, 48, 48), [0, 255, 0]);
        let mut buf2 = vec![0u8; (w * h * 3) as usize];
        assert_eq!(textured_rgb(&mut buf2, w, h, &batches, &tex, &cam), n);
        assert_eq!(buf, buf2);
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

    /// Live check: real judgetower model textured-fill renders
    /// non-empty. Per-batch textures via `model::texture_pixels`
    /// (batches whose texture misses skip); no color asserts (V
    /// orientation unproven). Skips when install dir absent.
    #[test]
    fn live_judgetower_textured_renders() {
        use crate::{decrypt, manifest, model};
        let res = std::path::Path::new("/tmp/dsj3-wrap/Data Files/Resources");
        if !res.join("Resource.000").exists() || !res.join("Resource.001").exists() {
            return;
        }
        let plain0 = decrypt::decrypt(
            &std::fs::read(res.join("Resource.000")).unwrap(),
            decrypt::K_RES_HEX,
        )
        .unwrap();
        let m = manifest::parse(&String::from_utf16le_lossy(&plain0)).unwrap();
        let plain1 = decrypt::decrypt(
            &std::fs::read(res.join("Resource.001")).unwrap(),
            decrypt::K_RES_HEX,
        )
        .unwrap();
        let entries = manifest::split(&m, &plain1).unwrap();
        let (_, model_blob) = entries
            .iter()
            .find(|(id, _)| id.contains("judgetower-summer-model"))
            .unwrap();
        let batches = model::parse(&String::from_utf8_lossy(model_blob)).unwrap();
        let cam = Cam { scale: 6.0, cx: 0.75, cy: -1.5 };
        let (w, h) = (160, 120);
        let mut buf = vec![0u8; (w * h * 3) as usize];
        let mut covered = 0usize;
        let mut drew = 0usize;
        for b in &batches {
            let tex = match model::texture_pixels(&entries, &b.texture) {
                Ok(t) => t,
                Err(_) => continue,
            };
            covered += textured_rgb(&mut buf, w, h, std::slice::from_ref(b), &tex, &cam);
            drew += 1;
        }
        if drew == 0 {
            return;
        }
        assert!(covered > 0, "covered={covered} drew={drew}");
        eprintln!("live judgetower textured: batches={} drew={drew} covered={covered}", batches.len());
        let mut buf2 = vec![0u8; (w * h * 3) as usize];
        let mut covered2 = 0usize;
        for b in &batches {
            let tex = match model::texture_pixels(&entries, &b.texture) {
                Ok(t) => t,
                Err(_) => continue,
            };
            covered2 += textured_rgb(&mut buf2, w, h, std::slice::from_ref(b), &tex, &cam);
        }
        assert_eq!(covered, covered2);
        assert_eq!(buf, buf2);
    }

    /// End-to-end inrun b50 strip, headless (`evidence/004ddae0_emit_check.md`
    /// + `evidence/00434020_esp_shift.md`): `Inrun::anchors/moveto` →
    /// `StripCursor` emits (`dda60` open, `ddae0` ×3, `dd970` seal) →
    /// `strip_batch` + `wireframe` pixels. Generated Hill01-equivalent
    /// fixture (live `Hill01-HS138.hil` values); asserts emitted X
    /// strictly increases and the polyline lights pixels.
    #[test]
    fn inrun_strip_renders_headless() {
        use crate::mesh::{EmitAction, EmitErr, Inrun, StripCursor};
        // Generated fixture: Hill01 inrun profile values.
        let ir = Inrun {
            lz: 3.0,
            ls: 42.0,
            lg: 4.7,
            as_: 44.2,
            rc: 50.0,
            lt: 4.6,
            at: 10.5,
            ht: 1.7,
            tz: -0.3,
            ws: 3.0,
        };
        let (m, l1) = (ir.moveto(true), ir.lineto1(true));
        let p2 = ir.anchors(true)[2];
        let end = (0.0, ir.ht); // b50 `ddae0(0, ht)`.
        // b50 order must be X-monotone or the game throws (Decrease).
        assert!(m.0 < l1.0 && l1.0 < p2.0 && p2.0 < end.0, "m={m:?} l1={l1:?} p2={p2:?}");
        let mut s = StripCursor::open(m.0, m.1);
        let mut pts = vec![m];
        for &(x, y) in &[l1, p2, end] {
            assert_eq!(s.push(x, y), Ok(EmitAction::Emit));
            pts.push((s.x, s.y));
        }
        // Equal-X drops silently (no cursor/count move).
        let c = s.count;
        assert_eq!(s.push(end.0, 99.0), Ok(EmitAction::IgnoreEqual));
        assert_eq!((s.x, s.count), (end.0, c));
        // Decrease throws; seal ends the strip like `dd970`.
        assert_eq!(s.push(end.0 - 1.0, 0.0), Err(EmitErr::Decrease));
        s.seal();
        assert_eq!(s.push(1.0, 0.0), Err(EmitErr::Closed));
        // Render: frame the strip, draw, require lit + screen-X monotone.
        let (lox, hix) = (pts[0].0, pts[3].0);
        let (mut loy, mut hiy) = (f32::INFINITY, f32::NEG_INFINITY);
        for &(_, y) in &pts {
            loy = loy.min(y);
            hiy = hiy.max(y);
        }
        let cam = Cam { scale: 3.0, cx: (lox + hix) / 2.0, cy: (loy + hiy) / 2.0 };
        let (w, h) = (220, 140);
        let batch = strip_batch(&pts);
        let mut buf = vec![0u8; (w * h) as usize];
        let n = wireframe(&mut buf, w, h, &[batch], &cam);
        assert!(n > 100, "lit={n}");
        let sx: Vec<i32> = pts
            .iter()
            .map(|&(x, y)| {
                project(&Vertex { x, y, z: 0.0, u: 0.0, v: 0.0 }, &cam, w, h).0
            })
            .collect();
        assert!(sx.windows(2).all(|p| p[0] < p[1]), "sx={sx:?}");
        let mut buf2 = vec![0u8; (w * h) as usize];
        assert_eq!(wireframe(&mut buf2, w, h, &[strip_batch(&pts)], &cam), n);
        assert_eq!(buf, buf2);
    }

    /// End-to-end inrun b58 width strip, headless
    /// (`evidence/004ddae0_emit_check.md` §3 b58:
    /// `dda60(P3.x-lz, ws*0.5)`, `ddae0(0, ws*0.5)`, `dd970`):
    /// `Inrun::anchors/moveto` → `StripCursor` emit →
    /// `strip_batch` + `wireframe` pixels. Generated
    /// Hill01-inrun-equivalent fixture (lz=3, ws=3, P3 from
    /// anchors); asserts emitted X strictly increases and
    /// the polyline lights pixels.
    #[test]
    fn inrun_b58_strip_renders_headless() {
        use crate::mesh::{EmitAction, EmitErr, Inrun, StripCursor};
        // Generated fixture: Hill01 inrun profile values (mirror b50 test).
        let ir = Inrun {
            lz: 3.0,
            ls: 42.0,
            lg: 4.7,
            as_: 44.2,
            rc: 50.0,
            lt: 4.6,
            at: 10.5,
            ht: 1.7,
            tz: -0.3,
            ws: 3.0,
        };
        let p3 = ir.anchors(true)[3];
        // b58 wiring (§3): dda60(P3.x-lz, ws*0.5); ddae0(0, ws*0.5).
        let open = (p3.0 - ir.lz, ir.ws * 0.5);
        let end = (0.0, ir.ws * 0.5);
        // b58 order must be X-monotone or the game throws (Decrease).
        assert!(open.0 < end.0, "open={open:?} end={end:?}");
        let mut s = StripCursor::open(open.0, open.1);
        let mut pts = vec![open];
        assert_eq!(s.push(end.0, end.1), Ok(EmitAction::Emit));
        pts.push((s.x, s.y));
        // Equal-X drops silently (no cursor/count move).
        let c = s.count;
        assert_eq!(s.push(end.0, 99.0), Ok(EmitAction::IgnoreEqual));
        assert_eq!((s.x, s.count), (end.0, c));
        // Decrease throws; seal ends the strip like `dd970`.
        assert_eq!(s.push(end.0 - 1.0, 0.0), Err(EmitErr::Decrease));
        s.seal();
        assert_eq!(s.push(1.0, 0.0), Err(EmitErr::Closed));
        // Render: frame the strip, draw, require lit + screen-X monotone.
        let (lox, hix) = (pts[0].0, pts[1].0);
        let (mut loy, mut hiy) = (f32::INFINITY, f32::NEG_INFINITY);
        for &(_, y) in &pts {
            loy = loy.min(y);
            hiy = hiy.max(y);
        }
        let cam = Cam { scale: 3.0, cx: (lox + hix) / 2.0, cy: (loy + hiy) / 2.0 };
        let (w, h) = (220, 140);
        let batch = strip_batch(&pts);
        let mut buf = vec![0u8; (w * h) as usize];
        let n = wireframe(&mut buf, w, h, &[batch], &cam);
        assert!(n > 100, "lit={n}");
        let sx: Vec<i32> = pts
            .iter()
            .map(|&(x, y)| {
                project(&Vertex { x, y, z: 0.0, u: 0.0, v: 0.0 }, &cam, w, h).0
            })
            .collect();
        assert!(sx.windows(2).all(|p| p[0] < p[1]), "sx={sx:?}");
        let mut buf2 = vec![0u8; (w * h) as usize];
        assert_eq!(wireframe(&mut buf2, w, h, &[strip_batch(&pts)], &cam), n);
        assert_eq!(buf, buf2);
    }

    /// End-to-end landing b68 width strip, headless
    /// (`evidence/00434390_emit_args.md` §3 b68:
    /// `dda60(0,w0*0.5)`, 3x `ddae0`, `ddf10`, `dd970`):
    /// `Landing::anchors` → `StripCursor` emits → `strip_batch` +
    /// `wireframe` pixels. Generated dhill-equivalent fixture (same
    /// values as `mesh.rs` `landing_anchors_endpoints`); asserts
    /// emitted X strictly increases and the polyline lights pixels.
    #[test]
    fn landing_b68_strip_renders_headless() {
        use crate::mesh::{EmitAction, EmitErr, Landing, StripCursor};
        // Generated fixture: dhill profile values (mirror landing test).
        let mut m = std::collections::HashMap::new();
        for (k, v) in [
            ("a0", 10.0), ("ak", 44.0), ("hk", 65.0), ("nk", 1.0),
            ("rl", 120.0), ("l1", 8.0), ("l2", 12.0), ("rs", 60.0),
            ("lb", 5.0), ("hr", 3.0), ("nr", 40.0), ("ar", 35.0),
            ("w0", 6.0), ("wk", 6.5), ("wb", 7.0),
        ] {
            m.insert(k.to_string(), v);
        }
        let la = Landing::from_map(&m).unwrap();
        let a = la.anchors(true);
        // b68 wiring (§3): dda60(0, w0*0.5); ddae0(nk, wk*0.5);
        // ddae0(L4x, wb*0.5); ddae0(N11-wb*0.5, wb*0.5);
        // ddf10(N11, 0, N11-wb*0.5, 0) → cursor (N11, 0).
        let (w0h, wkh, wbh) = (la.w0 * 0.5, la.wk * 0.5, la.wb * 0.5);
        let open = (0.0f32, w0h);
        let p1 = (la.nk, wkh);
        let p2 = (a.l4x, wbh);
        let p3 = (a.n11 - wbh, wbh);
        let end = (a.n11, 0.0);
        // b68 order must be X-monotone or the game throws (Decrease).
        assert!(
            open.0 < p1.0 && p1.0 < p2.0 && p2.0 < p3.0 && p3.0 < end.0,
            "open={open:?} p1={p1:?} p2={p2:?} p3={p3:?} end={end:?}"
        );
        let mut s = StripCursor::open(open.0, open.1);
        let mut pts = vec![open];
        for &(x, y) in &[p1, p2, p3, end] {
            assert_eq!(s.push(x, y), Ok(EmitAction::Emit));
            pts.push((s.x, s.y));
        }
        // Equal-X drops silently (no cursor/count move).
        let c = s.count;
        assert_eq!(s.push(end.0, 99.0), Ok(EmitAction::IgnoreEqual));
        assert_eq!((s.x, s.count), (end.0, c));
        // Decrease throws; seal ends the strip like `dd970`.
        assert_eq!(s.push(end.0 - 1.0, 0.0), Err(EmitErr::Decrease));
        s.seal();
        assert_eq!(s.push(1.0, 0.0), Err(EmitErr::Closed));
        // Render: frame the strip, draw, require lit + screen-X monotone.
        let (lox, hix) = (pts[0].0, pts[4].0);
        let (mut loy, mut hiy) = (f32::INFINITY, f32::NEG_INFINITY);
        for &(_, y) in &pts {
            loy = loy.min(y);
            hiy = hiy.max(y);
        }
        let cam = Cam { scale: 3.0, cx: (lox + hix) / 2.0, cy: (loy + hiy) / 2.0 };
        let (w, h) = (220, 140);
        let batch = strip_batch(&pts);
        let mut buf = vec![0u8; (w * h) as usize];
        let n = wireframe(&mut buf, w, h, &[batch], &cam);
        assert!(n > 100, "lit={n}");
        let sx: Vec<i32> = pts
            .iter()
            .map(|&(x, y)| {
                project(&Vertex { x, y, z: 0.0, u: 0.0, v: 0.0 }, &cam, w, h).0
            })
            .collect();
        assert!(sx.windows(2).all(|p| p[0] < p[1]), "sx={sx:?}");
        let mut buf2 = vec![0u8; (w * h) as usize];
        assert_eq!(wireframe(&mut buf2, w, h, &[strip_batch(&pts)], &cam), n);
        assert_eq!(buf, buf2);
    }

    /// End-to-end landing b60 profile strip, headless
    /// (`evidence/00434390_emit_args.md` §4 b60:
    /// `dda60(0,0)`, `ddcb0`, `ddf10`, `ddf10`, `ddae0`,
    /// `ddcb0`, 10x samples, `dd970`):
    /// `landing_build` → `strip_batch(b60)` + `wireframe` pixels.
    /// Fixture dhill values mirror `mesh.rs`
    /// `landing_anchors_endpoints`; live Hill01 dhill via manifest
    /// locate when user-supplied files present. Asserts world-X
    /// monotone, lit pixels, screen-X monotone, deterministic
    /// re-render.
    #[test]
    fn landing_b60_strip_renders_headless() {
        use crate::mesh::{Landing, landing_build};
        fn fixture() -> Landing {
            // Hill01-equivalent fixture (live Hill01-HS138.hil dhill
            // values): the synthetic `landing_anchors_endpoints`
            // values (nk=1, rl=120, ar=35, ...) throw Decrease inside
            // `landing_build`, so they cannot drive a render proof.
            let mut m = std::collections::HashMap::new();
            for (k, v) in [
                ("a0", 10.0), ("ak", 44.0), ("hk", 65.0), ("nk", 93.0),
                ("rl", 350.0), ("l1", 14.0), ("l2", 23.0), ("rs", 140.0),
                ("lb", 35.0), ("hr", 5.0), ("nr", 35.0), ("ar", 5.0),
                ("w0", 3.5), ("wk", 26.0), ("wb", 32.4),
            ] {
                m.insert(k.to_string(), v);
            }
            Landing::from_map(&m).unwrap()
        }
        fn render_assert(pts: &[(f32, f32)]) {
            assert!(pts.len() >= 2, "len={}", pts.len());
            assert!(
                pts.windows(2).all(|w| w[0].0 < w[1].0),
                "world-X monotone"
            );
            let (lox, hix) = (pts[0].0, pts[pts.len() - 1].0);
            let (mut loy, mut hiy) = (f32::INFINITY, f32::NEG_INFINITY);
            for &(_, y) in pts {
                loy = loy.min(y);
                hiy = hiy.max(y);
            }
            let cam = Cam { scale: 3.0, cx: (lox + hix) / 2.0, cy: (loy + hiy) / 2.0 };
            // b60 spans ~270x113m (Hill01); b68's 220x140 would clip
            // it to lit=34. 900x400 frames it whole at the same scale
            // (all 75 fixture points in range, screen-X still strict).
            let (w, h) = (900, 400);
            let batch = strip_batch(pts);
            let mut buf = vec![0u8; (w * h) as usize];
            let n = wireframe(&mut buf, w, h, &[batch], &cam);
            assert!(n > 100, "lit={n}");
            let sx: Vec<i32> = pts
                .iter()
                .map(|&(x, y)| {
                    project(&Vertex { x, y, z: 0.0, u: 0.0, v: 0.0 }, &cam, w, h).0
                })
                .collect();
            assert!(sx.windows(2).all(|p| p[0] < p[1]), "sx={sx:?}");
            let mut buf2 = vec![0u8; (w * h) as usize];
            assert_eq!(wireframe(&mut buf2, w, h, &[strip_batch(pts)], &cam), n);
            assert_eq!(buf, buf2);
        }
        // Fixture fallback (Hill01-equivalent values above).
        let b = landing_build(&fixture()).unwrap();
        eprintln!("fixture landing b60={} b68={} samples={}", b.b60.len(), b.b68.len(), b.samples.len());
        render_assert(&b.b60);
        // Live Hill01 dhill via manifest locate, skipped when absent.
        let (r000, r001) = (
            std::path::Path::new("/tmp/dsj3-wrap/Data Files/Resources/Resource.000"),
            std::path::Path::new("/tmp/dsj3-wrap/Data Files/Resources/Resource.001"),
        );
        if !r000.exists() || !r001.exists() {
            return;
        }
        let mraw = std::fs::read(r000).unwrap();
        let mplain = crate::decrypt::decrypt(&mraw, crate::decrypt::K_RES_HEX).unwrap();
        let man = crate::manifest::parse(&String::from_utf16le_lossy(&mplain)).unwrap();
        let e = man
            .entries
            .iter()
            .find(|e| e.id.contains("Hill01"))
            .or_else(|| man.entries.iter().find(|e| e.id.ends_with(".hil")))
            .unwrap();
        let raw = std::fs::read(r001).unwrap();
        let blob = crate::decrypt::decrypt(&raw, crate::decrypt::K_RES_HEX).unwrap();
        let t = std::str::from_utf8(&blob[e.offset as usize..e.offset as usize + e.size as usize]).unwrap();
        let h = crate::hill::parse(t).unwrap();
        let live = Landing::from_map(&h.profile_dhill).unwrap();
        let lb = landing_build(&live).unwrap();
        eprintln!("live {} landing b60={} b68={} samples={}", e.id, lb.b60.len(), lb.b68.len(), lb.samples.len());
        render_assert(&lb.b60);
    }

    /// Full-scene transform proof (`evidence/00455ba0_render_assets.md`
    /// §4 + `evidence/00409060_submit.md` §4 U3): tree-loop caller
    /// composes `(R×S)×T` via `0046f9f0`/`0046fa40`/`0046f910` +
    /// `0046efc0` × 2, submits the single buffer via `00409060`.
    /// Applies that product (matrix fns only) to batch vertices, then
    /// `textured_rgb` fill. Generated quad fixture + live
    /// judgetower batch (skip when absent). Row-vector `v*M`,
    /// translation row `[12..15]` (see `matrix.rs`).
    #[test]
    fn judgetower_fullscene_transform_compose() {
        use crate::matrix::{matrix_multiply, scale, translation, y_rotation, Mat4};
        // ponytail: test-local point xform; no scene-graph API (out of scope).
        fn apply(m: &Mat4, v: &Vertex) -> Vertex {
            Vertex {
                x: v.x * m[0] + v.y * m[4] + v.z * m[8] + m[12],
                y: v.x * m[1] + v.y * m[5] + v.z * m[9] + m[13],
                z: v.x * m[2] + v.y * m[6] + v.z * m[10] + m[14],
                u: v.u,
                v: v.v,
            }
        }
        fn xbatch(b: &Batch, m: &Mat4) -> Batch {
            Batch {
                id: b.id.clone(),
                texture: b.texture.clone(),
                material: b.material.clone(),
                vertices: b.vertices.iter().map(|v| apply(m, v)).collect(),
                faces: b.faces.clone(),
            }
        }
        fn frame(vertices: &[Vertex], w: u32, h: u32) -> Cam {
            let (mut lox, mut hix) = (f32::INFINITY, f32::NEG_INFINITY);
            let (mut loy, mut hiy) = (f32::INFINITY, f32::NEG_INFINITY);
            for v in vertices {
                lox = lox.min(v.x);
                hix = hix.max(v.x);
                loy = loy.min(v.y);
                hiy = hiy.max(v.y);
            }
            let s = ((w as f32 / (hix - lox + 1e-6).abs().max(1e-6))
                .min(h as f32 / (hiy - loy + 1e-6).abs().max(1e-6))
                * 0.9)
                .max(0.5);
            Cam { scale: s, cx: (lox + hix) / 2.0, cy: (loy + hiy) / 2.0 }
        }
        // Caller order: (R×S)×T — ECX is LEFT in `0046efc0` (matrix.rs).
        let r = y_rotation(0.5);
        let s = scale(2.0, 3.0, 4.0);
        let t = translation(10.0, 20.0, 30.0);
        let m = matrix_multiply(matrix_multiply(r, s), t);
        // Last row is exactly T (R,S last rows are [0,0,0,1]).
        assert_eq!(&m[12..16], &[10.0, 20.0, 30.0, 1.0]);
        // Origin lands on T; (1,0,0) proves R-then-S-then-T:
        // row0 = [2cos, 0, 4sin] + T.
        let o = apply(&m, &Vertex { x: 0.0, y: 0.0, z: 0.0, u: 0.0, v: 0.0 });
        assert_eq!([o.x, o.y, o.z], [10.0, 20.0, 30.0]);
        let c = 0.5f32.cos();
        let sn = 0.5f32.sin();
        let p = apply(&m, &Vertex { x: 1.0, y: 0.0, z: 0.0, u: 0.0, v: 0.0 });
        assert!((p.x - (2.0 * c + 10.0)).abs() < 1e-5, "px={}", p.x);
        assert!((p.y - 20.0).abs() < 1e-5, "py={}", p.y);
        assert!((p.z - (4.0 * sn + 30.0)).abs() < 1e-5, "pz={}", p.z);
        // Generated quad fixture through the composed frame + textured fill.
        let tex = crate::png::Image {
            width: 2,
            height: 2,
            pixels: vec![
                255, 0, 0, 255, 0, 255, 0, 255,
                0, 0, 255, 255, 255, 255, 255, 255,
            ],
        };
        let qb = Batch {
            id: "q".into(),
            texture: String::new(),
            material: String::new(),
            vertices: vec![
                Vertex { x: 0.0, y: 0.0, z: 0.0, u: 0.0, v: 0.0 },
                Vertex { x: 1.0, y: 0.0, z: 0.0, u: 1.0, v: 0.0 },
                Vertex { x: 1.0, y: 1.0, z: 0.0, u: 1.0, v: 1.0 },
                Vertex { x: 0.0, y: 1.0, z: 0.0, u: 0.0, v: 1.0 },
            ],
            faces: vec![Face { v1: 1, v2: 2, v3: 3 }, Face { v1: 1, v2: 3, v3: 4 }],
        };
        let xb = xbatch(&qb, &m);
        // UVs survive the frame (fill already proven in textured_quad).
        assert_eq!(
            xb.vertices.iter().map(|v| (v.u, v.v)).collect::<Vec<_>>(),
            qb.vertices.iter().map(|v| (v.u, v.v)).collect::<Vec<_>>()
        );
        let (w, h) = (64, 64);
        let cam = frame(&xb.vertices, w, h);
        let mut buf = vec![0u8; (w * h * 3) as usize];
        let n = textured_rgb(&mut buf, w, h, &[xb.clone()], &tex, &cam);
        assert!(n > 500, "n={n}");
        let mut buf2 = vec![0u8; (w * h * 3) as usize];
        assert_eq!(textured_rgb(&mut buf2, w, h, &[xb], &tex, &cam), n);
        assert_eq!(buf, buf2);
        // Live judgetower batch through the same compose shape; skip absent.
        let res = std::path::Path::new("/tmp/dsj3-wrap/Data Files/Resources");
        if !res.join("Resource.000").exists() || !res.join("Resource.001").exists() {
            return;
        }
        use crate::{decrypt, manifest, model};
        let plain0 =
            decrypt::decrypt(&std::fs::read(res.join("Resource.000")).unwrap(), decrypt::K_RES_HEX)
                .unwrap();
        let man = manifest::parse(&String::from_utf16le_lossy(&plain0)).unwrap();
        let plain1 =
            decrypt::decrypt(&std::fs::read(res.join("Resource.001")).unwrap(), decrypt::K_RES_HEX)
                .unwrap();
        let entries = manifest::split(&man, &plain1).unwrap();
        let (_, model_blob) = entries
            .iter()
            .find(|(id, _)| id.contains("judgetower-summer-model"))
            .unwrap();
        let batches = model::parse(&String::from_utf8_lossy(model_blob)).unwrap();
        let (src, teximg) = batches
            .iter()
            .find_map(|b| model::texture_pixels(&entries, &b.texture).ok().map(|t| (b, t)))
            .unwrap();
        let live = xbatch(src, &m);
        let (lw, lh) = (160, 120);
        let lcam = frame(&live.vertices, lw, lh);
        let mut lb = vec![0u8; (lw * lh * 3) as usize];
        let ln = textured_rgb(&mut lb, lw, lh, std::slice::from_ref(&live), &teximg, &lcam);
        assert!(ln > 0, "live covered={ln}");
        eprintln!("live judgetower xform: batches={} src={} covered={ln}", batches.len(), src.id);
        let mut lb2 = vec![0u8; (lw * lh * 3) as usize];
        assert_eq!(
            textured_rgb(&mut lb2, lw, lh, std::slice::from_ref(&live), &teximg, &lcam),
            ln
        );
        assert_eq!(lb, lb2);
    }
}
