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
}
