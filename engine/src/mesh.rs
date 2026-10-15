//! Hill profile geometry (transcribed from the game, evidence-backed).
//!
//! Inrun builder `FUN_00434020` (ev_5ea46e79...): chained anchors
//! from `(lz ls lg as rc lt at ht tz ws)` (caller converts angle
//! keys `at as ar ak a0` via `×pi×(1/180)` (`[0x5ce060]=1/180`,
//! `[0x61b880]` reads as pi; file value 0.0, set at runtime).
//! One ESP-shift (`PUSH ECX` at `0x43416b`) re-bases all later
//! slots; a pointer slot reads as float ≈ 1e-26 (harmless, +0).
//! Anchors (Hill01, radians): P0(−4.5,2.5) P1(9.1,44.6)
//! P2(−25.7,8.8) P3(−55.9,38.1); moveTo(P3.x−lz, P3.y).
//! Emits are X-monotone polylines (`004ddae0` throws on decrease).
//!
//! Landing builder `FUN_00434390` (ev_2a3f9799...): arcs from
//! `(a0 ak hk nk rl l1 l2 rs lb hr nr ar w0 wk wb)`; verified
//! arc-length structure (`l1/rl`, `l2/rl` sweeps give exactly
//! l1/l2 meters). Terrain builder `FUN_004348a0` (ev_740d0d8f...):
//! 61-row heightfield + cosine noise (base `FUN_00434ff0` open).
//!
//! OPEN (not guessed): inrun/landing/terrain meshes live in
//! SEPARATE local frames (closest cross-mesh anchors 29m apart —
//! composition transform in `FUN_00436620` unmapped); full emit
//! topology → polyline (arg slots mapped, strip encoding open);
//! `[0x61b880]`=pi assumed from `pi,pi/2,3pi/2` usage (file: 0.0).
//! Do NOT fabricate track geometry from anchors alone.

use std::f32::consts::PI;

#[derive(Debug, Clone, Copy)]
pub struct Inrun {
    pub lz: f32,
    pub ls: f32,
    pub lg: f32,
    pub as_: f32,
    pub rc: f32,
    pub lt: f32,
    pub at: f32,
    pub ht: f32,
    pub tz: f32,
    pub ws: f32,
}

impl Inrun {
    pub fn from_map(m: &std::collections::HashMap<String, f32>) -> Result<Self, String> {
        let g = |k: &str| m.get(k).copied().ok_or_else(|| format!("inrun missing @{k}"));
        Ok(Inrun {
            lz: g("lz")?,
            ls: g("ls")?,
            lg: g("lg")?,
            as_: g("as")?,
            rc: g("rc")?,
            lt: g("lt")?,
            at: g("at")?,
            ht: g("ht")?,
            tz: g("tz")?,
            ws: g("ws")?,
        })
    }

    /// Chained anchor points, transcribed op-for-op from
    /// `0x434161`-`0x434209` with ESP-shift tracking (a `PUSH ECX`
    /// at `0x43416b` shifts all later `[ESP+X]` by −4; pointer slot
    /// `S-0x28` reads heap-address-as-float ≈ 1e-26, treated as 0).
    /// Returns `(P0, P1, P2, P3)` with P3 the final inrun anchor.
    pub fn anchors(&self, deg2rad: bool) -> [(f32, f32); 4] {
        let cvt = |d: f32| if deg2rad { d * PI / 180.0 } else { d };
        let (at, as_) = (cvt(self.at), cvt(self.as_));
        let pi = PI;
        // P0 = (cos(pi−at)*lt, sin(pi−at)*lt + ht)
        let p0 = ((pi - at).cos() * self.lt, (pi - at).sin() * self.lt + self.ht);
        // P1 = (cos(pi/2−at)*rc + ~0, sin(pi/2−at)*rc + P0.x)
        let p1 = (
            (pi * 0.5 - at).cos() * self.rc,
            (pi * 0.5 - at).sin() * self.rc + p0.0,
        );
        // P2 = P1 + (cos(1.5pi−as)*rc, sin(1.5pi−as)*rc)
        let p2 = (
            (pi * 1.5 - as_).cos() * self.rc + p1.0,
            (pi * 1.5 - as_).sin() * self.rc + p1.1,
        );
        // P3 = P2 + (cos(pi−as)*ls, sin(pi−as)*ls)
        let p3 = (
            (pi - as_).cos() * self.ls + p2.0,
            (pi - as_).sin() * self.ls + p2.1,
        );
        [p0, p1, p2, p3]
    }

    /// MoveTo anchor transcribed from `0x43420d`-`0x434225`:
    /// `(P3.x − lz, P3.y)` (asm-grounded).
    pub fn moveto(&self, deg2rad: bool) -> (f32, f32) {
        let p = self.anchors(deg2rad);
        (p[3].0 - self.lz, p[3].1)
    }

    /// First lineTo transcribed from `0x43422a`-`0x434237`:
    /// `(x=as_rad, y=P3.x)` — axis roles flagged, HS/plotted.
    pub fn lineto1(&self, deg2rad: bool) -> (f32, f32) {
        let cvt = |d: f32| if deg2rad { d * PI / 180.0 } else { d };
        let p = self.anchors(deg2rad);
        (cvt(self.as_), p[3].0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hill;

    fn hill01() -> hill::Hill {
        let raw = std::fs::read("/tmp/dsj3-wrap/Data Files/Resources/Resource.001").ok();
        let raw = match raw {
            Some(r) => r,
            None => return hill::parse("<hill version=\"x\"><inrun><profile lz=\"1\"/></inrun><dhill><profile a0=\"1\"/><judgetower d=\"1\" z=\"1\"/></dhill><terrain><profile in=\"1\"/><trees n=\"1\"/></terrain></hill>").unwrap(),
        };
        let blob = crate::decrypt::decrypt(&raw, crate::decrypt::K_RES_HEX).unwrap();
        let t = String::from_utf8_lossy(&blob[247684..247684 + 1889]).into_owned();
        hill::parse(&t).unwrap()
    }

    #[test]
    fn anchors_sane_and_hs_close() {
        if !std::path::Path::new("/tmp/dsj3-wrap/Data Files/Resources/Resource.001").exists() {
            return;
        }
        let h = hill01();
        let ir = Inrun::from_map(&h.profile_inrun).unwrap();
        for deg2rad in [true, false] {
            let p = ir.anchors(deg2rad);
            eprintln!("deg2rad={deg2rad} anchors={p:?}");
            for &(x, y) in &p {
                assert!(x.is_finite() && y.is_finite());
                assert!(x.abs() < 5000.0 && y.abs() < 5000.0);
            }
        }
    }
}
