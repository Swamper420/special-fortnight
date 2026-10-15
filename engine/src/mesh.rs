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
//! composition transform in `FUN_00436620` unmapped);
//! `[0x61b880]`=pi assumed from `pi,pi/2,3pi/2` usage (file: 0.0).
//! Emit topology → polyline MAPPED (`evidence/004ddae0_emit_check.md`):
//! `dda60` opens (empty strip), `ddae0` appends linear `y(x)`
//! segments (`442fb0` slope/intercept), `ddf10/ddcb0` append curve
//! nodes + sampled steps, `dd970` seals (`+0x30`); `ddae0` throws
//! on `x < cursor` (NaN too, x87 C0) and drops `x == cursor`.
//! Do NOT fabricate track geometry from anchors alone.

/// Outcome of one `004ddae0` guard sequence, transcribed op-for-op
/// from `0x4ddafe`-`0x4ddb73` (flag → decrease → equal).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EmitAction {
    /// x advanced: append segment, `count.wrapping_add(1)`, cursor=x.
    Emit,
    /// x == cursor (`TEST AH,0x40`): silent no-op.
    IgnoreEqual,
}

/// `004ddae0` throw sites (`"Invalid data exception"`, `0x6067a8`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EmitErr {
    /// `[ECX+0x30] != 0` (strip sealed by `004dd970`).
    Closed,
    /// `x < cursor` via x87 C0 (`0x4ddb2e-0x4ddb62`); unordered
    /// (NaN) also sets C0, so NaN throws here, before equality.
    Decrease,
}

/// Transcribed `004ddae0` guards in asm branch order.
/// Widths: flag byte, f32 compare, i32 count handled by caller.
pub fn emit_check(closed: bool, cursor_x: f32, x: f32) -> Result<EmitAction, EmitErr> {
    if closed {
        return Err(EmitErr::Closed);
    }
    // C0 set on less-than OR unordered: NaN reads as decrease.
    if x.is_nan() || x < cursor_x {
        return Err(EmitErr::Decrease);
    }
    if x == cursor_x {
        return Ok(EmitAction::IgnoreEqual);
    }
    Ok(EmitAction::Emit)
}

/// Transcribed `004dda60` guards: sealed → throw; non-empty
/// (`[ECX+0x0c] != 0`) → throw; else open at (x, y).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MovetoErr {
    Closed,
    NonEmpty,
}

pub fn moveto_check(closed: bool, count: i32) -> Result<(), MovetoErr> {
    if closed {
        return Err(MovetoErr::Closed);
    }
    if count != 0 {
        return Err(MovetoErr::NonEmpty);
    }
    Ok(())
}

/// Minimal strip cursor: `[ECX+0x20]=x`, `[ECX+0x24]=y`,
/// `[ECX+0x2c]=x`, count `[ECX+0x0c]` (`INC` wraps),
/// seal flag `[ECX+0x30]` (`004dd970` sets 1).
#[derive(Debug, Clone, Copy)]
pub struct StripCursor {
    pub x: f32,
    pub y: f32,
    pub count: i32,
    pub closed: bool,
}

impl StripCursor {
    pub fn open(x: f32, y: f32) -> Self {
        StripCursor { x, y, count: 0, closed: false }
    }

    /// One `004ddae0` step: guards in order, then cursor advance.
    /// `00442fb0` slope/intercept construction lives in the
    /// appended node (layout open); only cursor/count modeled.
    pub fn push(&mut self, x: f32, y: f32) -> Result<EmitAction, EmitErr> {
        let a = emit_check(self.closed, self.x, x)?;
        if a == EmitAction::Emit {
            self.x = x;
            self.y = y;
            self.count = self.count.wrapping_add(1);
        }
        Ok(a)
    }

    /// `004dd970`: `[ECX+0x30] = 1`.
    pub fn seal(&mut self) {
        self.closed = true;
    }
}

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

/// Terrain base `FUN_00434ff0` (evidence `evidence/00434ff0_terrain_base.md`).
///
/// `thr/off/x0` = `[this+0x260/+0x264/+0x98]`; `lo/hi` = `[obj60+0x28/+0x2c]`
/// (`FUN_004de320/004de350`, throw if `[obj60+0x30]==0` → `panic` here, U5).
/// `xform` = opaque virtual transform `FUN_004de3e0` (target unmapped, U2).
/// f64 intermediates (≈ x87 extended); f32 round-trips where asm stores float.
#[derive(Debug, Clone, Copy)]
pub struct TerrainBase {
    pub thr: f32,
    pub off: f32,
    pub x0: f32,
    pub lo: f32,
    pub hi: f32,
    pub range_present: bool,
}

/// `FUN_00468310`: median-clamp, C0-bit exact (`NaN` value → `lo`).
pub fn clamp3(lo: f32, hi: f32, v: f32) -> f32 {
    if !(lo <= v) {
        lo
    } else if hi < v {
        hi
    } else {
        v
    }
}

/// `FUN_00468360`: max, C0-bit exact (`NaN` b → `a`).
pub fn max2(a: f32, b: f32) -> f32 {
    if !(a <= b) {
        a
    } else {
        b
    }
}

impl TerrainBase {
    /// `FUN_00434ff0(ECX=this, p1, p2) -> f32`, branch-for-branch from asm.
    pub fn eval(&self, xform: impl FnOnce(f32) -> f32, p1: f32, p2: f32) -> f32 {
        if !(self.thr <= p1) {
            // Branch A: sqrt(max(|p2|-xform(clamp(lo,hi,p1)),0)² + g²),
            // g = p1-x0 if p1 < x0 else 0.
            if !self.range_present {
                panic!("FUN_00434ff0: range object absent ([obj60+0x30]==0)");
            }
            let d = xform(clamp3(self.lo, self.hi, p1)) as f64;
            let e = p2.abs() as f64 - d;
            let f = max2(e as f32, 0.0) as f64;
            let g = if !(self.x0 <= p1) {
                p1 as f64 - self.x0 as f64
            } else {
                0.0
            };
            (f * f + g * g).sqrt() as f32
        } else {
            // Branch B: max(sqrt(p2² + (p1-thr)²) - off, 0).
            let dx = (p1 - self.thr) as f64;
            let h = ((p2 as f64) * (p2 as f64) + dx * dx).sqrt() - self.off as f64;
            max2(h as f32, 0.0)
        }
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

    /// ONE check for the emit-guard transcription
    /// (`evidence/004ddae0_emit_check.md`): branch order
    /// closed → decrease (incl. NaN, x87 C0) → equal-drop → emit;
    /// `moveto` sealed/non-empty throws; count wraps like `INC`.
    #[test]
    fn emit_guards_in_asm_order() {
        assert_eq!(emit_check(true, 0.0, 1.0), Err(EmitErr::Closed));
        assert_eq!(emit_check(false, 1.0, 0.5), Err(EmitErr::Decrease));
        assert_eq!(emit_check(false, 1.0, f32::NAN), Err(EmitErr::Decrease));
        assert_eq!(emit_check(false, 1.0, 1.0), Ok(EmitAction::IgnoreEqual));
        assert_eq!(emit_check(false, 1.0, 2.0), Ok(EmitAction::Emit));
        assert_eq!(moveto_check(true, 0), Err(MovetoErr::Closed));
        assert_eq!(moveto_check(false, 1), Err(MovetoErr::NonEmpty));
        assert_eq!(moveto_check(false, 0), Ok(()));
        // Generated strip: monotone emits advance, equal drops,
        // decrease + post-seal throw; count wraps at i32::MAX.
        let mut s = StripCursor::open(-60.0, 40.0);
        assert_eq!(s.push(-50.0, 41.0), Ok(EmitAction::Emit));
        assert_eq!((s.x, s.count), (-50.0, 1));
        assert_eq!(s.push(-50.0, 42.0), Ok(EmitAction::IgnoreEqual));
        assert_eq!((s.x, s.count), (-50.0, 1));
        assert_eq!(s.push(-60.0, 0.0), Err(EmitErr::Decrease));
        s.count = i32::MAX;
        assert_eq!(s.push(-40.0, 0.0), Ok(EmitAction::Emit));
        assert_eq!(s.count, i32::MIN);
        s.seal();
        assert_eq!(s.push(0.0, 0.0), Err(EmitErr::Closed));
    }

    /// ONE check for `FUN_00434ff0` (`evidence/00434ff0_terrain_base.md`,
    /// generated fixture — no original bytes): closed forms per branch,
    /// C0-bit NaN mappings (clamp/max/branch-select), absent-range panic.
    #[test]
    fn terrain_base_branches() {
        let t = |thr: f32, off: f32, x0: f32| TerrainBase {
            thr,
            off,
            x0,
            lo: 0.0,
            hi: 100.0,
            range_present: true,
        };
        // Branch B: sqrt(4² + (13-10)²) - 2 = 3.
        assert_eq!(t(10.0, 2.0, 0.0).eval(|c| c, 13.0, 4.0), 3.0);
        // Branch B clamped: sqrt(0 + 1) - 100 < 0 → 0.
        assert_eq!(t(10.0, 100.0, 0.0).eval(|c| c, 11.0, 0.0), 0.0);
        // Branch A, g<0 leg: C=30, D=30, E=|10|-30→0; G=30-50=-20 → 20.
        assert_eq!(t(100.0, 0.0, 50.0).eval(|c| c, 30.0, 10.0), 20.0);
        // Branch A, g=0 leg: C=60, D=0, E=10 → 10; G=0 → 10.
        assert_eq!(t(100.0, 0.0, 50.0).eval(|c| c - 60.0, 60.0, 10.0), 10.0);
        // Branch A clamp hi: p1=150 → C=100; D=100, E=-90 → F=0; G=-50 → 50.
        assert_eq!(t(2000.0, 0.0, 200.0).eval(|c| c, 150.0, 10.0), 50.0);
        // x87 C0 mappings: NaN value → lo; NaN b → a; NaN p1 → A-path (NaN out).
        assert_eq!(clamp3(2.0, 5.0, f32::NAN), 2.0);
        assert_eq!(max2(1.0, f32::NAN), 1.0);
        assert!(t(10.0, 0.0, 0.0).eval(|c| c, f32::NAN, 1.0).is_nan());
    }

    #[test]
    #[should_panic(expected = "range object absent")]
    fn terrain_base_absent_range_panics() {
        let t = TerrainBase {
            thr: 100.0,
            off: 0.0,
            x0: 0.0,
            lo: 0.0,
            hi: 1.0,
            range_present: false,
        };
        t.eval(|c| c, 1.0, 1.0);
    }
}
