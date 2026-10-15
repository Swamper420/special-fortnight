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
//! SEPARATE local frames (closest cross-mesh anchors 29m apart).
//! `FUN_00436620` applies NO placement transform (dispatcher only:
//! version gate, then inrun → dhill → terrain builders in order on
//! the SAME hill object; `evidence/00436620_composition.md`);
//! relative frame placement stays unmapped (caller/render side).
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
    /// `(x=P3.x, y=P3.y)` — proven in
    /// `evidence/00434020_esp_shift.md` (pushed-last word is
    /// param_1; the `dda60` `RET 8` slot trick re-bases later
    /// `[ESP+X]` by +4, so `[ESP+0x5c]` there is P3.x).
    pub fn lineto1(&self, deg2rad: bool) -> (f32, f32) {
        let p = self.anchors(deg2rad);
        (p[3].0, p[3].1)
    }
}

/// Takeoff markers (`FUN_00538660` + stores in `FUN_00434020`;
/// evidence `evidence/00538660_takeoff_markers.md`).
///
/// `538660(this, a, b, c)`: `[this]=a; [this+4]=b; [this+8]=c`
/// (thiscall `ECX`, `RET 0xc`; no branches, callees, strings).
/// Marker math (`0x4342ae`-`0x43437e` op order, x87 extended
/// intermediates ≈ `f64`, `FSTP float` rounds each stored slot):
/// `sn=f32(sin(-as))`, `cs=f32(cos(-as))`,
/// `m1=(cs*lg+P3.x, ((sn*lg)+K1)+P3.y, tag)`,
/// `t=lg+STEP` once (`FLD ST0` reuse),
/// `m2=((t*cs)+P3.x, (((t*sn)+K2)+P3.y), tag)`.
/// `K1/K2/STEP` are exact file bits (`[0x608ae4]/[0x608ae8]/`
/// `[0x5ce048]`), not decimal shorthand. `as` arrives in
/// radians (caller converts); `tag` = opaque `param_9` word
/// (integer `PUSH`, `MOV` copies — never float).
/// `[ESI+0x25c]=0` (`EBP`), `[ESI+0x280]=-as` (exact `FCHS`),
/// `[ESI+0x284]=P3.x` (bit copy).
pub const TAKEOFF_K1: f32 = f32::from_bits(0x3E99999A);
pub const TAKEOFF_K2: f32 = f32::from_bits(0x3F170A3D);
pub const TAKEOFF_STEP: f32 = f32::from_bits(0x3D99999A);

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TakeoffMarkers {
    pub m1: (f32, f32, u32),
    pub m2: (f32, f32, u32),
    pub flag: u32,
    pub neg_as: f32,
    pub p3x_copy: f32,
}

pub fn takeoff_markers(lg: f32, as_rad: f32, p3x: f32, p3y: f32, tag: u32) -> TakeoffMarkers {
    // FSIN/FCOS in extended, FSTP-round to f32 per stored slot.
    let sn = ((-as_rad) as f64).sin() as f32;
    let cs = ((-as_rad) as f64).cos() as f32;
    // y1 = ((sn*lg)+K1)+P3.y; x1 = (cs*lg)+P3.x.
    let m1x = ((cs as f64) * (lg as f64) + (p3x as f64)) as f32;
    let m1y = (((sn as f64) * (lg as f64) + (TAKEOFF_K1 as f64)) + (p3y as f64)) as f32;
    // t = lg+STEP once, then y2 = (((t*sn)+K2)+P3.y), x2 = (t*cs)+P3.x.
    let t = (lg as f64) + (TAKEOFF_STEP as f64);
    let m2x = (t * (cs as f64) + (p3x as f64)) as f32;
    let m2y = ((t * (sn as f64) + (TAKEOFF_K2 as f64)) + (p3y as f64)) as f32;
    TakeoffMarkers { m1: (m1x, m1y, tag), m2: (m2x, m2y, tag), flag: 0, neg_as: -as_rad, p3x_copy: p3x }
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

/// Terrain heightfield loop `FUN_004348a0`
/// (`evidence/004348a0_terrain_loop.md`). Only the asm-certain parts:
/// grid bounds, per-vertex coords, cosine noise, guard predicates.
/// Max/min-arg wiring, sin weights, RNG tables, vector growth: open (U3-U5).
pub const TERRAIN_ROWS: u32 = 61; // `MOV [EBP+0x84],0x3d` (outer bound)

/// Per-vertex coords (`0x434b51`-`0x434b8f`, asm order): `FILD` col/row
/// (int→x87, exact), `FMUL` step, `FADD` base, `FSTP` float.
/// f64 intermediates (≈ x87 extended); single f32 round per slot.
pub fn terrain_coords(col: u32, row: u32, step_x: f32, base_x: f32, step_y: f32, base_y: f32) -> (f32, f32) {
    (
        (col as f64 * step_x as f64 + base_x as f64) as f32,
        (row as f64 * step_y as f64 + base_y as f64) as f32,
    )
}

/// Adjustment-guard predicate (`0x434bd6`/`0x434c24`): `FCOMP; FNSTSW;
/// TEST AH,1; JZ skip` — skips iff C0=0 (ordered ≥), so less OR
/// unordered (NaN) enters. `!(fvar >= bound)` matches exactly.
pub fn terrain_adjust_enter(fvar: f32, bound: f32) -> bool {
    !(fvar >= bound)
}

/// Cosine noise (`0x434c75`-`0x434cd4`, tap order): `acc=0`;
/// per tap `t=fvar/div*pi; acc += cos(t+t+ph)*amp` (first fVar4 taps,
/// then fVar5 taps). x87 extended ≈ f64; one f32 round at return.
#[allow(clippy::too_many_arguments)]
pub fn terrain_noise(
    fvar4: f32,
    fvar5: f32,
    pi: f32,
    div_a: &[f32; 8],
    ph_a: &[f32; 8],
    amp_a: &[f32; 8],
    div_b: &[f32; 8],
    ph_b: &[f32; 8],
    amp_b: &[f32; 8],
) -> f32 {
    let mut acc = 0.0f64;
    for k in 0..8 {
        let t1 = fvar4 as f64 / div_a[k] as f64 * pi as f64;
        acc += (t1 + t1 + ph_a[k] as f64).cos() * amp_a[k] as f64;
        let t2 = fvar5 as f64 / div_b[k] as f64 * pi as f64;
        acc += (t2 + t2 + ph_b[k] as f64).cos() * amp_b[k] as f64;
    }
    acc as f32
}

/// Hill-mesh dispatch `FUN_00436620` (`evidence/00436620_composition.md`).
///
/// Observed: version gate, then `inrun → dhill → terrain` builders run
/// in order on the SAME hill object (`MOV ECX,EDI` at
/// `0x436c09/0x437434/0x437700`); no placement transform between them.
/// Relative frame placement stays unmapped — this records order + sharing.
pub const COMPOSE_ORDER: [&str; 3] = ["inrun", "dhill", "terrain"];

/// Run the three builders in observed order on one shared object.
pub fn compose<H>(hill: &mut H, mut inrun: impl FnMut(&mut H), mut dhill: impl FnMut(&mut H), mut terrain: impl FnMut(&mut H)) {
    inrun(hill);
    dhill(hill);
    terrain(hill);
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

    /// ONE check for `FUN_00436620` dispatch
    /// (`evidence/00436620_composition.md`, generated stubs — no
    /// original bytes): builders run inrun → dhill → terrain on one
    /// shared object; no transform modeled because none observed.
    #[test]
    fn composition_dispatch_order_shared_object() {
        use std::cell::RefCell;
        let seen: RefCell<Vec<(&str, usize)>> = RefCell::new(Vec::new());
        let mut hill = 0u32;
        compose(
            &mut hill,
            |h| seen.borrow_mut().push(("inrun", h as *mut u32 as usize)),
            |h| seen.borrow_mut().push(("dhill", h as *mut u32 as usize)),
            |h| seen.borrow_mut().push(("terrain", h as *mut u32 as usize)),
        );
        let seen = seen.borrow();
        assert_eq!(COMPOSE_ORDER, ["inrun", "dhill", "terrain"]);
        assert_eq!(
            seen.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            COMPOSE_ORDER
        );
        assert_eq!(seen[0].1, seen[1].1);
        assert_eq!(seen[1].1, seen[2].1);
    }

    /// ONE check for takeoff markers (`evidence/00538660_takeoff_markers.md`,
    /// generated fixture — no original bytes): tag/flag/neg/p3x bit-exact;
    /// as=0 degenerates to (lg+P3.x, K+P3.y) rows spaced by STEP/(K2-K1);
    /// nonzero angle finite with STEP*cos spacing.
    #[test]
    fn takeoff_marker_rows() {
        let m = takeoff_markers(10.0, 0.0, 100.0, 40.0, 0xDEAD_BEEF);
        assert_eq!(m.flag, 0);
        assert_eq!((m.m1.2, m.m2.2), (0xDEAD_BEEF, 0xDEAD_BEEF));
        assert_eq!(m.neg_as.to_bits(), (-0.0f32).to_bits());
        assert_eq!(m.p3x_copy.to_bits(), 100.0f32.to_bits());
        assert!((m.m1.0 - 110.0).abs() < 1e-4);
        assert!((m.m1.1 - (TAKEOFF_K1 + 40.0)).abs() < 1e-4);
        assert!((m.m2.0 - m.m1.0 - TAKEOFF_STEP).abs() < 1e-3);
        assert!((m.m2.1 - m.m1.1 - (TAKEOFF_K2 - TAKEOFF_K1)).abs() < 1e-3);
        let n = takeoff_markers(20.0, 0.61, -55.9, 38.1, 7);
        for v in [n.m1.0, n.m1.1, n.m2.0, n.m2.1] {
            assert!(v.is_finite());
        }
        assert!(((n.m2.0 - n.m1.0) as f64 - 0.075 * (-0.61f64).cos()).abs() < 1e-3);
    }

    /// ONE check for `FUN_004348a0` loop core
    /// (`evidence/004348a0_terrain_loop.md`, generated fixture — no
    /// original bytes): 61-row bound; exact coords (col 3 → 7.0,
    /// row 0 → −300.0); noise zero-amps → 0, unit tables at origin →
    /// 16.0 (8 taps × (1+1)); guard less/equal/greater + NaN-enters.
    #[test]
    fn terrain_loop_core() {
        assert_eq!(TERRAIN_ROWS, 61);
        assert_eq!(terrain_coords(3, 0, 2.0, 1.0, 10.0, -300.0), (7.0, -300.0));
        assert_eq!(terrain_coords(u32::MAX, 60, 1.0, 0.0, 1.0, 0.0).1, 60.0);
        let z = [0.0f32; 8];
        let u = [1.0f32; 8];
        assert_eq!(terrain_noise(1.5, -2.5, std::f32::consts::PI, &u, &z, &z, &u, &z, &z), 0.0);
        assert_eq!(
            terrain_noise(0.0, 0.0, std::f32::consts::PI, &u, &z, &u, &u, &z, &u),
            16.0
        );
        assert!(terrain_adjust_enter(1.0, 2.0));
        assert!(!terrain_adjust_enter(2.0, 1.0));
        assert!(!terrain_adjust_enter(1.0, 1.0));
        assert!(terrain_adjust_enter(f32::NAN, 1.0));
        assert!(terrain_adjust_enter(1.0, f32::NAN));
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
