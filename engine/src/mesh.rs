//! Hill profile geometry (transcribed from the game, evidence-backed).
//!
//! Inrun builder `FUN_00434020` (ev_5ea46e79...): chained anchors
//! from `(lz ls lg as rc lt at ht tz ws)` (caller converts angle
//! keys `at as ar ak a0` via `×pi×(1/180)` (`[0x5ce060]=1/180`,
//! `[0x61b880]` reads as pi; file value 0.0, set at runtime).
//! One ESP-shift (`PUSH ECX` at `0x43416b`) re-bases all later
//! slots.
//! Anchors (Hill01, radians): P0(−4.5,2.5) P1(4.6,51.7)
//! P2(−30.3,15.9) P3(−60.4,45.1); moveTo(P3.x−lz, P3.y).
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
    /// at `0x43416b` shifts all later `[ESP+X]` by −4).
    /// Returns `(P0, P1, P2, P3)` with P3 the final inrun anchor.
    pub fn anchors(&self, deg2rad: bool) -> [(f32, f32); 4] {
        let cvt = |d: f32| if deg2rad { d * PI / 180.0 } else { d };
        let (at, as_) = (cvt(self.at), cvt(self.as_));
        let pi = PI;
        // P0 = (cos(pi−at)*lt, sin(pi−at)*lt + ht)
        let p0 = ((pi - at).cos() * self.lt, (pi - at).sin() * self.lt + self.ht);
        // P1 = (cos(pi/2−at)*rc + P0.x, sin(pi/2−at)*rc + P0.y)
        let p1 = (
            (pi * 0.5 - at).cos() * self.rc + p0.0,
            (pi * 0.5 - at).sin() * self.rc + p0.1,
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

/// Landing (`dhill`) anchors `FUN_00434390` (`0x4344d1`-`0x4345f6`,
/// evidence `evidence/00434390_anchors.md` §2 + emit roles
/// `evidence/00434390_emit_args.md` §§3-4 + key map
/// `evidence/00436620_param_keys.md` §3).
///
/// Caller `0x436620` parses dhill keys in order
/// `wb wk w0 ar nr hr lb rs l2 l1 rl nk hk ak a0`, first-parsed
/// ends deepest, so `p1=a0 p2=ak p3=hk p4=nk p5=rl p6=l1 p7=l2
/// p8=rs p9=lb p10=hr p11=nr p12=ar p13=w0 p14=wk p15=wb`
/// (reversal = inference, param_keys U1). Caller converts only
/// `a0/ak/ar` via `×pi×(1/180)` FMUL pairs, hence `deg2rad`
/// touches just those three.
#[derive(Debug, Clone, Copy)]
pub struct Landing {
    pub a0: f32,
    pub ak: f32,
    pub hk: f32,
    pub nk: f32,
    pub rl: f32,
    pub l1: f32,
    pub l2: f32,
    pub rs: f32,
    pub lb: f32,
    pub hr: f32,
    pub nr: f32,
    pub ar: f32,
    pub w0: f32,
    pub wk: f32,
    pub wb: f32,
}

/// Stored landing anchors (one field per `FSTP`/`FST` slot) plus
/// the x87-stack-only angles/slopes consumed at emit time.
#[derive(Debug, Clone, Copy)]
pub struct LandingAnchors {
    pub l1x: f32,
    pub l1y: f32,
    pub a16: f32,
    pub l2x: f32,
    pub l2y: f32,
    pub l3x: f32,
    pub l3y: f32,
    pub l4x: f32,
    pub s5: f32,
    pub l4y: f32,
    pub n9: f32,
    pub n11: f32,
    pub m10: f32,
    pub at: f32,
    /// `tan(-p1)` (`0x434618-0x434623` FCHS/FPTAN, popped).
    pub slope0: f32,
    /// `tan(-p2-p6/p5)` (`0x434602-0x434615` FCHS/FSUB/FPTAN, popped).
    pub slope1: f32,
}

impl Landing {
    pub fn from_map(m: &std::collections::HashMap<String, f32>) -> Result<Self, String> {
        let g = |k: &str| m.get(k).copied().ok_or_else(|| format!("dhill missing @{k}"));
        Ok(Landing {
            a0: g("a0")?,
            ak: g("ak")?,
            hk: g("hk")?,
            nk: g("nk")?,
            rl: g("rl")?,
            l1: g("l1")?,
            l2: g("l2")?,
            rs: g("rs")?,
            lb: g("lb")?,
            hr: g("hr")?,
            nr: g("nr")?,
            ar: g("ar")?,
            w0: g("w0")?,
            wk: g("wk")?,
            wb: g("wb")?,
        })
    }

    /// Anchor chain transcribed op-for-op from `0x4344d1`-`0x4345f6`
    /// in asm order (param_N roles, key names where param_keys §3
    /// proves them). f64 intermediates (≈ x87 ST0), one f32 round
    /// per stored slot; x87-stack-only angles stay f64 until use.
    /// Slot reuses (`param_3/param_7/T65/T75/N9` slots) are comments
    /// only — fresh locals here.
    pub fn anchors(&self, deg2rad: bool) -> LandingAnchors {
        let cvt = |d: f32| if deg2rad { d * PI / 180.0 } else { d };
        // p1=a0 p2=ak p12=ar arrive in radians when caller converts.
        let (p1, p2, p12) = (cvt(self.a0), cvt(self.ak), cvt(self.ar));
        let (p3, p4, p5) = (self.hk, self.nk, self.rl);
        let (p6, p7, p8) = (self.l1, self.l2, self.rs);
        let (p9, p10, p11) = (self.lb, self.hr, self.nr);
        let pi = std::f64::consts::PI;
        // Angle base: pi*0.5-p2 (x87 stack; p4 parked at [B+0x2c]).
        let a14base = pi * 0.5 - p2 as f64;
        // L1x=[B+0x14], L1y=[B+0x10].
        let l1x = ((a14base.cos() * p5 as f64 + p4 as f64)) as f32;
        let l1y = ((a14base.sin() * p5 as f64 - p3 as f64)) as f32;
        // T65=[B+0x1c] scratch (p6/p5).
        let t65 = (p6 / p5) as f32;
        // A16base=pi*1.5-p2 (x87 stack); A16=[B+0x30]=A16base-T65.
        let a16base = pi * 1.5 - p2 as f64;
        let a16 = (a16base - t65 as f64) as f32;
        // L2x=[B+0x18]; L2y inline (recomputed at ddcb0#1, no store).
        let l2x = ((a16 as f64).cos() * p5 as f64 + l1x as f64) as f32;
        let l2y = ((a16 as f64).sin() * p5 as f64 + l1y as f64) as f32;
        // T75=[B+0x78] scratch (p7/p5); A15=A16base+T75 (x87 stack).
        let t75 = (p7 / p5) as f32;
        let a15 = a16base + t75 as f64;
        // L3x=[B+0x6c] (dead param_3 slot); L3y=[B+0x20].
        let l3x = (a15.cos() * p5 as f64 + l1x as f64) as f32;
        let l3y = (a15.sin() * p5 as f64 + l1y as f64) as f32;
        // A14=a14base+T75 (x87 stack, FADD onto surviving copy).
        let a14 = a14base + t75 as f64;
        // L4x=[B+0x7c] (dead param_7 slot); S5=[B+0x24] FST-kept
        // (dead T65 slot); L4y=[B+0x28]=S5-p8.
        let l4x = ((a14.cos() * p8 as f64 + l3x as f64)) as f32;
        let s5 = ((a14.sin() * p8 as f64 + l3y as f64)) as f32;
        let l4y = (s5 as f64 - p8 as f64) as f32;
        // N9=[B+0x80]=L4x+p9; N11=[B+0x78]=N9+p11 (dead T75 slot);
        // M10=[B+0x8c]=L4y+p10 (dead param_11 slot).
        let n9 = (l4x as f64 + p9 as f64) as f32;
        let n11 = (n9 as f64 + p11 as f64) as f32;
        let m10 = (l4y as f64 + p10 as f64) as f32;
        // AT=[B+0x84]=atan(p12) via FLD1/FPATAN (dead param_9 slot).
        let at = (p12 as f64).atan() as f32;
        // Emit-time slopes (FPTAN, popped, not stored).
        let slope0 = (-(p1 as f64)).tan() as f32;
        let slope1 = ((-(p2 as f64)) - t65 as f64).tan() as f32;
        LandingAnchors { l1x, l1y, a16, l2x, l2y, l3x, l3y, l4x, s5, l4y, n9, n11, m10, at, slope0, slope1 }
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
/// grid bounds, per-vertex coords, cosine noise, guard predicates, plus
/// strip lo-min / hi-max wiring (`FUN_00435740`/`00435770` as called from
/// the loop: `min2(lo_b50, lo_b60)` / `max2(hi_b50, hi_b60)`, arg order
/// from asm staging per `evidence/00435740_strip_minmax.md` §3) plus the
/// sin-weight tail (`evidence/004348a0_sin_tail.md`: `FSIN param_6/7`,
/// `max2(param_2, 1-t1)` / `min2(1-param_2, t1)` weights,
/// `clamp3(h-t2, h+t2)` into `v = f18*noise + f16`).
/// RNG tables, vector growth: still open.
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

/// Guard sin factor (`[0x5ce05c]`, exact file bits `0xBBB60B61` =
/// `-0.0055555556900799274`; see `evidence/004348a0_guard_h.md` §4).
pub const TERRAIN_GUARD_SIN_NEG: f32 = f32::from_bits(0xBBB6_0B61);

/// Guard-block height accum `h` (`0x434b9e`-`0x434c71` per vertex;
/// `evidence/004348a0_guard_h.md`). Seed + two guarded adjustments in
/// asm order; `f64` intermediates (≈ x87 extended), one `f32` round per
/// asm `FSTP` (`t_max`, `t2`, `h0`, `ta`, each new `h`). The second
/// body-1 `xform` (`tb`) and the body-2 chain stay unrounded like the
/// `ST0`-direct asm path (virtual targets assumed `f32`-rounded on
/// return, `de3e0` U3 carried). Guards/combines reuse
/// `terrain_adjust_enter` / `max2` / `min2` — NaN sides identical.
/// `xform_b60`/`xform_b50` = opaque `FUN_004de3e0` on the b60/b50 strips.
#[allow(clippy::too_many_arguments)]
pub fn terrain_guard_h(
    fvar4: f32,
    lo_b60: f32,
    hi_b60: f32,
    lo_b50: f32,
    hi_b50: f32,
    x0: f32,
    p1_in: f32,
    p3_a0: f32,
    pi: f32,
    xform_b60: impl Fn(f32) -> f32,
    xform_b50: impl Fn(f32) -> f32,
) -> f32 {
    // Seed: h0 = xform_b60(min2(hi_b60, max2(lo_b60, fvar4))).
    let t_max = max2(lo_b60, fvar4);
    let t2 = crate::fn_00435740::min2(hi_b60, t_max);
    let mut h = xform_b60(t2);
    // Body 1 (`0x434bd6`): h += (xform_b50(max2(lo_b50,fvar4)) - xform_b50(hi_b50)) * p1.
    if terrain_adjust_enter(fvar4, lo_b60) {
        let ta = xform_b50(max2(lo_b50, fvar4));
        let tb = xform_b50(hi_b50);
        h = ((ta as f64 - tb as f64) * p1_in as f64 + h as f64) as f32;
    }
    // Body 2 (`0x434c24`): h += sin((pi*p3) * NEG) * (max2(fvar4,x0) - lo_b50) * p1.
    if terrain_adjust_enter(fvar4, lo_b50) {
        let m = max2(fvar4, x0);
        let s = ((pi as f64 * p3_a0 as f64) * TERRAIN_GUARD_SIN_NEG as f64).sin();
        h = (s * (m as f64 - lo_b50 as f64) * p1_in as f64 + h as f64) as f32;
    }
    h
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

/// Sin-weight tail factors (`0x434cd8`-`0x434dcb`, exact file bits):
/// `[0x5ce058]` (t1 weight), `[0x5ce054]` (clamp half-width), `[0x5ce050]`
/// (f18 weight). See `evidence/004348a0_sin_tail.md`.
pub const TERRAIN_W_LO: f32 = f32::from_bits(0x3B5A_740E);
pub const TERRAIN_W_HI: f32 = f32::from_bits(0x3E99_999A);
pub const TERRAIN_W_F18: f32 = f32::from_bits(0x3D08_8889);

/// Sin-weight tail (`0x434cd8`-`0x434dcb`, per vertex, after the noise
/// loop; `evidence/004348a0_sin_tail.md`). Slot identities from ESP
/// simulation: `fvar4`/`fvar5` = vertex coords, `lo_b60` =
/// `strip_lo(b60)`, `param_5` read as `f32`, `base` = `00434ff0` return,
/// `h` = height accum, `noise` = cosine accum. x87 extended ≈ f64; one
/// f32 round per `FSTP` (`wsum`, `t1`/`t2`, `m1*h`, `combined`, clamp
/// args, `f18` arg, `v`). Combines reuse `max2`/`min2`/`clamp3` (same
/// `FCOMP` shapes + NaN sides as the reader sites).
#[allow(clippy::too_many_arguments)]
pub fn terrain_sin_tail(
    fvar4: f32,
    lo_b60: f32,
    fvar5: f32,
    param_5: f32,
    param_6: f32,
    param_7: f32,
    param_2: f32,
    base: f32,
    h: f32,
    noise: f32,
) -> f32 {
    // `FSIN` on the widened params (host sin ≈ x87 FSIN, see U-host-sin).
    let s6 = (param_6 as f64).sin();
    let s7 = (param_7 as f64).sin();
    // `FMULP`/`FADDP` order: `(fvar4-lo_b60)*s7 + fvar5*s6 + param_5`.
    let wsum = ((fvar4 as f64 - lo_b60 as f64) * s7 + fvar5 as f64 * s6 + param_5 as f64) as f32;
    let t1 = (base as f64 * TERRAIN_W_LO as f64) as f32;
    let t2 = (base as f64 * TERRAIN_W_HI as f64) as f32;
    let m1 = max2(param_2, 1.0 - t1);
    let m1h = (m1 as f64 * h as f64) as f32;
    let m2 = crate::fn_00435740::min2(1.0 - param_2, t1);
    let combined = (m2 as f64 * wsum as f64 + m1h as f64) as f32;
    let f16 = clamp3((h as f64 - t2 as f64) as f32, (h as f64 + t2 as f64) as f32, combined);
    let f18 = crate::fn_00435740::min2((base as f64 * TERRAIN_W_F18 as f64) as f32, 1.0);
    (f18 as f64 * noise as f64 + f16 as f64) as f32
}

/// `FUN_00435740` as called from `FUN_004348a0` (terrain builder):
/// `min2(a = lo_b50, b = lo_b60)` — first getter stages b60, second call
/// reads b50, stack at `CALL 00468340` is `[second=b50][first=b60]`
/// (`evidence/00435740_strip_minmax.md` §3). Reuses the checked `strip_lo`
/// getter (`FUN_004de320`) + `min2` (`FUN_00468340`); NaN either side → b60.
pub fn strip_lo_min(
    b50: &crate::fn_004de320::StripRange,
    b60: &crate::fn_004de320::StripRange,
) -> f32 {
    crate::fn_00435740::min2(
        crate::fn_004de320::strip_lo(b50),
        crate::fn_004de320::strip_lo(b60),
    )
}

/// `FUN_00435770` twin: `max2(a = hi_b50, b = hi_b60)` via the checked
/// `strip_hi` getter (`FUN_004de350`) + `max2` (`FUN_00468360`);
/// NaN either side → a (b50-side: NaN `hi_b50` survives as NaN, NaN
/// `hi_b60` falls back to `hi_b50`). Note the strip-minmax dossier §4
/// summary line says "NaN → b60-side" for max — the asm + `max2` mapping
/// it cites give a-side; this transcription follows the asm.
pub fn strip_hi_max(
    b50: &crate::fn_004de320::StripRange,
    b60: &crate::fn_004de320::StripRange,
) -> f32 {
    max2(
        crate::fn_004de320::strip_hi(b50),
        crate::fn_004de320::strip_hi(b60),
    )
}

/// Terrain builder `FUN_004348a0` entry/setup/grid driver
/// (`evidence/004348a0_terrain_loop.md`, tail
/// `evidence/004348a0_sin_tail.md`, slot map
/// `evidence/004df840_seed.md` + `evidence/00436620_param_keys.md` §4).
///
/// Fixed slot map (parse order `rs d2 d1 l2 l1 ax az y0 l0 a0 dh in`,
/// first-parsed deepest, so last-parsed = `param_1`):
/// `p1=in p2=dh p3=a0 p4=l0 p5=y0 p6=az p7=ax p8=l1
/// p9=l2 p10=d1 p11=d2 p12=rs` (seed, int-parsed via `004caee0`,
/// deepest slot; `RET 0x30` frame). Caller converts only `ax`/`az`
/// via `×pi×(1/180)` (`0x437649/0x43766f`), hence `deg2rad` touches
/// just those two.
///
/// Wired (asm order per vertex): `terrain_coords` → `TerrainBase::eval`
/// → guard predicates (`terrain_adjust_enter`) → `terrain_noise` →
/// `terrain_sin_tail` → `Vec::push` (std equivalent of the
/// `[this+0x74/0x78/0x7c]` vector push; original growth path
/// `operator_new`/`00475330`/`0059c120` stays open).
/// Open (caller-supplied, not guessed): RNG tables (`div`/`ph` need
/// `004df9a0`/`004df960` outputs), guard `xform` virtual targets
/// (combine itself = `terrain_guard_h`, wired as the `height` closure), `cols`/`step_x`/`base_x`
/// (`0059e643` + `__ftol` semantics unmapped), `thr`/`off` writers,
/// `lo_b60` strip object.
#[derive(Debug, Clone, Copy)]
pub struct Terrain {
    pub in_: f32,
    pub dh: f32,
    pub a0: f32,
    pub l0: f32,
    pub y0: f32,
    pub az: f32,
    pub ax: f32,
    pub l1: f32,
    pub l2: f32,
    pub d1: f32,
    pub d2: f32,
    /// `rs`: seed slot (`param_12`, int-parsed). Kept `f32` like
    /// `hill.rs`; the int parse (`004caee0`) has no transcription yet.
    pub rs: f32,
}

impl Terrain {
    pub fn from_map(m: &std::collections::HashMap<String, f32>) -> Result<Self, String> {
        let g = |k: &str| m.get(k).copied().ok_or_else(|| format!("terrain missing @{k}"));
        Ok(Terrain {
            in_: g("in")?,
            dh: g("dh")?,
            a0: g("a0")?,
            l0: g("l0")?,
            y0: g("y0")?,
            az: g("az")?,
            ax: g("ax")?,
            l1: g("l1")?,
            l2: g("l2")?,
            d1: g("d1")?,
            d2: g("d2")?,
            rs: g("rs")?,
        })
    }
}

/// Fixed grid axes (`0x434a6a`/`0x434a6e`): `[EBP+0x90]=10.0f`
/// (`0x41200000`), `[EBP+0x88]=10.0×-30.0` (`[0x5ce064]`).
pub const TERRAIN_STEP_Y: f32 = 10.0;
pub const TERRAIN_BASE_Y: f32 = -300.0;

/// Setup tap, pure part (`0x434949`-`0x434a0e`): amplitude tables
/// `ampA[k]=ampB[k]=k×(p11−p10)×0.125+p10` (`[0x5ce074]`=0.125,
/// `FILD` counter, exact). `p10=d1`, `p11=d2`.
pub fn terrain_amp_tap(k: u32, d1: f32, d2: f32) -> f32 {
    (k as f64 * (d2 as f64 - d1 as f64) * 0.125 + d1 as f64) as f32
}

/// Setup tap, pure part (same loop): divisor scale
/// `s=(p9−p8)×k×0.125+p8`; asm multiplies `(|RNG|+1.0)×s`
/// (`004df9a0` output open, caller supplies). `p8=l1`, `p9=l2`.
pub fn terrain_div_span(k: u32, l1: f32, l2: f32) -> f32 {
    ((l2 as f64 - l1 as f64) * k as f64 * 0.125 + l1 as f64) as f32
}

/// Setup tables: `amp` shared (`ampA==ampB` per asm, passed twice to
/// `terrain_noise`); `div`/`ph` need the RNG calls (open).
#[derive(Debug, Clone)]
pub struct TerrainTables {
    pub amp: [f32; 8],
    pub div_a: [f32; 8],
    pub ph_a: [f32; 8],
    pub div_b: [f32; 8],
    pub ph_b: [f32; 8],
}

/// Grid shape: `rows` fixed (`TERRAIN_ROWS`); `cols`/`step_x`/`base_x`
/// caller-supplied (`__ftol`/`0059e643` path open).
#[derive(Debug, Clone, Copy)]
pub struct TerrainGrid {
    pub cols: u32,
    pub step_x: f32,
    pub base_x: f32,
}

/// One `FUN_004348a0` vertex in asm order (`0x434b51`-`0x434dcb`):
/// coords → base → noise → sin tail. `h` = guard-block accum
/// (open: `004de3e0` targets/order); `xform` = opaque base transform
/// (`004de3e0`, `TerrainBase` U2); `lo_b60` = `strip_lo(b60)`.
/// `xform` runs once per vertex here (base only); guard-side `xform`
/// calls live inside the caller's `h` closure, like the asm repeats
/// the `CALL`.
#[allow(clippy::too_many_arguments)]
pub fn terrain_vertex(
    col: u32,
    row: u32,
    grid: &TerrainGrid,
    base: &TerrainBase,
    xform: impl FnOnce(f32) -> f32,
    h: f32,
    lo_b60: f32,
    params: &Terrain,
    tables: &TerrainTables,
    pi: f32,
) -> f32 {
    let (fvar4, fvar5) = terrain_coords(col, row, grid.step_x, grid.base_x, TERRAIN_STEP_Y, TERRAIN_BASE_Y);
    let b = base.eval(xform, fvar4, fvar5);
    let noise = terrain_noise(fvar4, fvar5, pi, &tables.div_a, &tables.ph_a, &tables.amp, &tables.div_b, &tables.ph_b, &tables.amp);
    terrain_sin_tail(fvar4, lo_b60, fvar5, params.y0, params.az, params.ax, params.dh, b, h, noise)
}

/// Grid driver: `61 × cols` vertices in row-major asm order, pushed
/// to a `Vec` (growth path open, see above). Deterministic given
/// fixed tables/`h` (RNG + guard-xform variance lives in inputs).
pub fn terrain_build(
    grid: &TerrainGrid,
    base: &TerrainBase,
    xform: impl Fn(f32) -> f32,
    height: impl Fn(f32, f32) -> f32,
    lo_b60: f32,
    params: &Terrain,
    tables: &TerrainTables,
    pi: f32,
) -> Vec<f32> {
    let mut out = Vec::with_capacity(grid.cols as usize * TERRAIN_ROWS as usize);
    for row in 0..TERRAIN_ROWS {
        for col in 0..grid.cols {
            let (fvar4, fvar5) = terrain_coords(col, row, grid.step_x, grid.base_x, TERRAIN_STEP_Y, TERRAIN_BASE_Y);
            let b = base.eval(&xform, fvar4, fvar5);
            let h = height(fvar4, b);
            out.push(terrain_vertex(col, row, grid, base, &xform, h, lo_b60, params, tables, pi));
        }
    }
    out
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

    /// ONE check for landing anchors `FUN_00434390`
    /// (`evidence/00434390_anchors.md` §2 chain,
    /// `evidence/00434390_emit_args.md` §§3-4 endpoint roles,
    /// `evidence/00436620_param_keys.md` §3 key map; generated
    /// fixture for unit shape + live Hill01 dhill values when
    /// user-supplied files present, skipped otherwise).
    #[test]
    fn landing_anchors_endpoints() {
        // Generated shape: endpoint relations straight from the
        // emit_args wiring (b60 cursor (N11,M10), b68 end (N11,0);
        // ddf10#2 curve end (L4x,S5) vs cursor (L4x,L4y)).
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
        for v in [a.l1x, a.l1y, a.l2x, a.l2y, a.l3x, a.l3y, a.l4x, a.s5, a.l4y, a.n9, a.n11, a.m10, a.at] {
            assert!(v.is_finite());
        }
        assert!((a.n11 - (a.n9 + 40.0)).abs() < 1e-3);
        assert!((a.m10 - (a.l4y + 3.0)).abs() < 1e-3);
        assert!((a.l4y - (a.s5 - 60.0)).abs() < 1e-3);
        assert!((a.at - (35.0f32 * PI / 180.0).atan()).abs() < 1e-6);
        // Live Hill01 dhill values (manifest locate like
        // hill.rs live_all_demo_hills): finite/bounded + same
        // endpoint relations with live nr/hr/rs.
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
        let raw = std::fs::read(r001).unwrap();
        let blob = crate::decrypt::decrypt(&raw, crate::decrypt::K_RES_HEX).unwrap();
        let e = man.entries.iter().find(|e| e.id.ends_with(".hil")).unwrap();
        let t = std::str::from_utf8(&blob[e.offset as usize..e.offset as usize + e.size as usize]).unwrap();
        let h = hill::parse(t).unwrap();
        let live = Landing::from_map(&h.profile_dhill).unwrap();
        let b = live.anchors(true);
        eprintln!("live landing anchors={b:?}");
        for v in [b.l1x, b.l1y, b.l2x, b.l2y, b.l3x, b.l3y, b.l4x, b.s5, b.l4y, b.n9, b.n11, b.m10, b.at, b.slope0, b.slope1] {
            assert!(v.is_finite(), "{v}");
            assert!(v.abs() < 5000.0, "{v}");
        }
        assert!((b.n11 - (b.n9 + live.nr)).abs() < 1e-2);
        assert!((b.m10 - (b.l4y + live.hr)).abs() < 1e-2);
        assert!((b.l4y - (b.s5 - live.rs)).abs() < 1e-2);
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
        // U3 wiring closed (evidence/00435740_strip_minmax.md §3):
        // 00435740 = min(lo_b50, lo_b60), 00435770 = max(hi_b50, hi_b60);
        // NaN either side -> b60-side value.
        use crate::fn_004de320::StripRange;
        let b50 = StripRange { lo: 12.5, hi: 44.0, present: true };
        let b60 = StripRange { lo: -3.25, hi: 47.75, present: true };
        assert_eq!(strip_lo_min(&b50, &b60), -3.25);
        assert_eq!(strip_hi_max(&b50, &b60), 47.75);
        let n = StripRange { lo: f32::NAN, hi: f32::NAN, present: true };
        assert_eq!(strip_lo_min(&n, &b60), -3.25);
        assert!(strip_lo_min(&b50, &n).is_nan());
        // max2 NaN either side -> a (b50-side): NaN hi_b50 survives as NaN,
        // NaN hi_b60 falls back to hi_b50.
        assert!(strip_hi_max(&n, &b60).is_nan());
        assert_eq!(strip_hi_max(&b50, &n), 44.0);
    }

    /// ONE check for the guard-block height accum `h`
    /// (`evidence/004348a0_guard_h.md`, generated fixtures — no
    /// original bytes): seed `xform_b60(min2(hi_b60, max2(lo_b60,
    /// fvar4)))`; body-1/body-2 guarded adds in asm order (incl. the
    /// body-2 `max2(fvar4, x0)` arg flip); NaN enters both guards with
    /// the asm a/b sides.
    #[test]
    fn terrain_guard_h_combine() {
        let id = |c: f32| c;
        // Seed only: fvar4=50 above both bounds; no guard enters.
        assert_eq!(terrain_guard_h(50.0, 10.0, 20.0, 2.0, 8.0, 100.0, 0.5, 0.0, PI, id, id), 20.0);
        // Both... first body only: fvar4=5 < lo_b60=10 enters body 1
        // (ta=5, tb=8: h=10+(5-8)*0.5=8.5); 5 >= lo_b50=2 skips body 2.
        assert_eq!(terrain_guard_h(5.0, 10.0, 20.0, 2.0, 8.0, 100.0, 0.5, 0.0, PI, id, id), 8.5);
        // Body 2 nonzero sin: lo_b60=1 skips body 1; fvar4=5 < lo_b50=10
        // enters body 2 with p3=90 → sin(-pi/2) ≈ -1, m=max2(5,100)=100:
        // h = 5 + (-1)*(100-10)*0.5 = -40 (tolerance: host sin ≈ FSIN).
        let h = terrain_guard_h(5.0, 1.0, 20.0, 10.0, 8.0, 100.0, 0.5, 90.0, PI, id, id);
        assert!((h - -40.0).abs() < 1e-4, "{h}");
        // NaN fvar4 enters both: seed max2(10,NaN)=10 → min2(20,10)=10;
        // body 1 max2(2,NaN)=2 → h=10+(2-8)*0.5=7; body 2
        // max2(NaN,100)=NaN, sin(0)=0 → 0*NaN=NaN poisons h.
        let h = terrain_guard_h(f32::NAN, 10.0, 20.0, 2.0, 8.0, 100.0, 0.5, 0.0, PI, id, id);
        assert!(h.is_nan(), "{h}");
    }

    /// ONE check for the `FUN_004348a0` sin-weight tail
    /// (`evidence/004348a0_sin_tail.md`, generated fixture — no
    /// original bytes): `wsum` sin wiring, `t1`/`t2` weights,
    /// `max2(param_2, 1-t1)` / `min2(1-param_2, t1)` combines,
    /// `clamp3(h-t2, h+t2)` center, `v = f18*noise + f16`;
    /// NaN `param_2` falls back to `lo`, NaN `base` poisons `v`.
    #[test]
    fn terrain_sin_tail_weights() {
        let v = terrain_sin_tail(7.0, 2.0, 3.0, 1.0, 0.0, 0.0, 0.25, 10.0, 5.0, 6.0);
        assert!((v - 6.8666663).abs() < 1e-5, "{v}");
        // sin(pi/2) steers fvar5 fully into wsum: 3*1+1 = 4.
        let v = terrain_sin_tail(7.0, 2.0, 3.0, 1.0, std::f32::consts::FRAC_PI_2, 0.0, 0.25, 10.0, 5.0, 6.0);
        assert!((v - 6.9666662).abs() < 1e-5, "{v}");
        // NaN param_2: m1 -> NaN side, m2 -> t1 side; combined NaN
        // clamps to lo = h - t2, so v = f18*noise + lo.
        let v = terrain_sin_tail(7.0, 2.0, 3.0, 1.0, 0.0, 0.0, f32::NAN, 10.0, 5.0, 6.0);
        assert!((v - 4.0).abs() < 1e-5, "{v}");
        // NaN base: weights NaN, f18 falls back to 1.0, v NaN.
        let v = terrain_sin_tail(7.0, 2.0, 3.0, 1.0, 0.5, -0.25, 0.25, f32::NAN, 5.0, 6.0);
        assert!(v.is_nan(), "{v}");
    }

    /// ONE check for the `FUN_004348a0` entry/setup/grid driver
    /// (slot map `evidence/004df840_seed.md` + param_keys §4; generated
    /// fixtures for unit parts, live Hill01 terrain profile when
    /// user-supplied files present, skipped otherwise): pure setup
    /// taps exact; grid finite + deterministic re-run.
    #[test]
    fn terrain_build_driver() {
        // Generated shape: amp/span taps linear in k (0.125 step).
        assert_eq!(terrain_amp_tap(0, 6.0, 7.0), 6.0);
        assert_eq!(terrain_amp_tap(4, 6.0, 7.0), 6.5);
        assert_eq!(terrain_amp_tap(7, 6.0, 7.0), 6.875);
        assert_eq!(terrain_div_span(0, 4.0, 5.0), 4.0);
        assert_eq!(terrain_div_span(7, 4.0, 5.0), 4.875);
        assert_eq!(TERRAIN_STEP_Y, 10.0);
        assert_eq!(TERRAIN_BASE_Y, -300.0);
        // Live Hill01 terrain profile via manifest locate (same shape
        // as `landing_anchors_endpoints` above).
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
        let raw = std::fs::read(r001).unwrap();
        let blob = crate::decrypt::decrypt(&raw, crate::decrypt::K_RES_HEX).unwrap();
        let e = man.entries.iter().find(|e| e.id.ends_with(".hil")).unwrap();
        let t = std::str::from_utf8(&blob[e.offset as usize..e.offset as usize + e.size as usize]).unwrap();
        let h = hill::parse(t).unwrap();
        let mut tp = Terrain::from_map(&h.profile_terrain).unwrap();
        // Caller converts ax/az deg→rad (param_keys §4 FMUL sites).
        tp.ax = tp.ax * PI / 180.0;
        tp.az = tp.az * PI / 180.0;
        eprintln!("live terrain params={tp:?} seed_rs={}", tp.rs);
        // Fixture tables (RNG outputs open): amp from live d1/d2,
        // div from live l1/l2 spans (unit RNG factor), zero phases.
        let mut amp = [0.0f32; 8];
        let mut div_a = [0.0f32; 8];
        let mut div_b = [0.0f32; 8];
        for k in 0..8 {
            amp[k] = terrain_amp_tap(k as u32, tp.d1, tp.d2);
            div_a[k] = terrain_div_span(k as u32, tp.l1, tp.l2);
            div_b[k] = div_a[k];
        }
        let tables = TerrainTables { amp, div_a, ph_a: [0.0; 8], div_b, ph_b: [0.0; 8] };
        // Fixtures for open parts: identity base xform, guard accum
        // = its transcription (`terrain_guard_h` curried over fixture
        // strips/xforms — the `height` closure seam; base value `b`
        // is not an input to `h`), zero lo strip.
        let base = TerrainBase { thr: 0.0, off: 0.0, x0: 0.0, lo: -100.0, hi: 100.0, range_present: true };
        let grid = TerrainGrid { cols: 41, step_x: 2.0, base_x: -40.0 };
        let build = || {
            terrain_build(
                &grid,
                &base,
                |c| c,
                |fvar4, _| terrain_guard_h(fvar4, -50.0, 50.0, -60.0, 60.0, 0.0, tp.in_, tp.a0, PI, |c| c, |c| c),
                0.0,
                &tp,
                &tables,
                PI,
            )
        };
        let g1 = build();
        let g2 = build();
        assert_eq!(g1.len(), TERRAIN_ROWS as usize * grid.cols as usize);
        assert!(g1.iter().all(|v| v.is_finite()));
        assert_eq!(g1, g2);
        eprintln!("live terrain sample={:?}", &g1[..4]);
        // Seeded RNG tables (live rs; `rng_float::terrain_rng_tables`):
        // second grid, finite + deterministic re-run + div>0.
        let seed = crate::rng_float::terrain_seed(&tp);
        let live = crate::rng_float::terrain_rng_tables(seed, &tp, PI);
        for k in 0..8 {
            for &d in &[live.div_a[k], live.div_b[k]] {
                assert!(d.is_finite() && d > 0.0, "{d}");
            }
        }
        let build_live = || {
            terrain_build(
                &grid,
                &base,
                |c| c,
                |fvar4, _| terrain_guard_h(fvar4, -50.0, 50.0, -60.0, 60.0, 0.0, tp.in_, tp.a0, PI, |c| c, |c| c),
                0.0,
                &tp,
                &live,
                PI,
            )
        };
        let r1 = build_live();
        let r2 = build_live();
        assert_eq!(r1.len(), g1.len());
        assert!(r1.iter().all(|v| v.is_finite()));
        assert_eq!(r1, r2);
        eprintln!("live rng tables seed={seed} div_a={:?} sample={:?}", live.div_a, &r1[..4]);
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
