//! Arc slot-0 xform `0x443450` (evidence-backed).
//!
//! Bytes `0x443450-0x4434c6` (`read_bytes ev_b875db8f...`): thiscall
//! (`ECX` = arc element, one `f32` stack arg, `RET 4`, `f32` in `ST0`):
//! `d = square([ECX+0x14]) - square(x-[ECX+0xC])` via helper `0x443290`
//! (`ev_5a54de34...`), `FCOMP` against `+0.0` at `[0x005cd378]`
//! (`ev_3d1f761d...`), `FNSTSW/TEST AH,1/JZ` guard, then
//! `y = [ECX+0x10] - [ECX+0x18]_i32 * sqrt(d or 0)`. The `JZ`-taken
//! block recomputes `d` (`FCOMP` popped it). No procedure entry exists
//! in the DB (`not_in_procedure`, `ev_706eca78...`; xrefs exactly
//! `["0x5ce110"]`, `ev_4da8ff9d...`) — reached only via vtable
//! `0x5ce110` slot 0 (`ev_75389852...`) from `FUN_004de3e0`. No trig
//! opcode in the body; the curve is `sqrt`, not `atan`. Full asm, NaN
//! map, callers: `evidence/00443450_arc_xform.md`.
//!
//! Only the pure guarded-sqrt is transcribed here; range gating stays in
//! the selector (`00442f80` predicate + `004de2a0`), same split as
//! `crate::fn_00443030::linear_xform`.
//!
//! Caveat: asm returns the 80-bit `ST0` value with no `FSTP m32`
//! rounding; `f32` output may differ on sub-`f32`-precision borderlines.
//! `FIMUL` scales by the exact `i32`; `n as f32` rounds `|n| > 2^24`
//! first. Field mapping (`+12/+16/+20/+24` roles) is body order only;
//! ctor `0x443370` input-to-slot wiring is out of scope (see evidence U4).

/// Arc xform `0x443450`: `cy - n*sqrt(max(d,0))`, branch-for-branch.
///
/// `d = r*r - (x-cx)*(x-cx)`; `d >= 0.0` (ordered, `JZ` taken) uses
/// `sqrt(d)`, else (negative or unordered/NaN) uses `sqrt(0.0)`.
/// NaN in `x`/`cx`/`r` therefore maps to `cy ∓ 0`, unlike the
/// linear/cubic xforms which poison through.
pub fn arc_xform(cx: f32, cy: f32, r: f32, n: i32, x: f32) -> f32 {
    let d = r * r - (x - cx) * (x - cx);
    // sqrt(0.0) is +0.0: matches the fallthrough path's FLD 0.0; FSQRT.
    let s = if d >= 0.0 { d.sqrt() } else { 0.0 };
    cy - n as f32 * s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE check for the arc xform (`evidence/00443450_arc_xform.md`,
    /// generated fixtures — no original bytes): clamped-sqrt values,
    /// `d == 0` branch boundary, mirrored `n`, NaN clamping.
    #[test]
    fn arc_xform_values() {
        // r=5, cx=1, cy=2, n=1: x=1 -> d=25 -> 2-5 = -3.
        assert_eq!(arc_xform(1.0, 2.0, 5.0, 1, 1.0), -3.0);
        // x=4 -> d=25-9=16 -> 2-4 = -2.
        assert_eq!(arc_xform(1.0, 2.0, 5.0, 1, 4.0), -2.0);
        // x=6 -> d=0 -> JZ-taken boundary -> 2-0 = 2.
        assert_eq!(arc_xform(1.0, 2.0, 5.0, 1, 6.0), 2.0);
        // x=7 -> d=-11 -> clamp path -> 2.
        assert_eq!(arc_xform(1.0, 2.0, 5.0, 1, 7.0), 2.0);
        // Negative n mirrors: x=4 -> 2+4 = 6.
        assert_eq!(arc_xform(1.0, 2.0, 5.0, -1, 4.0), 6.0);
        // Zero n -> cy everywhere (x=4: 2-0 = 2).
        assert_eq!(arc_xform(1.0, 2.0, 5.0, 0, 4.0), 2.0);
        // NaN clamps to cy (fallthrough path), unlike linear/cubic.
        assert_eq!(arc_xform(1.0, 2.0, 5.0, 1, f32::NAN), 2.0);
        assert_eq!(arc_xform(1.0, 2.0, f32::NAN, 1, 1.0), 2.0);
        assert_eq!(arc_xform(f32::NAN, 2.0, 5.0, 1, 1.0), 2.0);
        // NaN cy still poisons (FSUBR on both paths).
        assert!(arc_xform(1.0, f32::NAN, 5.0, 1, 4.0).is_nan());
    }
}
