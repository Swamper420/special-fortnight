//! Arc slot+4 `0x4434d0` slope (evidence-backed).
//!
//! Bytes `0x4434d0-0x443547` (entry-walk `ev_41a4b26e...`): thiscall
//! (`ECX` = arc element, one `f32` stack arg, `RET 4`, `f32` in `ST0`):
//! `d = square([ECX+0x14]) - square(x-[ECX+0xC])` via helper `0x443290`
//! (`ev_5a54de34...`), `FCOMP` against `1e-5f` at `[0x005ce11c]`
//! (`ev_3674b04b...`: bits `0x3727C5AC`), `FNSTSW/TEST AH,1/JZ` guard,
//! then merge `FLD x; FSUB [+12]; FIMUL [+24]_i32; FXCH; FSQRT;
//! FXCH; FXCH; FDIVP` = `(x-cx)*n/sqrt(s)` where `s = d` (`JZ` taken,
//! `d >= 1e-5f` ordered; block recomputes `d` since `FCOMP` popped it)
//! else `s = 1e-5f`. No procedure entry exists in the DB
//! (`not_in_procedure`, `ev_53f9e35e...`; xrefs exactly `["0x5ce114"]`,
//! `ev_4bfc75bc...`) — reached only via vtable `0x5ce110` slot+4
//! (`ev_75389852...`). Full asm, NaN map, callers:
//! `evidence/004434d0_arc_slot1.md`.
//!
//! This is `dy/dx` of the slot-0 curve `y = cy - n*sqrt(d)`
//! (`crate::fn_00443450`): `d/dx` gives `n*(x-cx)/sqrt(d)`. The epsilon
//! clamp keeps the divisor `>= sqrt(1e-5)`, so ordered inputs never
//! produce `inf`/`NaN`. Field `+16` (`cy`) is never read.
//!
//! Only the pure slope is transcribed here; range gating stays in
//! the selector, same split as `crate::fn_00443450::arc_xform`.
//!
//! Caveat: `d` is compared in 80-bit `ST0` (`FCOMP`, no rounding) while
//! the transcription compares an `f32` `d` — borderlines at `d ≈ 1e-5f`
//! can take different arms. Result stays 80-bit (`FDIVP`, no `FSTP m32`);
//! `FIMUL` scales the exact `i32` while `n as f32` rounds `|n| > 2^24`
//! first (exact for ctor `n ∈ {-1,+1}`).

/// Arc slope `0x4434d0`: `n*(x-cx)/sqrt(s)`, branch-for-branch.
///
/// `d = r*r - (x-cx)*(x-cx)`; `s = d` if `d >= 1e-5` (ordered, `JZ`
/// taken) else `s = 1e-5` (negative, tiny, or unordered/NaN). NaN in
/// `x`/`cx` poisons the numerator; NaN in `r` alone clamps to a finite
/// value; `cy` is unread so it cannot affect the result.
pub fn fn_004434d0(cx: f32, r: f32, n: i32, x: f32) -> f32 {
    let d = r * r - (x - cx) * (x - cx);
    // 1e-5f32 = 0x3727C5AC, the [0x005ce11c] constant (test-pinned).
    let s = if d >= 1e-5 { d } else { 1e-5 };
    (x - cx) * n as f32 / s.sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE check (`evidence/004434d0_arc_slot1.md`, generated
    /// fixtures — no original bytes): interior derivative values,
    /// clamp-path value, `d == 0` boundary, zero numerator, NaN map,
    /// epsilon bit pin.
    #[test]
    fn arc_slope_values() {
        // Epsilon constant is exactly 0x3727C5AC.
        assert_eq!(1e-5f32.to_bits(), 0x3727C5AC);
        // r=5, cx=1, n=1: x=4 -> d=16 -> 3*1/4 = 0.75.
        assert_eq!(fn_004434d0(1.0, 5.0, 1, 4.0), 0.75);
        // x=1 -> numerator 0 -> 0/5 = 0.
        assert_eq!(fn_004434d0(1.0, 5.0, 1, 1.0), 0.0);
        // Negative n mirrors: x=4 -> -3/4 = -0.75.
        assert_eq!(fn_004434d0(1.0, 5.0, -1, 4.0), -0.75);
        // Outside: x=7 -> d=-11 -> clamp -> 6/sqrt(1e-5).
        assert_eq!(fn_004434d0(1.0, 5.0, 1, 7.0), 6.0 / 1e-5f32.sqrt());
        // d == 0 boundary (x=6): clamp arm, numerator still 5.
        assert_eq!(fn_004434d0(1.0, 5.0, 1, 6.0), 5.0 / 1e-5f32.sqrt());
        // NaN x / cx poison through the numerator.
        assert!(fn_004434d0(1.0, 5.0, 1, f32::NAN).is_nan());
        assert!(fn_004434d0(f32::NAN, 5.0, 1, 1.0).is_nan());
        // NaN r alone clamps to finite (d NaN takes the eps arm).
        assert_eq!(fn_004434d0(1.0, f32::NAN, 1, 4.0), 3.0 / 1e-5f32.sqrt());
    }
}
