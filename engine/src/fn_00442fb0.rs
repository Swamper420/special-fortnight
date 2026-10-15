//! Linear element ctor `0x442fb0` (evidence-backed).
//!
//! thiscall `FUN_00442fb0(x0, y0, x1, y1)` (`RET 0x10`): builds the
//! segment line through `(x0,y0)`, `(x1,y1)`, stored to element slots
//! `+12` (slope) / `+16` (intercept) — see `crate::fn_00443030`. Full
//! pseudocode, asm, callers, const refs:
//! `evidence/00442fb0_linear_ctor.md`.
//!
//! Only the slope/intercept core is transcribed here. The base-range call
//! (`0x442f30`, own procedure unit) and the element write-back (vtable
//! `0x5ce0e8`, `lo`/`hi`, slot stores — `mesh.rs` integration) are out of
//! scope; `engine/src/mesh.rs` is untouched.
//!
//! Caveat: asm accumulates divide and mul/sub chains in 80-bit `ST0`
//! with a single `FSTP m32` rounding per slot. Intermediates below are
//! `f64` (nearest portable stand-in), rounded once per slot on cast —
//! last-ulp differences vs the original are possible (carried U2).

/// Slope/intercept core of `0x442fb0`: `(slope, intercept)` for slots `+12/+16`.
///
/// `gap = x1 - x0` (`FSUB` order). Normal arm (`0.0 < |gap|`,
/// ordered-above): `s = (y1-y0)/gap`, `b = y0-x0*s` (`FDIV ST0,ST1`
/// then `FSUBR` order). Degenerate arm (gap `== 0.0`, incl. `-0.0`,
/// OR NaN — x87 C3-or-C0 via `TEST AH,0x41`): `s = 0.0`, same
/// `b = y0-x0*0.0` shape (NOT simplified to `y0`: `x0=inf/NaN`
/// yields NaN through `FMUL`/`FSUBR`, preserved here).
pub fn fn_00442fb0(x0: f32, y0: f32, x1: f32, y1: f32) -> (f32, f32) {
    let (x0, y0, x1, y1) = (x0 as f64, y0 as f64, x1 as f64, y1 as f64);
    let gap = x1 - x0;
    let slope = if 0.0 < gap.abs() {
        ((y1 - y0) / gap) as f32
    } else {
        0.0
    };
    let intercept = (y0 - x0 * slope as f64) as f32;
    (slope, intercept)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fn_00443030::linear_xform;

    /// ONE check (`evidence/00442fb0_linear_ctor.md`, generated fixtures):
    /// ctor outputs fed to the slot-0 xform reproduce both endpoints,
    /// plus the degenerate `gap==0`/`-0.0`/NaN arms.
    #[test]
    fn linear_ctor_endpoints() {
        for (x0, y0, x1, y1) in [
            (1.0f32, 2.0, 3.0, 6.0),
            (0.0, 10.0, 4.0, 8.0),
            (-3.0, 0.5, 1.5, -2.0),
        ] {
            let (s, b) = fn_00442fb0(x0, y0, x1, y1);
            assert_eq!(linear_xform(s, b, x0), y0);
            assert_eq!(linear_xform(s, b, x1), y1);
        }
        assert_eq!(fn_00442fb0(1.0, 2.0, 1.0, 9.0), (0.0, 2.0));
        assert_eq!(fn_00442fb0(-0.0, 2.0, 0.0, 9.0), (0.0, 2.0));
        let (s, b) = fn_00442fb0(f32::NAN, 2.0, 1.0, 9.0);
        assert_eq!(s, 0.0);
        assert!(b.is_nan());
    }
}
