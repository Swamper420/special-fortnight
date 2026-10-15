//! Linear slot-0 xform `0x443030` (evidence-backed).
//!
//! Bytes `0x443030-0x44303c` (`read_bytes ev_2894cc26...`): thiscall
//! (`ECX` = linear element, one `f32` stack arg, `RET 4`, `f32` in `ST0`):
//! `FLD [ESP+4]; FMUL [ECX+0xC] (slope); FADD [ECX+0x10] (intercept)`.
//! No procedure entry exists in the DB (`not_in_procedure`,
//! `ev_6b5fcd28...`) — reached only via vtable `0x5ce0e8` slot 0
//! (`ev_5e9d537d...`) from `FUN_004de3e0`. Ctor `FUN_00442fb0`
//! (`ev_f5a89aaf...`) sets `+12 = (p4-p2)/(p3-p1)`, `+16 = p2-p1*slope`
//! (degenerate gap: slope `0`, intercept `p2`). Full asm, NaN map,
//! callers: `evidence/00443030_linear_xform.md`.
//!
//! Only the pure multiply-add is transcribed here; range gating stays in
//! the selector (`00442f80` predicate + `004de2a0`), same split as
//! `crate::fn_004357a0::strip_range_predicate`.
//!
//! Caveat: asm returns the 80-bit `ST0` value with no `FSTP m32`
//! rounding; `f32` output may differ on sub-`f32`-precision borderlines.

/// Linear xform `0x443030`: `slope * x + intercept`, op-for-op.
///
/// `FMUL` then `FADD`, no branches: NaN in any input poisons the output
/// (x87 QNaN passthrough; SNaN raises invalid → QNaN) — never maps NaN
/// away, unlike the `00442f80` predicate gates.
pub fn linear_xform(slope: f32, intercept: f32, x: f32) -> f32 {
    slope * x + intercept
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE check for the linear xform (`evidence/00443030_linear_xform.md`,
    /// generated fixtures — no original bytes): ctor-consistent line
    /// values, degenerate constant shape, NaN poisoning, overflow.
    #[test]
    fn linear_xform_values() {
        // Ctor shape: line through (1,2),(3,6) -> slope 2, intercept 0.
        assert_eq!(linear_xform(2.0, 0.0, 4.0), 8.0);
        assert_eq!(linear_xform(2.0, 0.0, 1.0), 2.0);
        assert_eq!(linear_xform(2.0, 0.0, 3.0), 6.0);
        // Degenerate ctor path (zero gap): slope 0, intercept p2 -> const.
        assert_eq!(linear_xform(0.0, 2.5, -1e30), 2.5);
        assert_eq!(linear_xform(0.0, 2.5, 1e30), 2.5);
        // Negative slope general case.
        assert_eq!(linear_xform(-0.5, 10.0, 4.0), 8.0);
        // NaN poisons (no mapping): x, slope, or intercept NaN -> NaN.
        assert!(linear_xform(2.0, 0.0, f32::NAN).is_nan());
        assert!(linear_xform(f32::NAN, 0.0, 1.0).is_nan());
        assert!(linear_xform(2.0, f32::NAN, 1.0).is_nan());
        // Overflow -> inf, not trap (no status check in body).
        assert_eq!(linear_xform(2.0, 0.0, f32::MAX), f32::INFINITY);
    }
}
