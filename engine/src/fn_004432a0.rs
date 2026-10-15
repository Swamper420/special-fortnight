//! Cubic slot-0 xform `0x4432a0` (evidence-backed).
//!
//! Bytes `0x4432a0-0x4432ba` (`read_bytes ev_e350d247...`): thiscall
//! (`ECX` = cubic element, one `f32` stack arg, `RET 4`, `f32` in `ST0`):
//! Horner cubic `((c3*x+c2)*x+c1)*x+c0` with `c3=[ECX+0xC]`,
//! `c2=[ECX+0x10]`, `c1=[ECX+0x14]`, `c0=[ECX+0x18]` —
//! `FMUL,FADD` x3, no branches, no calls. Reached via vtable `0x5ce0fc`
//! slot 0 (`ev_59842dfd...`) from `FUN_004de3e0`, plus a direct static
//! call from `0x434390` (`ev_70bd7da4...`). Full asm, NaN map, callers:
//! `evidence/004432a0_cubic_xform.md`.
//!
//! Only the pure Horner chain is transcribed here; range gating stays in
//! the selector (`00442f80` predicate + `004de2a0`), same split as
//! `crate::fn_00443030::linear_xform`.
//!
//! Caveat: asm returns the 80-bit `ST0` value with no `FSTP m32`
//! rounding; `f32` output may differ on sub-`f32`-precision borderlines.
//! Coeff-slot mapping (`+12` = outermost multiplier) is body order only;
//! ctor `0x443060` input-to-slot wiring is out of scope (see evidence U4).

/// Cubic xform `0x4432a0`: Horner `((c3*x+c2)*x+c1)*x+c0`, op-for-op.
///
/// `FMUL,FADD` x3, no branches: NaN in any input poisons the output
/// (x87 QNaN passthrough; SNaN raises invalid → QNaN) — never maps NaN
/// away, unlike the `00442f80` predicate gates. Intermediate NaN
/// poisons all downstream rounds (single chain).
pub fn cubic_xform(c3: f32, c2: f32, c1: f32, c0: f32, x: f32) -> f32 {
    ((c3 * x + c2) * x + c1) * x + c0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE check for the cubic xform (`evidence/004432a0_cubic_xform.md`,
    /// generated fixtures — no original bytes): Horner values, constant
    /// shape, NaN poisoning, overflow.
    #[test]
    fn cubic_xform_values() {
        // Coeffs (1,2,3,4): x=0 -> 4; x=1 -> 10; x=2 -> 26.
        assert_eq!(cubic_xform(1.0, 2.0, 3.0, 4.0, 0.0), 4.0);
        assert_eq!(cubic_xform(1.0, 2.0, 3.0, 4.0, 1.0), 10.0);
        assert_eq!(cubic_xform(1.0, 2.0, 3.0, 4.0, 2.0), 26.0);
        // Zero high coeffs -> constant function y = c0.
        assert_eq!(cubic_xform(0.0, 0.0, 0.0, 2.5, -1e30), 2.5);
        assert_eq!(cubic_xform(0.0, 0.0, 0.0, 2.5, 1e30), 2.5);
        // Negative x general case: (1*-8)+(2*4)+(3*-2)+4 = -8+8-6+4 = -2.
        assert_eq!(cubic_xform(1.0, 2.0, 3.0, 4.0, -2.0), -2.0);
        // NaN poisons (no mapping): x or any coeff NaN -> NaN.
        assert!(cubic_xform(1.0, 2.0, 3.0, 4.0, f32::NAN).is_nan());
        assert!(cubic_xform(f32::NAN, 2.0, 3.0, 4.0, 1.0).is_nan());
        assert!(cubic_xform(1.0, f32::NAN, 3.0, 4.0, 1.0).is_nan());
        assert!(cubic_xform(1.0, 2.0, f32::NAN, 4.0, 1.0).is_nan());
        assert!(cubic_xform(1.0, 2.0, 3.0, f32::NAN, 1.0).is_nan());
        // Overflow -> inf, not trap (no status check in body).
        assert_eq!(cubic_xform(1.0, 0.0, 0.0, 0.0, 1e30), f32::INFINITY);
    }
}
