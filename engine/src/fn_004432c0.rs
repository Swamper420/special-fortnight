//! Cubic vtable slot +4: `0x4432c0` (evidence-backed).
//!
//! Bytes `0x4432c0-0x4432dd` (decoder `ev_1cd494f9...` .. `ev_3f5efb3b...`):
//! `FLD x; FMUL [ECX+0xC]; FMUL [0x005ce0f8]=3.0; FLD [ECX+0x10];`
//! `FADD ST0,ST0; FADDP; FMUL x; FADD [ECX+0x14]; RET 4` —
//! first derivative `y' = 3*c3*x^2 + 2*c2*x + c1` of the slot-0 Horner
//! cubic. `c0` (`+24`) unread. Reached only via vtable `0x5ce0fc` slot+4
//! (xref `ev_d806c6fe...`); `not_in_procedure` (`ev_b9a50dae...`).
//! Full asm, NaN map, callers: `evidence/004432c0_cubic_slots.md`.
//!
//! Sibling slot+8 (`0x4432e0`, signed radius of curvature
//! `(1+y'^2)^1.5/y''` with `FLT_MAX` arm) is analyzed in the same evidence
//! file but NOT transcribed here: it CALLs `0x443290` (square) and the
//! unverified double helper `0x59e3a0`→`0x59e3c2` (evidence U3).
//!
//! Only the pure derivative is transcribed here; range gating stays in the
//! selector, same split as `crate::fn_004432a0`.
//!
//! Caveat: asm returns the 80-bit `ST0` value with no `FSTP m32`
//! rounding; `f32` output may differ on sub-`f32`-precision borderlines.

/// Cubic slot+4 `0x4432c0`: `((x*c3*3 + 2*c2)*x + c1)`, op-for-op.
///
/// `FADD ST0,ST0` doubles `c2` (no `2.0` constant anywhere); the `3.0`
/// is the `.rdata` word at `0x005ce0f8`, not an immediate. NaN in any
/// input poisons the output (x87 QNaN passthrough; SNaN raises
/// invalid → QNaN) — never maps NaN away (contrast slot+8, which maps
/// zero/NaN `y''` to `FLT_MAX`).
pub fn cubic_slope(c3: f32, c2: f32, c1: f32, x: f32) -> f32 {
    (x * c3 * 3.0 + 2.0 * c2) * x + c1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE check (`evidence/004432c0_cubic_slots.md`, generated
    /// fixtures — no original bytes): derivative values, `c0`
    /// independence, NaN poisoning, overflow.
    #[test]
    fn cubic_slope_values() {
        // Coeffs (1,2,3): y' = 3x^2+4x+3: x=0 -> 3; x=1 -> 10; x=2 -> 23.
        assert_eq!(cubic_slope(1.0, 2.0, 3.0, 0.0), 3.0);
        assert_eq!(cubic_slope(1.0, 2.0, 3.0, 1.0), 10.0);
        assert_eq!(cubic_slope(1.0, 2.0, 3.0, 2.0), 23.0);
        // y' of a constant cubic is 0 whatever x is.
        assert_eq!(cubic_slope(0.0, 0.0, 0.0, -1e30), 0.0);
        assert_eq!(cubic_slope(0.0, 0.0, 0.0, 1e30), 0.0);
        // Negative x: 3*4+4*-2+3 = 12-8+3 = 7.
        assert_eq!(cubic_slope(1.0, 2.0, 3.0, -2.0), 7.0);
        // Term-for-term derivative of cubic_xform at (1,2,3,4), x=2:
        // (26-10)/eps ~ 23; check exact: slope matches Horner diff.
        assert_eq!(
            cubic_slope(1.0, 2.0, 3.0, 2.0),
            3.0 * 1.0 * 4.0 + 2.0 * 2.0 * 2.0 + 3.0
        );
        // NaN poisons (no mapping): x or any read coeff NaN -> NaN.
        assert!(cubic_slope(1.0, 2.0, 3.0, f32::NAN).is_nan());
        assert!(cubic_slope(f32::NAN, 2.0, 3.0, 1.0).is_nan());
        assert!(cubic_slope(1.0, f32::NAN, 3.0, 1.0).is_nan());
        assert!(cubic_slope(1.0, 2.0, f32::NAN, 1.0).is_nan());
        // Overflow -> inf, not trap (no status check in body).
        assert_eq!(cubic_slope(1.0, 0.0, 0.0, 1e30), f32::INFINITY);
    }
}
