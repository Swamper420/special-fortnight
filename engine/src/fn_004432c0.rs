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
//! `(1+y'^2)^1.5/y''` with `FLT_MAX` arm) is transcribed below as
//! `cubic_radius` (`evidence/0059e3c2_pow.md` proves the `0x59e3a0`→
//! `0x59e3c2` helper is CRT `pow(double,double)`).
//!
//! Only these pure fragments are transcribed here; range gating stays in
//! the selector, same split as `crate::fn_004432a0`.
//!
//! Caveats: asm returns the 80-bit `ST0` value with no `FSTP m32`
//! rounding, and the `pow` runs in 80-bit (`FYL2X`/`F2XM1`/`FSCALE`)
//! while Rust uses `f64::powf` — `f32` output may differ on
//! sub-`f32`-precision borderlines (same ceiling as `f32::atan` in
//! `crate::fn_004de480`).

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

/// Cubic slot+8 `0x4432e0`: signed radius of curvature
/// `(1+y'^2)^1.5 / y''`, `FLT_MAX` when `y''` is zero or NaN.
///
/// `d2 = 6*c3*x + 2*c2` (`FCOMP`+C3 arm: equal OR unordered → `FLT_MAX`,
/// so NaN maps away here, contrast `cubic_slope`); `d1` is `cubic_slope`;
/// `pow` is CRT `pow(double,double)` (`evidence/0059e3c2_pow.md`).
/// `FDIVP` keeps the sign of `d2` (no `fabs`). `d2` is recomputed in asm
/// after the `pow`; computed once here (same value, no side effects).
pub fn cubic_radius(c3: f32, c2: f32, c1: f32, x: f32) -> f32 {
    let d2 = 6.0 * c3 * x + 2.0 * c2;
    if d2 == 0.0 || d2.is_nan() {
        return f32::MAX; // bits 0x7F7FFFFF, dword at 0x005ce0f4
    }
    let d1 = (3.0 * c3 * x + 2.0 * c2) * x + c1;
    // ponytail: f64 base skips an f32 rounding the asm never takes
    // (base travels ST0→double direct; the FST m32 at 0x44332c is dead).
    let p = f64::powf(1.0 + (d1 as f64) * (d1 as f64), 1.5);
    (p / d2 as f64) as f32
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

    /// ONE check (`evidence/004432c0_cubic_slots.md` +
    /// `evidence/0059e3c2_pow.md`, generated fixtures — no original
    /// bytes): radius values, `FLT_MAX` arm, sign, NaN map.
    #[test]
    fn cubic_radius_values() {
        // d2 = 0 -> FLT_MAX (zero and -0.0 both equal 0.0 in FCOMP).
        assert_eq!(cubic_radius(1.0, 0.0, 0.0, 0.0).to_bits(), 0x7F7F_FFFF);
        assert_eq!(cubic_radius(0.0, 0.0, 5.0, 99.0).to_bits(), 0x7F7F_FFFF);
        // NaN d2 maps to FLT_MAX (unordered takes the arm, never NaN out).
        assert_eq!(cubic_radius(f32::NAN, 1.0, 0.0, 0.0).to_bits(), 0x7F7F_FFFF);
        // d1 = 0, d2 = 2: (1+0)^1.5/2 = 0.5.
        assert_eq!(cubic_radius(0.0, 1.0, 0.0, 0.0), 0.5);
        // Sign of d2 preserved: d1 = 0, d2 = -2 -> -0.5.
        assert_eq!(cubic_radius(0.0, -1.0, 0.0, 0.0), -0.5);
        // d1 = 2, d2 = 2: 5^1.5/2 matches f64::powf reference.
        let r = cubic_radius(0.0, 1.0, 0.0, 1.0);
        let want = (5.0f64.powf(1.5) / 2.0) as f32;
        assert_eq!(r, want);
        assert!((r - 5.59017).abs() < 1e-4);
        // NaN c1 only: d1 NaN -> NaN out (pow(NaN,1.5) is NaN).
        assert!(cubic_radius(0.0, 1.0, f32::NAN, 0.0).is_nan());
        // Infinite slope: base +Inf -> +Inf/d2.
        assert_eq!(cubic_radius(0.0, 1.0, f32::INFINITY, 0.0), f32::INFINITY);
    }
}
