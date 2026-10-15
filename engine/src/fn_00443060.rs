//! Cubic Hermite element ctor `0x443060` (evidence-backed).
//!
//! thiscall `FUN_00443060(x0, y0, x1, y1, m0, m1)` (`RET 0x18`): builds the
//! cubic `(x0,y0,m0)`, `(x1,y1,m1)` Hermite segment in absolute-`x` power
//! basis, stored to element slots `+12/+16/+20/+24` (`c3..c0`, outermost
//! Horner coeff first — see `crate::fn_004432a0`). Full pseudocode, asm,
//! callers, const refs: `evidence/00443060_cubic_ctor.md`.
//!
//! Only the coefficient core is transcribed here. The base-range call
//! (`0x442f30`, own procedure unit) and the element write-back (vtable
//! `0x5ce0fc`, `lo`/`hi`, slot stores — `mesh.rs` integration) are out of
//! scope; `engine/src/mesh.rs` is untouched.
//!
//! Caveat: asm accumulates each slot numerator/denominator in 80-bit `ST0`
//! with a single `FSTP m32` rounding per slot. Intermediates below are
//! `f64` (nearest portable stand-in), rounded once per slot on cast —
//! last-ulp differences vs the original are possible (carried U4).

/// Coeff core of `0x443060`: `(c3, c2, c1, c0)` for slots `+12..+24`.
///
/// Param roles (evidence §5, `m0`/`m1` assignment pinned by asymmetric
/// `2*m0+m1` term in `c2`): `x0`=param_1, `y0`=param_2, `x1`=param_3,
/// `y1`=param_4, `m0`=param_5 (slope at `x0`), `m1`=param_6 (slope at `x1`),
/// `h = x0 - x1` (`FSUB` order).
///
/// Closed forms (`H = x1 - x0 = -h`; Hermite `t = (x-x0)/H` expanded):
/// `c3 = (2*(y0-y1) + (m0+m1)*H) / H^3`,
/// `c2 = a2/H^2 - 3*a3*x0/H^3`, `c1 = m0 + 2*x0*(2*m0+m1)/H + ...`,
/// `c0 = y0 - m0*x0 + ...` with `a3 = 2*(y0-y1)+(m0+m1)*H`,
/// `a2 = 3*(y1-y0)-(2*m0+m1)*H` — each divided by `h^3` in `h`-form
/// (one `FDIVR` per slot in asm). Op shapes below follow the pseudocode
/// numerator parenthesization, not the compact forms.
///
/// Degenerate arm (`h == 0.0`, incl. `-0.0`, OR NaN — x87 C3 is set on
/// equal-or-unordered): `(0, 0, 0, y0)`, so the xform reads constant `y0`.
pub fn fn_00443060(x0: f32, y0: f32, x1: f32, y1: f32, m0: f32, m1: f32) -> (f32, f32, f32, f32) {
    let h = x0 - x1;
    if h == 0.0 || h.is_nan() {
        return (0.0, 0.0, 0.0, y0);
    }
    let (x0, y0, x1, y1, m0, m1, h) = (
        x0 as f64, y0 as f64, x1 as f64, y1 as f64, m0 as f64, m1 as f64, h as f64,
    );
    let h3 = h * h * h;
    let c3 = (y1 + y1 + (m0 + m1) * h - (y0 + y0)) / h3;
    let f2 = y0 * 3.0 - y1 * 3.0;
    let f3 = m0 + m0 + m1;
    let f4 = m1 + m1 + m0;
    let c2 = (((f2 - x1 * m0) + x1 * m1) * x0 + (f3 * x1 + f2) * x1 - x0 * x0 * f4) / h3;
    let c1 = (x0 * x0 * x0 * m1 + (x0 * x0 * f3 * x1 - x1 * x1 * x1 * m0)
        - (f4 * x1 + (y0 * 6.0 - y1 * 6.0)) * x0 * x1)
        / h3;
    let c0 = ((y1 - x1 * m1) * x0 * x0 * x0
        + (x1 * m0 + y0 * 3.0) * x1 * x1 * x0
        + ((m1 - m0) * x1 - y1 * 3.0) * x0 * x0 * x1
        - x1 * x1 * x1 * y0)
        / h3;
    (c3 as f32, c2 as f32, c1 as f32, c0 as f32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fn_004432a0::cubic_xform;

    /// ONE check (`evidence/00443060_cubic_ctor.md`, generated fixtures):
    /// ctor coeffs fed to the cubic xform reproduce endpoint values and
    /// slopes (Hermite identity; asymmetric slopes pin `m0`/`m1`
    /// assignment), plus the degenerate `h==0`/NaN arm `(0,0,0,y0)`.
    #[test]
    fn cubic_ctor_hermite() {
        for (x0, y0, x1, y1, m0, m1) in [
            (1.0f32, 2.0, 4.0, 3.0, 0.5, -0.25),
            (0.0, 1.0, 2.0, 0.0, 1.0, 1.0),
            (-3.0, 0.5, 1.5, -2.0, 0.0, 2.0),
        ] {
            let (c3, c2, c1, c0) = fn_00443060(x0, y0, x1, y1, m0, m1);
            for (x, ye, me) in [(x0, y0, m0), (x1, y1, m1)] {
                assert!((cubic_xform(c3, c2, c1, c0, x) - ye).abs() <= 1e-5, "{x} value");
                let slope = (3.0 * c3 * x + 2.0 * c2) * x + c1;
                assert!((slope - me).abs() <= 1e-5, "{x} slope");
            }
        }
        assert_eq!(fn_00443060(1.0, 2.0, 1.0, 9.0, 0.5, 0.5), (0.0, 0.0, 0.0, 2.0));
        assert_eq!(fn_00443060(-0.0, 2.0, 0.0, 9.0, 0.5, 0.5), (0.0, 0.0, 0.0, 2.0));
        assert_eq!(fn_00443060(f32::NAN, 2.0, 1.0, 9.0, 0.5, 0.5), (0.0, 0.0, 0.0, 2.0));
    }
}
