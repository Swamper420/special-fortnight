//! Landing 10x sample loop in `FUN_00434390` (evidence-backed).
//!
//! Scope: probe-sample driver ONLY (`0x4346cf-0x43473b`). The probe coeff
//! build (`CALL 0x00443060` at `0x4346ca` on a stack temp — see
//! `crate::fn_00443060`) and the `0x4de150` insert impurity stay out;
//! `eval` (slot-0 `0x4432a0` Horner on the probe coeffs) and `emit`
//! (`0x4de150`) are caller-passed closures — same split as
//! `crate::fn_004ddcb0::step_loop`. Full asm, pseudocode, const refs:
//! `evidence/00434390_sample_loop.md`. `engine/src/mesh.rs` untouched.
//!
//! Caveat: asm accumulates `i*pi*0.05`, `FSIN`, and the `x` chain in
//! 80-bit `ST0` with one `FSTP m32` rounding per sample. Intermediates
//! below are `f64` (nearest portable stand-in) — last-ulp differences
//! possible (evidence U3). Pi is loaded from `[0x61b880]` (file-zero,
//! set at runtime — evidence U1); `std::f64::consts::PI` used here.

/// Sample driver (`0x4346cf-0x43473b`):
/// `x_i = x1 - (1 - sin(i*pi*0.05)) * half * 0.5`, `i = 0..9`
/// (`FILD` counter, `FMUL pi`, `FMUL 0.05f32`, `FSIN`,
/// `FSUBR 1.0`, `FMUL half`, `FMUL 0.5`, `FSUBR x1` — order kept).
///
/// Exactly 10 iters (`INC EDI / CMP EDI,0xa / JC` unsigned-below,
/// post-increment `do/while`); no early exit. Per iter: `emit(x, eval(x))`.
pub fn sample_loop(
    x1: f32,
    half: f32,
    mut eval: impl FnMut(f32) -> f32,
    mut emit: impl FnMut(f32, f32),
) {
    let mut i: u32 = 0;
    loop {
        let s = (i as f64 * std::f64::consts::PI * f64::from(0.05f32)).sin();
        let x = (f64::from(x1) - (1.0 - s) * f64::from(half) * 0.5) as f32;
        let y = eval(x);
        emit(x, y);
        i += 1;
        if i >= 10 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE check (`evidence/00434390_sample_loop.md`, generated fixtures —
    /// stub eval, no original bytes): exactly 10 samples, exact `i=0`
    /// anchor `x1 - half/2`, monotone rise toward `x1`, `(x, eval(x))`
    /// wiring, `half=0` degenerates to all-`x1`.
    #[test]
    fn landing_sample_loop() {
        let mut pts = Vec::new();
        sample_loop(10.0, 4.0, |x| x * 2.0, |x, y| pts.push((x, y)));
        assert_eq!(pts.len(), 10);
        assert_eq!(pts[0].0, 8.0); // sin(0) = 0 -> 10 - 1*4*0.5
        for w in pts.windows(2) {
            assert!(w[0].0 < w[1].0, "monotone rise");
            assert!(w[1].0 < 10.0, "below anchor");
        }
        for (x, y) in &pts {
            assert_eq!(*y, x * 2.0);
        }

        let mut pts = Vec::new();
        sample_loop(3.0, 0.0, |x| x, |x, y| pts.push((x, y)));
        assert_eq!(pts.len(), 10);
        for (x, y) in &pts {
            assert_eq!(*x, 3.0);
            assert_eq!(*y, 3.0);
        }
    }
}
