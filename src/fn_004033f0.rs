//! Original procedure `0x004033f0` (5 bytes, `0x004033f0–0x004033f4`).
//! Evidence: `evidence/004033f0_fn_004033f0.md`.

/// Target `0x004033f8` (`FUN_004033f8`), reached by direct `JMP`
/// with EAX/`ST(0)` lanes implicit: direct intra-reconstruction
/// call (rewired; signatures verified `fn(i32, f64) -> f64`).

/// `JMP 0x004033f8` — tail-forward with identical lanes.
pub unsafe fn fn_004033f0(exp: i32, st0: f64) -> f64 {
    crate::fn_004033f8::fn_004033f8(exp, st0)
}

#[cfg(test)]
mod tests {
    use super::fn_004033f0;

    #[test]
    fn forwards_to_real_scale() {
        // Real `fn_004033f8` lanes: identity, scale, saturation.
        assert_eq!(unsafe { fn_004033f0(0, 2.5) }, 2.5);
        assert!((unsafe { fn_004033f0(3, 1.5) } - 1500.0).abs() < 1e-9);
        assert!((unsafe { fn_004033f0(-2, 5.0) } - 0.05).abs() < 1e-12);
        assert_eq!(unsafe { fn_004033f0(0x1400, 1.0) }, f64::INFINITY);
        assert_eq!(unsafe { fn_004033f0(-0x1400, 1.0) }, 0.0);
    }
}
