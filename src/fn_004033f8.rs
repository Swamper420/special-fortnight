//! Original procedure `0x004033f8` (169 bytes, `0x004033f8–0x004034a0`).
//! Evidence: `evidence/004033f8_fn_004033f8.md`.

/// Scale x87 `ST(0)` by `10^exp` (`exp` in EAX, signed).
///
/// Host model takes the FPU-stack slot as an explicit `f64` arg and
/// keeps the observed lane order: negative → divide lane,
/// zero → identity, `|exp| >= 0x1400` → saturation, else three
/// staged table multiplies/divides (5-bit, 4-bit, remainder chunks;
/// zero chunks skip their stage per the `JZ`s).
/// Table entries are undecoded (see evidence); stages use
/// `10^k` powers — a labeled guess, not an observation.
pub fn fn_004033f8(exp: i32, st0: f64) -> f64 {
    if exp < 0 {
        // 0x0040344c: NEG EAX; JGE saturation (unsigned compare
        // after NEG is exact as wrapping_neg + unsigned >=).
        let mag = (exp as u32).wrapping_neg();
        if mag >= 0x1400 {
            // FSTP ST0 + FLDZ.
            return 0.0;
        }
        let mut e = mag;
        let mut r = st0;
        let lo = e & 31;
        if lo != 0 {
            r /= 10f64.powi(lo as i32);
        }
        e >>= 5;
        if e == 0 {
            return r;
        }
        let mid = e & 15;
        if mid != 0 {
            r /= 10f64.powi((mid * 32) as i32);
        }
        e >>= 4;
        if e == 0 {
            return r;
        }
        r / 10f64.powi((e * 512) as i32)
    } else if exp == 0 {
        st0
    } else if (exp as u32) >= 0x1400 {
        // FSTP ST0 + FLD overflow const; const value unproven.
        //
        // ponytail: saturation as +inf, upgrade to decoded
        // `DAT_004034a1` bytes once table contents proven.
        f64::INFINITY
    } else {
        let mut e = exp as u32;
        let mut r = st0;
        let lo = e & 31;
        if lo != 0 {
            r *= 10f64.powi(lo as i32);
        }
        e >>= 5;
        if e == 0 {
            return r;
        }
        let mid = e & 15;
        if mid != 0 {
            r *= 10f64.powi((mid * 32) as i32);
        }
        e >>= 4;
        if e == 0 {
            return r;
        }
        r * 10f64.powi((e * 512) as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::fn_004033f8;

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() / b.abs().max(1e-300) < 1e-12
    }

    #[test]
    fn scale_lanes() {
        assert_eq!(fn_004033f8(0, 2.5), 2.5);
        assert!(close(fn_004033f8(1, 2.0), 20.0));
        assert!(close(fn_004033f8(3, 1.5), 1500.0));
        // exp=33: lo=1, mid=1, hi=0 → 10^1·10^32.
        assert!(close(fn_004033f8(33, 1.0), 1e33));
        assert!(close(fn_004033f8(-2, 5.0), 0.05));
        assert!(close(fn_004033f8(-33, 1.0), 1e-33));
        assert_eq!(fn_004033f8(0x1400, 1.0), f64::INFINITY);
        assert_eq!(fn_004033f8(-0x1400, 1.0), 0.0);
    }
}
