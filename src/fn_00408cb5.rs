//! Original procedure `0x00408cb5` (274 bytes, `0x408cb5–0x408dc6`).
//! Evidence: `evidence/00408cb5_fn_00408cb5.md`.

/// `DAT_00412824`: 10-byte extended-double compare const (observed
/// image bytes decode to exactly `1e18`; see evidence).
///
/// ponytail: static standing in for image bytes, rewire to real
/// image-relative data once data layout proven.
pub static mut DAT_00412824: [u8; 10] =
    [0x00, 0x00, 0x40, 0x76, 0x3a, 0x6b, 0x0b, 0xde, 0x3a, 0x40];

/// `DAT_00412830`: i32 `FIDIV` divisor (observed image bytes: `10`).
///
/// ponytail: static standing in for image bytes, rewire to real
/// image-relative data once data layout proven.
pub static mut DAT_00412830: i32 = 10;

/// Host `f64` read of a 10-byte little-endian extended double
/// (sign + 15-bit exponent + 64-bit mantissa with explicit integer
/// bit). Exact only for values fitting `f64`; the original kept 80
/// bits throughout (see Unknowns in evidence).
fn ext80_to_f64(mantissa: u64, exp_word: u16) -> f64 {
    let unbiased = ((exp_word & 0x7fff) as i32).wrapping_sub(0x3fff);
    let sign = if exp_word & 0x8000 != 0 { -1.0 } else { 1.0 };
    sign * (mantissa as f64) / 9_223_372_036_854_775_808.0 * 2f64.powi(unbiased)
}

/// ce2→db8 tail: `[out+3]=0`, `[out]=e`, `[out+2]=sign`.
unsafe fn store_tail(out: *mut u8, e: u16, sign: u8) {
    core::ptr::write_unaligned(out.wrapping_byte_add(3), 0u8);
    core::ptr::write_unaligned(out as *mut u16, e);
    core::ptr::write_unaligned(out.wrapping_byte_add(2), sign);
}

/// db1→db5→db8 tail: `[out]=est` (low 16), `[out+2]=sign>>15`.
unsafe fn tail(out: *mut u8, sign_src: u16, est: i32) {
    core::ptr::write_unaligned(out as *mut u16, est as u16);
    core::ptr::write_unaligned(out.wrapping_byte_add(2), ((sign_src >> 15) & 1) as u8);
}

/// Normal lane (0x408ceb…): scale, round, normalize, BCD-unpack,
/// keep-count round/truncate, sign tail.
unsafe fn convert_normal(
    out: *mut u8,
    input: *mut u8,
    exp_word: u16,
    mag: u32,
    param_4: u32,
    param_5: u32,
) {
    // 0x408ceb FLD: full 80-bit magnitude (host f64 read).
    let mantissa: u64 = core::ptr::read_unaligned(input as *const u64);
    let f = ext80_to_f64(mantissa, exp_word).abs();
    // 0x408ced: est = (((mag-0x3fff)*0x4d10)>>16)+1, 32-bit wrap + SAR.
    let mut est =
        (mag.wrapping_sub(0x3fff).wrapping_mul(0x4d10) as i32 >> 16).wrapping_add(1);
    // 0x408cff: EAX=0x12-est; FABS; thunk scales ST(0)
    // (EBX=[EBP-4]=0, the dispatcher-zeroed local).
    let scale_arg = 0x12i32.wrapping_sub(est);
    let mut r = crate::fn_004033f8::fn_004033f8(scale_arg, f);
    // 0x408d13 FRNDINT (nearest-even assumed; see evidence).
    r = r.round_ties_even();
    // 0x408d15: EDI=[EBP-4]=0; FLD [0x412824]; FCOMP; FSTSW.
    let tbytes: [u8; 10] =
        core::ptr::read_unaligned(core::ptr::addr_of!(DAT_00412824));
    let table = ext80_to_f64(
        u64::from_le_bytes([
            tbytes[0], tbytes[1], tbytes[2], tbytes[3], tbytes[4], tbytes[5], tbytes[6],
            tbytes[7],
        ]),
        u16::from_le_bytes([tbytes[8], tbytes[9]]),
    );
    // 0x408d25 TEST 0x4100 (C3|C0): !(table > r) → FIDIV + est++.
    if !(table > r) {
        let div: f64 =
            core::ptr::read_unaligned(core::ptr::addr_of!(DAT_00412830)) as f64;
        r /= div;
        est = est.wrapping_add(1);
    }
    // 0x408d36 FBSTP → 18 BCD digits (rounds again per RC).
    // Out-of-f64-range magnitudes saturate (original stored
    // indefinite BCD; see Unknowns).
    let n: u64 = if r.is_finite() {
        r.round_ties_even().clamp(0.0, 999_999_999_999_999_999.0) as u64
    } else {
        999_999_999_999_999_999
    };
    let mut dig = [0u8; 18];
    {
        let mut t = n;
        for i in (0..18).rev() {
            dig[i] = (t % 10) as u8;
            t /= 10;
        }
    }
    // 9-iteration STOSW loop + STOSB NUL at out+3.
    let mut p = out.wrapping_byte_add(3);
    for j in 0..9 {
        core::ptr::write_unaligned(p, dig[2 * j].wrapping_add(b'0'));
        core::ptr::write_unaligned(p.wrapping_byte_add(1), dig[2 * j + 1].wrapping_add(b'0'));
        p = p.wrapping_byte_add(2);
    }
    core::ptr::write_unaligned(p, 0u8);
    // 0x408d5a: keep = est + [EBP+8] (wrap); JNS else zero path.
    let keep = (est as u32).wrapping_add(param_4);
    if (keep as i32) < 0 {
        store_tail(out, 0, 0);
        return;
    }
    // 0x408d69: unsigned min with [EBP+0xc].
    let mut k = if keep < param_5 { keep } else { param_5 };
    // 0x408d71: <0x12 → round-or-truncate at digit[k], else k=0x12.
    if k < 0x12 {
        let at = out.wrapping_byte_add(3).wrapping_byte_add(k as usize);
        let d: u8 = core::ptr::read_unaligned(at as *const u8);
        if d >= 0x35 {
            // Round-up lane with '9'-carry (0x408d7d…).
            let mut c = k;
            loop {
                let slot = out.wrapping_byte_add(3).wrapping_byte_add(c as usize);
                core::ptr::write_unaligned(slot, 0u8);
                c = c.wrapping_sub(1);
                if (c as i32) < 0 {
                    // 0x408d92: [EBX+3]=0x31 word, est++.
                    core::ptr::write_unaligned(out.wrapping_byte_add(3) as *mut u16, 0x31);
                    est = est.wrapping_add(1);
                    break;
                }
                let pos = out.wrapping_byte_add(3).wrapping_byte_add(c as usize);
                let v: u8 =
                    core::ptr::read_unaligned(pos as *const u8).wrapping_add(1);
                core::ptr::write_unaligned(pos, v);
                if v <= 0x39 {
                    break;
                }
            }
            tail(out, exp_word, est);
            return;
        }
        // else fall through to the truncate/strip lane, k unchanged.
    } else {
        k = 0x12;
    }
    // Truncate/strip lane (0x408da2…): NUL at k, strip '0's down;
    // running off the front clears the sign (0x408dc3→db5).
    let mut sign_src = exp_word;
    loop {
        let slot = out.wrapping_byte_add(3).wrapping_byte_add(k as usize);
        core::ptr::write_unaligned(slot, 0u8);
        k = k.wrapping_sub(1);
        if (k as i32) < 0 {
            sign_src = 0;
            break;
        }
        let pos = out.wrapping_byte_add(3).wrapping_byte_add(k as usize);
        if core::ptr::read_unaligned(pos as *const u8) != b'0' {
            break;
        }
    }
    tail(out, sign_src, est);
}

/// Extended-double at `input` → `{exp, sign, digits}` at `out`
/// (≥22 bytes: 3 header + 18 digits + NUL). `param_4`/`param_5` are
/// the shared-frame `[EBP+8]`/`[EBP+0xC]`. No prologue: shares
/// `0x408c88`'s frame (sole caller). `RET` pops nothing.
pub unsafe fn fn_00408cb5(out: *mut u8, input: *mut u8, param_4: u32, param_5: u32) {
    // 0x408cb5: AX=[ESI+8]; EDX=EAX; EAX&=0x7fff.
    let exp_word: u16 =
        core::ptr::read_unaligned(input.wrapping_byte_add(8) as *const u16);
    let mag = (exp_word as u32) & 0x7fff;
    // 0x408cc0 JZ: zero/subnormal lane (ce0→ce2→db8, EAX=0, EDX=0).
    if mag == 0 {
        store_tail(out, 0, 0);
        return;
    }
    if mag != 0x7fff {
        convert_normal(out, input, exp_word, mag, param_4, param_5);
        return;
    }
    // Inf/nan lane (0x408cc9…): integer-bit test, then mantissa words.
    let intbit: u16 =
        core::ptr::read_unaligned(input.wrapping_byte_add(6) as *const u16) & 0x8000;
    if intbit == 0 {
        // ce2→db8 with the exponent word (sign preserved).
        store_tail(out, 0x7fff, (exp_word >> 15) as u8);
        return;
    }
    let lo: u32 = core::ptr::read_unaligned(input as *const u32);
    if lo != 0 {
        // cdf→ce0→ce2→db8: EAX=0x8000, EDX=0.
        store_tail(out, 0x8000, 0);
        return;
    }
    let hi: u32 = core::ptr::read_unaligned(input.wrapping_byte_add(4) as *const u32);
    if hi != 0x8000_0000 {
        store_tail(out, 0x8000, 0);
        return;
    }
    // Integer-bit-only mantissa = ±inf.
    store_tail(out, 0x7fff, (exp_word >> 15) as u8);
}

#[cfg(test)]
mod tests {
    use super::{DAT_00412824, DAT_00412830, fn_00408cb5};

    unsafe fn word_at(p: *mut u8, off: usize) -> u16 {
        core::ptr::read_unaligned(p.wrapping_byte_add(off) as *const u16)
    }

    unsafe fn byte_at(p: *mut u8, off: usize) -> u8 {
        core::ptr::read_unaligned(p.wrapping_byte_add(off) as *const u8)
    }

    unsafe fn digits_eq(p: *mut u8, want: &[u8]) -> bool {
        for (i, b) in want.iter().enumerate() {
            if byte_at(p, 3 + i) != *b {
                return false;
            }
        }
        byte_at(p, 3 + want.len()) == 0
    }

    fn input10(mant: u64, exp: u16) -> [u8; 10] {
        let mut b = [0u8; 10];
        b[..8].copy_from_slice(&mant.to_le_bytes());
        b[8..].copy_from_slice(&exp.to_le_bytes());
        b
    }

    #[test]
    fn class_lanes() {
        // Tables pin the observed image bytes.
        assert_eq!(
            unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(DAT_00412824)) },
            [0x00, 0x00, 0x40, 0x76, 0x3a, 0x6b, 0x0b, 0xde, 0x3a, 0x40]
        );
        assert_eq!(
            unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(DAT_00412830)) },
            10
        );

        // Zero-exp lane → {0, 0, ""}.
        let mut out = [0xAAu8; 32];
        let mut zero = [0u8; 10];
        unsafe { fn_00408cb5(out.as_mut_ptr(), zero.as_mut_ptr(), 0, 9) };
        assert_eq!(unsafe { word_at(out.as_mut_ptr(), 0) }, 0);
        assert_eq!(unsafe { byte_at(out.as_mut_ptr(), 2) }, 0);
        assert!(unsafe { digits_eq(out.as_mut_ptr(), b"") });

        // +inf → {0x7FFF, 0, ""}.
        let mut out = [0xAAu8; 32];
        let mut infp = input10(0x8000_0000_0000_0000, 0x7FFF);
        unsafe { fn_00408cb5(out.as_mut_ptr(), infp.as_mut_ptr(), 0, 9) };
        assert_eq!(unsafe { word_at(out.as_mut_ptr(), 0) }, 0x7FFF);
        assert_eq!(unsafe { byte_at(out.as_mut_ptr(), 2) }, 0);
        assert!(unsafe { digits_eq(out.as_mut_ptr(), b"") });

        // -inf → {0x7FFF, 1, ""}.
        let mut out = [0xAAu8; 32];
        let mut infn = input10(0x8000_0000_0000_0000, 0xFFFF);
        unsafe { fn_00408cb5(out.as_mut_ptr(), infn.as_mut_ptr(), 0, 9) };
        assert_eq!(unsafe { word_at(out.as_mut_ptr(), 0) }, 0x7FFF);
        assert_eq!(unsafe { byte_at(out.as_mut_ptr(), 2) }, 1);
        assert!(unsafe { digits_eq(out.as_mut_ptr(), b"") });

        // Nan with integer bit + payload → {0x8000, 0, ""}.
        let mut out = [0xAAu8; 32];
        let mut nan = input10(0xC000_0000_0000_0000, 0x7FFF);
        unsafe { fn_00408cb5(out.as_mut_ptr(), nan.as_mut_ptr(), 0, 9) };
        assert_eq!(unsafe { word_at(out.as_mut_ptr(), 0) }, 0x8000);
        assert_eq!(unsafe { byte_at(out.as_mut_ptr(), 2) }, 0);
        assert!(unsafe { digits_eq(out.as_mut_ptr(), b"") });

        // Nan, integer bit clear → exponent-word lane {0x7FFF, sign, ""}.
        let mut out = [0xAAu8; 32];
        let mut nan2 = input10(0x4000_0000_0000_0000, 0xFFFF);
        unsafe { fn_00408cb5(out.as_mut_ptr(), nan2.as_mut_ptr(), 0, 9) };
        assert_eq!(unsafe { word_at(out.as_mut_ptr(), 0) }, 0x7FFF);
        assert_eq!(unsafe { byte_at(out.as_mut_ptr(), 2) }, 1);
        assert!(unsafe { digits_eq(out.as_mut_ptr(), b"") });

        // Normal lane: 8.0, decimals 0 → "8", exp 1, sign 0.
        let mut out = [0xAAu8; 32];
        let mut eight = input10(0x8000_0000_0000_0000, 0x4002);
        unsafe { fn_00408cb5(out.as_mut_ptr(), eight.as_mut_ptr(), 0, 9) };
        assert_eq!(unsafe { word_at(out.as_mut_ptr(), 0) }, 1);
        assert_eq!(unsafe { byte_at(out.as_mut_ptr(), 2) }, 0);
        assert!(unsafe { digits_eq(out.as_mut_ptr(), b"8") });

        // Normal lane: -8.0 → same with sign 1.
        let mut out = [0xAAu8; 32];
        let mut neight = input10(0x8000_0000_0000_0000, 0xC002);
        unsafe { fn_00408cb5(out.as_mut_ptr(), neight.as_mut_ptr(), 0, 9) };
        assert_eq!(unsafe { word_at(out.as_mut_ptr(), 0) }, 1);
        assert_eq!(unsafe { byte_at(out.as_mut_ptr(), 2) }, 1);
        assert!(unsafe { digits_eq(out.as_mut_ptr(), b"8") });
    }
}
