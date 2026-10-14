//! Original procedure `0x00408dd7` (212 bytes, `0x408dd7–0x408eaa`).
//! Evidence: `evidence/00408dd7_fn_00408dd7.md`.

/// Embedded `FIDIV` divisor table reused from code bytes at
/// `0x408dc3`: `[0x408dc3]` decodes from live instruction bytes
/// (`XOR EDX,EDX; JMP -0x12` = `0xEEEBD231`, never consumed — the
/// `scale == 4` lane always skips `FIDIV`); the rest are the `.text`
/// gap dwords `10, 100, 1000, 10000` (see evidence).
///
/// ponytail: static standing in for image bytes, rewire to real
/// image-relative data once data layout proven.
pub static mut TABLE_00408DC3: [u32; 5] = [0xEEEB_D231, 10, 100, 1000, 10000];

/// Zero lane (`0x408e9d→0x408ea4`): `{len 0, sign 0, ""}`.
unsafe fn store_zero(out: *mut u8) {
    core::ptr::write_unaligned(out.wrapping_byte_add(3), 0u8);
    core::ptr::write_unaligned(out as *mut u16, 0u16);
    core::ptr::write_unaligned(out.wrapping_byte_add(2), 0u8);
}

/// Emit `dig[2*j]…` nibble pairs as ASCII chars (MSB-first),
/// returning the end pointer. Shared by the count-char lane and the
/// skip-lane tail (assembly shares them via `JNZ 0x408e6e`).
unsafe fn emit_from(mut p: *mut u8, dig: &[u8; 18], mut j: usize) -> *mut u8 {
    while j < 9 {
        core::ptr::write_unaligned(p, dig[2 * j].wrapping_add(b'0'));
        p = p.wrapping_byte_add(1);
        core::ptr::write_unaligned(p, dig[2 * j + 1].wrapping_add(b'0'));
        p = p.wrapping_byte_add(1);
        j += 1;
    }
    p
}

/// `u64` magnitude at `input` → `{len, sign, digits}` at `out`.
/// `param_4` is the shared-frame `[EBP+8]` (clamped 0..4);
/// `[EBP+0xC]` is never read here (see evidence). `RET` pops
/// nothing. `WAIT`s are host no-ops.
pub unsafe fn fn_00408dd7(out: *mut u8, input: *mut u8, param_4: u32) {
    // 0x408dd7: EAX=[ESI]; EDX=[ESI+4]; ECX=EAX|EDX; JZ e9d.
    let mut lo: u32 = core::ptr::read_unaligned(input as *const u32);
    let mut hi: u32 = core::ptr::read_unaligned(input.wrapping_byte_add(4) as *const u32);
    if lo | hi == 0 {
        store_zero(out);
        return;
    }
    let orig_hi = hi;
    // 0x408de6: JNS df1 else NEG EDX; NEG EAX; SBB EDX,0 (64-bit negate).
    if (hi as i32) < 0 {
        let borrow = if lo != 0 { 1u32 } else { 0u32 };
        lo = lo.wrapping_neg();
        hi = hi.wrapping_neg().wrapping_sub(borrow);
    }
    // 0x408df1: count=0; scale=[EBP+8] clamped <0→0, >3→4.
    let mut scale = param_4 as i32;
    if scale < 0 {
        scale = 0;
    }
    let mut count: u32 = 0;
    if scale > 3 {
        scale = 4;
        // 0x408e06: INC/SUB/SBB/JNC … DEC/ADD/ADC = exact udivmod by 10^18.
        let full = ((hi as u64) << 32) | lo as u64;
        count = (full / 1_000_000_000_000_000_000) as u32;
        let rem = full % 1_000_000_000_000_000_000;
        lo = rem as u32;
        hi = (rem >> 32) as u32;
    }
    // FILD qword; FIDIV 10^(4-scale) unless scale==4; FBSTP rounds
    // per FPU RC (nearest-even assumed — see evidence): exact
    // integer math, since halfway cases sit ≥1/(2·divisor) from .5,
    // beyond 80-bit rounding noise.
    let n: u64 = if scale == 4 {
        ((hi as u64) << 32) | lo as u64
    } else {
        let table: [u32; 5] =
            core::ptr::read_unaligned(core::ptr::addr_of!(TABLE_00408DC3));
        let div = table[(4 - scale) as usize] as u64;
        let full = ((hi as u64) << 32) | lo as u64;
        let mut q = full / div;
        let r = full % div;
        if r.wrapping_mul(2) > div || (r.wrapping_mul(2) == div && q & 1 == 1) {
            q = q.wrapping_add(1);
        }
        q
    };
    // 18-digit zero-padded decimal text. FBSTP order: the
    // lowest-address byte holds the least-significant pair, so the
    // ECX=9..1 scan below runs most-significant-first.
    let mut dig = [0u8; 18];
    {
        let mut t = n;
        for i in (0..18).rev() {
            dig[i] = (t % 10) as u8;
            t /= 10;
        }
    }
    let mut edi = out.wrapping_byte_add(3);
    if count != 0 {
        // 0x408e64: count char + full 18-digit emission.
        core::ptr::write_unaligned(edi, (count as u8).wrapping_add(b'0'));
        edi = emit_from(edi.wrapping_byte_add(1), &dig, 0);
    } else {
        // Leading-nibble skip (0x408e49…): the first nonzero nibble
        // starts emission (hi, then lo); all-zero falls to zero lane.
        let mut j = 0;
        loop {
            if j >= 9 {
                store_zero(out);
                return;
            }
            let hi_n = dig[2 * j];
            let lo_n = dig[2 * j + 1];
            if hi_n != 0 {
                core::ptr::write_unaligned(edi, hi_n.wrapping_add(b'0'));
                edi = edi.wrapping_byte_add(1);
                core::ptr::write_unaligned(edi, lo_n.wrapping_add(b'0'));
                edi = edi.wrapping_byte_add(1);
                j += 1;
                break;
            }
            if lo_n != 0 {
                core::ptr::write_unaligned(edi, lo_n.wrapping_add(b'0'));
                edi = edi.wrapping_byte_add(1);
                j += 1;
                break;
            }
            j += 1;
        }
        edi = emit_from(edi, &dig, j);
    }
    // 0x408e84: EAX=EDI(end); ECX=EBX+scale+3; len = EAX-ECX (short).
    let trunc = out.wrapping_byte_add(3).wrapping_byte_add(scale as usize);
    let len = (edi as usize).wrapping_sub(trunc as usize) as u16;
    // NUL + trailing-zero strip (0x408e8c…).
    core::ptr::write_unaligned(edi, 0u8);
    loop {
        edi = edi.wrapping_byte_sub(1);
        if core::ptr::read_unaligned(edi as *const u8) != b'0' {
            break;
        }
        core::ptr::write_unaligned(edi, 0u8);
    }
    // 0x408e95: sign = original [ESI+4] >> 31; tail stores.
    core::ptr::write_unaligned(out as *mut u16, len);
    core::ptr::write_unaligned(out.wrapping_byte_add(2), (orig_hi >> 31) as u8);
}

#[cfg(test)]
mod tests {
    use super::{TABLE_00408DC3, fn_00408dd7};

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

    #[test]
    fn int_lanes() {
        // Table pins the observed image bytes.
        assert_eq!(
            unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(TABLE_00408DC3)) },
            [0xEEEB_D231, 10, 100, 1000, 10000]
        );

        // Zero lane → {0, 0, ""}.
        let mut out = [0xAAu8; 32];
        let mut zero = [0u8; 8];
        unsafe { fn_00408dd7(out.as_mut_ptr(), zero.as_mut_ptr(), 4) };
        assert_eq!(unsafe { word_at(out.as_mut_ptr(), 0) }, 0);
        assert_eq!(unsafe { byte_at(out.as_mut_ptr(), 2) }, 0);
        assert!(unsafe { digits_eq(out.as_mut_ptr(), b"") });

        // Small value, scale 4 (no FIDIV): "1", len = 1-4 = -3.
        let mut out = [0xAAu8; 32];
        let mut one = 1u64.to_le_bytes();
        unsafe { fn_00408dd7(out.as_mut_ptr(), one.as_mut_ptr(), 4) };
        assert_eq!(unsafe { word_at(out.as_mut_ptr(), 0) }, 0xFFFD);
        assert_eq!(unsafe { byte_at(out.as_mut_ptr(), 2) }, 0);
        assert!(unsafe { digits_eq(out.as_mut_ptr(), b"1") });

        // 10^18 chunk lane: count 1 + zero remainder, len = 19-4.
        let mut out = [0xAAu8; 32];
        let mut big = 1_000_000_000_000_000_000u64.to_le_bytes();
        unsafe { fn_00408dd7(out.as_mut_ptr(), big.as_mut_ptr(), 4) };
        assert_eq!(unsafe { word_at(out.as_mut_ptr(), 0) }, 15);
        assert_eq!(unsafe { byte_at(out.as_mut_ptr(), 2) }, 0);
        assert!(unsafe { digits_eq(out.as_mut_ptr(), b"1") });

        // Negative input: negate + sign 1.
        let mut out = [0xAAu8; 32];
        let mut neg = (-5i64).to_le_bytes();
        unsafe { fn_00408dd7(out.as_mut_ptr(), neg.as_mut_ptr(), 4) };
        assert_eq!(unsafe { word_at(out.as_mut_ptr(), 0) }, 0xFFFD);
        assert_eq!(unsafe { byte_at(out.as_mut_ptr(), 2) }, 1);
        assert!(unsafe { digits_eq(out.as_mut_ptr(), b"5") });

        // Divide lane: 15000/10000 = 1.5 → 2 (ties-even), len 1.
        let mut out = [0xAAu8; 32];
        let mut v = 15000u64.to_le_bytes();
        unsafe { fn_00408dd7(out.as_mut_ptr(), v.as_mut_ptr(), 0) };
        assert_eq!(unsafe { word_at(out.as_mut_ptr(), 0) }, 1);
        assert_eq!(unsafe { byte_at(out.as_mut_ptr(), 2) }, 0);
        assert!(unsafe { digits_eq(out.as_mut_ptr(), b"2") });
    }
}
