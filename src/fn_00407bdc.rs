//! Original procedure `0x00407bdc` (249 bytes, `0x407bdc–0x407cd4`).
//! Evidence: `evidence/00407bdc_fn_00407bdc.md`.

/// Case-insensitive ordinal compare of two header-tagged wide objects.
/// Header (observed): length `u32` at `obj-4`, tag `u16` at `obj-10`;
/// `tag != 2` routes through `fn_00404e6c` into temp slots first.
/// `(param_1, param_2)` arrive in `(EAX, EDX)` per Ghidra `__register`
/// observation. Returns the first nonzero folded `u16` diff, else the
/// length diff (`len1.wrapping_sub(len2)`). Direct calls to done
/// `fn_00404e6c`/`fn_004046e8` (no hooks).
///
/// ponytail: temp slots are a host `[*mut u8; 2]` — stride is
/// pointer-sized on host (4 on target); full fidelity returns with
/// image-relative stack layout.
pub unsafe fn fn_00407bdc(param_1: *mut u8, param_2: *mut u8) -> u32 {
    if param_1.is_null() {
        if param_2.is_null() {
            return 0;
        }
        let len: u32 =
            core::ptr::read_unaligned((param_2 as usize).wrapping_sub(4) as *const u32);
        return len.wrapping_neg();
    }
    if param_2.is_null() {
        return core::ptr::read_unaligned((param_1 as usize).wrapping_sub(4) as *const u32);
    }
    let mut p1 = param_1;
    let mut p2 = param_2;
    let mut tmp: [*mut u8; 2] = [core::ptr::null_mut(), core::ptr::null_mut()];
    if core::ptr::read_unaligned(p1.wrapping_byte_offset(-10) as *const u16) != 2 {
        crate::fn_00404e6c::fn_00404e6c(tmp.as_mut_ptr() as *mut u8, p1);
        p1 = tmp[0];
    }
    if core::ptr::read_unaligned(p2.wrapping_byte_offset(-10) as *const u16) != 2 {
        crate::fn_00404e6c::fn_00404e6c(
            (tmp.as_mut_ptr() as *mut u8)
                .wrapping_byte_add(core::mem::size_of::<*mut u8>()),
            p2,
        );
        p2 = tmp[1];
    }
    let len1: u32 = core::ptr::read_unaligned((p1 as usize).wrapping_sub(4) as *const u32);
    let len2: u32 = core::ptr::read_unaligned((p2 as usize).wrapping_sub(4) as *const u32);
    // SUB/SBB/AND/ADD min: borrow mask keeps len1 iff len1 < len2.
    let lendiff = len1.wrapping_sub(len2);
    let borrow = if len1 < len2 { 0xffff_ffffu32 } else { 0 };
    let n = (borrow & lendiff).wrapping_add(len2);
    let stride = (n as usize).wrapping_mul(2);
    let base1 = (p1 as usize).wrapping_add(stride);
    let base2 = (p2 as usize).wrapping_add(stride);
    let mut result = lendiff;
    if n != 0 {
        // NEG-indexed pair loop: i in {-n, -n+2, ...}, continue while i < 0.
        let mut i: i32 = (n as i32).wrapping_neg();
        loop {
            let off = (i.wrapping_mul(2) as isize) as usize;
            let a: u32 =
                core::ptr::read_unaligned(base1.wrapping_add(off) as *const u32);
            let b: u32 =
                core::ptr::read_unaligned(base2.wrapping_add(off) as *const u32);
            if a != b {
                if (a as u16) != (b as u16) {
                    let mut lo1 = a & 0xffff;
                    let mut lo2 = b & 0xffff;
                    if 0x60 < lo1 && lo1 < 0x7b {
                        lo1 = lo1.wrapping_sub(0x20);
                    }
                    if 0x60 < lo2 && lo2 < 0x7b {
                        lo2 = lo2.wrapping_sub(0x20);
                    }
                    let d = lo1.wrapping_sub(lo2);
                    if d != 0 {
                        result = d;
                        break;
                    }
                    let h1 = a & 0xffff_0000;
                    let h2 = b & 0xffff_0000;
                    if h1 != h2 {
                        let mut hi1 = a.wrapping_shr(0x10);
                        let mut hi2 = b.wrapping_shr(0x10);
                        if 0x60 < hi1 && hi1 < 0x7b {
                            hi1 = hi1.wrapping_sub(0x20);
                        }
                        if 0x60 < hi2 && hi2 < 0x7b {
                            hi2 = hi2.wrapping_sub(0x20);
                        }
                        let d = hi1.wrapping_sub(hi2);
                        if d != 0 {
                            result = d;
                            break;
                        }
                    }
                } else {
                    let mut hi1 = a.wrapping_shr(0x10);
                    let mut hi2 = b.wrapping_shr(0x10);
                    if 0x60 < hi1 && hi1 < 0x7b {
                        hi1 = hi1.wrapping_sub(0x20);
                    }
                    if 0x60 < hi2 && hi2 < 0x7b {
                        hi2 = hi2.wrapping_sub(0x20);
                    }
                    let d = hi1.wrapping_sub(hi2);
                    if d != 0 {
                        result = d;
                        break;
                    }
                }
            }
            i = i.wrapping_add(2);
            if i >= 0 {
                break;
            }
        }
    }
    if (tmp[0] as usize) | (tmp[1] as usize) != 0 {
        crate::fn_004046e8::fn_004046e8(tmp.as_mut_ptr() as *mut u8, 2);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::fn_00407bdc;

    /// Arena: obj = base+12; tag u16 @+2 (`obj-10`), len u32 @+8
    /// (`obj-4`); words follow at obj.
    unsafe fn obj(buf: &mut [u8; 32], tag: u16, words: &[u16]) -> *mut u8 {
        let base = buf.as_mut_ptr();
        core::ptr::write_unaligned(base.wrapping_add(2) as *mut u16, tag);
        core::ptr::write_unaligned(base.wrapping_add(8) as *mut u32, words.len() as u32);
        core::ptr::copy_nonoverlapping(
            words.as_ptr(),
            base.wrapping_add(12) as *mut u16,
            words.len(),
        );
        base.wrapping_add(12)
    }

    #[test]
    fn null_tagged_compare_lanes() {
        let mut abuf = [0u8; 32];
        let mut bbuf = [0u8; 32];
        let mut cbuf = [0u8; 32];
        unsafe {
            // Null lanes.
            assert_eq!(fn_00407bdc(core::ptr::null_mut(), core::ptr::null_mut()), 0);
            let p = obj(&mut abuf, 2, &[0x61, 0x62, 0x63]);
            assert_eq!(fn_00407bdc(core::ptr::null_mut(), p), 0xffff_fffdu32);
            assert_eq!(fn_00407bdc(p, core::ptr::null_mut()), 3);
            // Equal + case-folded equal.
            let q = obj(&mut bbuf, 2, &[0x41, 0x42, 0x43]);
            assert_eq!(fn_00407bdc(p, q), 0);
            // Low-word diff: 'a'-'b'.
            let r = obj(&mut cbuf, 2, &[0x62]);
            let s = obj(&mut abuf, 2, &[0x61]);
            assert_eq!(fn_00407bdc(s, r), 0xffff_ffffu32);
            assert_eq!(fn_00407bdc(r, s), 1);
            // Length-prefix diff: "ab" vs "abc".
            let t = obj(&mut bbuf, 2, &[0x61, 0x62]);
            let u = obj(&mut cbuf, 2, &[0x61, 0x62, 0x63]);
            assert_eq!(fn_00407bdc(t, u), 0xffff_ffffu32);
            // Low words equal, high word diff: "ax" vs "ay".
            let v = obj(&mut abuf, 2, &[0x61, 0x78]);
            let w = obj(&mut bbuf, 2, &[0x61, 0x79]);
            assert_eq!(fn_00407bdc(v, w), 0xffff_ffffu32);
            // Low folded equal, high masked equal: "aX" vs "Ax".
            let x = obj(&mut cbuf, 2, &[0x61, 0x58]);
            let y = obj(&mut abuf, 2, &[0x41, 0x58]);
            assert_eq!(fn_00407bdc(x, y), 0);
            // Low folded equal, high differ: "aX" vs "AY".
            let z = obj(&mut bbuf, 2, &[0x41, 0x59]);
            assert_eq!(fn_00407bdc(x, z), 0xffff_ffffu32);
        }
    }
}
