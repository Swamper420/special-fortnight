//! Original procedure `0x0040d244` (118 bytes, `0x0040d244–0x0040d2b9`).
//! Evidence: `evidence/0040d244_fn_0040d244.md`.


/// Two-bit prefix + tree dispatch; returns `d11c` value (`+8`/`+0x10` biased).
/// `param_1` EAX / `param_2` EDX / `param_3` ECX per `__register` observation.
pub unsafe fn fn_0040d244(param_1: *mut u16, param_2: *mut u8, param_3: i32) -> i32 {
    if crate::fn_0040d094::fn_0040d094(param_1, param_2) == 0 {
        // ponytail: `SHL EAX,3; ADD EAX,EAX` byte math; `wrapping` matches wrap.
        let t: u32 = (param_3 as u32).wrapping_shl(3);
        let base = (param_1 as usize)
            .wrapping_add(t.wrapping_add(t) as usize)
            .wrapping_add(4);
        crate::fn_0040d11c::fn_0040d11c(base, 3, param_2)
    } else if crate::fn_0040d094::fn_0040d094(param_1.wrapping_byte_add(2), param_2) == 0 {
        let t: u32 = (param_3 as u32).wrapping_shl(3);
        let base = (param_1 as usize)
            .wrapping_add(t.wrapping_add(t) as usize)
            .wrapping_add(0x104);
        crate::fn_0040d11c::fn_0040d11c(base, 3, param_2).wrapping_add(8)
    } else {
        crate::fn_0040d11c::fn_0040d11c((param_1 as usize).wrapping_add(0x204), 8, param_2).wrapping_add(0x10)
    }
}

#[cfg(test)]
mod tests {
    use super::fn_0040d244;

    fn state(range: u32, code: u32) -> [u8; 16] {
        let mut s = [0u8; 16];
        unsafe {
            core::ptr::write_unaligned(s.as_mut_ptr().wrapping_byte_add(8) as *mut u32, range);
            core::ptr::write_unaligned(s.as_mut_ptr().wrapping_byte_add(0xc) as *mut u32, code);
        }
        s
    }

    // Prefix + tree bits driven through the real `fn_0040d094` /
    // `fn_0040d11c`; per-cell probs force each bit with `range` staying
    // `>= 0x1000000` (no renormalize). `param_3 = 1`.
    #[test]
    fn zero_mid_and_far_lanes() {
        // Zero lane: prefix bit 0 (cell+0 @0x400: bound 0x4000000 > code),
        // tree at `+20` count 3 of zero bits → node 8 − 8 = 0.
        let mut probs = [0x400u16; 512];
        probs[11] = 0x800;
        probs[12] = 0x800;
        probs[14] = 0x800;
        let mut st = state(0x8000000, 0x100000);
        let r = unsafe { fn_0040d244(probs.as_mut_ptr(), st.as_mut_ptr(), 1) };
        assert_eq!(r, 0);
        // Mid lane: bits 1 then 0 (cells +0 @0x100, +2 @0x400),
        // tree at `+0x114` count 3 of zeros → 0 + 8.
        let mut probs = [0x400u16; 512];
        probs[0] = 0x100;
        probs[1] = 0x400;
        probs[0x8b] = 0x800;
        probs[0x8c] = 0x800;
        probs[0x8e] = 0x800;
        let mut st = state(0x8000000, 0x4000000);
        let r = unsafe { fn_0040d244(probs.as_mut_ptr(), st.as_mut_ptr(), 1) };
        assert_eq!(r, 8);
        // Far lane: bits 1 then 1, tree at `+0x204` count 8 of zeros →
        // node 256 − 256 = 0, + 0x10.
        let mut probs = [0x400u16; 512];
        probs[0] = 0x100;
        probs[1] = 0x100;
        for node in [1u16, 2, 4, 8, 16, 32, 64, 128] {
            probs[0x102 + node as usize] = 0x800;
        }
        let mut st = state(0x8000000, 0x4000000);
        let r = unsafe { fn_0040d244(probs.as_mut_ptr(), st.as_mut_ptr(), 1) };
        assert_eq!(r, 16);
    }
}
