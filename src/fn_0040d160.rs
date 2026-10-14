//! Original procedure `0x0040d160` (68 bytes, `0x0040d160–0x0040d1a3`).
//! Evidence: `evidence/0040d160_fn_0040d160.md`.


/// Bit-plane decode; `out |= bit<<(i&31)` LSB-first.
pub unsafe fn fn_0040d160(param_1: usize, param_2: u32, param_3: *mut u8) -> u32 {
    let mut out: u32 = 0;
    let mut i: u32 = 0;
    let mut node: u32 = 1;
    if param_2 > 0 {
        loop {
            let cell = (param_1.wrapping_add((node as usize).wrapping_mul(2))) as *mut u16;
            let bit = crate::fn_0040d094::fn_0040d094(cell, param_3);
            node = node.wrapping_mul(2).wrapping_add(bit);
            // ponytail: `SHL EAX,CL` low-5-bit shift; mask explicit.
            out |= bit.wrapping_shl(i & 31);
            i = i.wrapping_add(1);
            if i >= param_2 {
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::fn_0040d160;

    // Bits driven through the real `fn_0040d094`; per-level prob cells
    // (nodes 1, 3, 6) force [1,0,1] with no renormalize, as in `d11c`.
    fn state(range: u32, code: u32) -> [u8; 16] {
        let mut s = [0u8; 16];
        unsafe {
            core::ptr::write_unaligned(s.as_mut_ptr().wrapping_byte_add(8) as *mut u32, range);
            core::ptr::write_unaligned(s.as_mut_ptr().wrapping_byte_add(0xc) as *mut u32, code);
        }
        s
    }

    #[test]
    fn plane_and_empty() {
        let mut probs = [0x400u16; 16];
        probs[1] = 0x100;
        probs[3] = 0x400;
        probs[6] = 0x100;
        let mut st = state(0x8000000, 0x4000000);
        let base = probs.as_mut_ptr() as usize;
        assert_eq!(unsafe { fn_0040d160(base, 3, st.as_mut_ptr()) }, 0b101);
        let mut probs = [0x400u16; 16];
        let mut st = state(0x8000000, 0x4000000);
        let base = probs.as_mut_ptr() as usize;
        assert_eq!(unsafe { fn_0040d160(base, 0, st.as_mut_ptr()) }, 0);
    }
}
