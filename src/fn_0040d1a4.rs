//! Original procedure `0x0040d1a4` (42 bytes, `0x0040d1a4–0x0040d1cd`).
//! Evidence: `evidence/0040d1a4_fn_0040d1a4.md`.


/// Byte-tree decode to `node>=0x100` (signed compare).
pub unsafe fn fn_0040d1a4(param_1: usize, param_2: *mut u8) -> u32 {
    let mut node: u32 = 1;
    loop {
        let cell = (param_1.wrapping_add((node as usize).wrapping_mul(2))) as *mut u16;
        let bit = crate::fn_0040d094::fn_0040d094(cell, param_2);
        node = bit | node.wrapping_add(node);
        if (node as i32) >= 0x100 {
            break;
        }
    }
    node
}

#[cfg(test)]
mod tests {
    use super::fn_0040d1a4;

    // Eight 1-bits through the real `fn_0040d094`: every fresh cell at
    // prob 0x20 gives `bound = range/64 <= code` with `range` staying
    // `>= 0x1000000` (no renormalize).
    #[test]
    fn walks_to_byte() {
        let mut probs = [0x20u16; 512];
        let mut st = [0u8; 16];
        unsafe {
            core::ptr::write_unaligned(st.as_mut_ptr().wrapping_byte_add(8) as *mut u32, 0x8000000);
            core::ptr::write_unaligned(st.as_mut_ptr().wrapping_byte_add(0xc) as *mut u32, 0x4000000);
        }
        let base = probs.as_mut_ptr() as usize;
        assert_eq!(unsafe { fn_0040d1a4(base, st.as_mut_ptr()) }, 0x1ff);
    }
}
