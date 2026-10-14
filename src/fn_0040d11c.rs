//! Original procedure `0x0040d11c` (67 bytes, `0x0040d11c–0x0040d15e`).
//! Evidence: `evidence/0040d11c_fn_0040d11c.md`.


/// Tree decode `param_2` bits; returns `node - (1<<(param_2&31))`.
pub unsafe fn fn_0040d11c(param_1: usize, param_2: u32, param_3: *mut u8) -> i32 {
    let mut node: u32 = 1;
    let mut left: u32 = param_2;
    if left != 0 {
        loop {
            // ponytail: `LEA EAX,[EDI+EBX*2]` byte math; `wrapping` here.
            let cell = (param_1.wrapping_add((node as usize).wrapping_mul(2))) as *mut u16;
            let bit = crate::fn_0040d094::fn_0040d094(cell, param_3);
            node = bit.wrapping_add(node.wrapping_add(node));
            left = left.wrapping_sub(1);
            if left == 0 {
                break;
            }
        }
    }
    // ponytail: `SHL EAX,CL` uses low 5 bits; mask explicit.
    let sub: u32 = 1u32.wrapping_shl(param_2 & 31);
    (node.wrapping_sub(sub)) as i32
}

#[cfg(test)]
mod tests {
    use super::fn_0040d11c;

    // Bits driven through the real `fn_0040d094` (bit = `code >= bound`,
    // `bound = (range>>11)*prob`); per-level prob cells force the pattern
    // with no renormalize (`range` stays `>= 0x1000000` throughout).
    // Cells at `base+node*2`: nodes 1, 3, 6 → byte offsets 2, 6, 12.
    fn probs_for(bits: [u16; 3]) -> [u16; 16] {
        let mut p = [0x400u16; 16];
        p[1] = bits[0];
        p[3] = bits[1];
        p[6] = bits[2];
        p
    }
    fn state(range: u32, code: u32) -> [u8; 16] {
        let mut s = [0u8; 16];
        unsafe {
            core::ptr::write_unaligned(s.as_mut_ptr().wrapping_byte_add(8) as *mut u32, range);
            core::ptr::write_unaligned(s.as_mut_ptr().wrapping_byte_add(0xc) as *mut u32, code);
        }
        s
    }

    #[test]
    fn tree_walk_and_empty() {
        // range 0x8000000, code 0x4000000; forced pattern [1,0,1]:
        // L1: bound=(0x8000000>>11)*0x100=0x1000000 <= code → 1,
        //   range→0x7000000, code→0x3000000.
        // L2: bound=(0x7000000>>11)*0x400=0x3800000 > code → 0,
        //   range→0x3800000.
        // L3: bound=(0x3800000>>11)*0x100=0x380000 <= code 0x3000000 → 1.
        // node: 1→3→6→13; minus (1<<3)=8 → 5.
        let mut probs = probs_for([0x100, 0x400, 0x100]);
        let mut st = state(0x8000000, 0x4000000);
        let base = probs.as_mut_ptr() as usize;
        assert_eq!(unsafe { fn_0040d11c(base, 3, st.as_mut_ptr()) }, 5);
        // Zero count: 1-(1<<0)=0, no calls.
        let mut probs = probs_for([0x100, 0x400, 0x100]);
        let mut st = state(0x8000000, 0x4000000);
        let base = probs.as_mut_ptr() as usize;
        assert_eq!(unsafe { fn_0040d11c(base, 0, st.as_mut_ptr()) }, 0);
    }
}
