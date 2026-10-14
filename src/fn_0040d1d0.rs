//! Original procedure `0x0040d1d0` (115 bytes, `0x0040d1d0–0x0040d242`).
//! Evidence: `evidence/0040d1d0_fn_0040d1d0.md`.


/// Context byte-tree decode; mismatch takes plain tail to `>=0x100`.
/// `param_1` EAX / `param_2` EDX / `param_3` CL per `__register` observation.
pub unsafe fn fn_0040d1d0(param_1: usize, param_2: *mut u8, param_3: u8) -> u32 {
    let mut node: u32 = 1;
    let mut cur: u8 = param_3;
    loop {
        // ponytail: `MOVZX/SAR/AND` context bit; equals `cur>>7 & 1`.
        let ctx: u32 = ((cur as u32) >> 7) & 1;
        let addr = param_1
            .wrapping_add((node as usize).wrapping_mul(2))
            .wrapping_add(0x200)
            .wrapping_add(ctx as usize * 0x200);
        cur = cur.wrapping_shl(1);
        let bit = crate::fn_0040d094::fn_0040d094(addr as *mut u16, param_2);
        node = node.wrapping_add(node) | bit;
        if bit != ctx {
            while (node as i32) < 0x100 {
                let cell =
                    (param_1.wrapping_add((node as usize).wrapping_mul(2))) as *mut u16;
                let b = crate::fn_0040d094::fn_0040d094(cell, param_2);
                node = node.wrapping_add(node) | b;
            }
            break;
        }
        if (node as i32) >= 0x100 {
            break;
        }
    }
    node
}

#[cfg(test)]
mod tests {
    use super::fn_0040d1d0;

    fn state(range: u32, code: u32) -> [u8; 16] {
        let mut s = [0u8; 16];
        unsafe {
            core::ptr::write_unaligned(s.as_mut_ptr().wrapping_byte_add(8) as *mut u32, range);
            core::ptr::write_unaligned(s.as_mut_ptr().wrapping_byte_add(0xc) as *mut u32, code);
        }
        s
    }

    #[test]
    fn match_and_mismatch_lanes() {
        // Match lane (`cur=0`, ctx 0): fresh cells at prob 0x800 give a
        // steady `bound = 0x1000000 > code`; node doubles to 0x100.
        // Cells at `base+0x200+node*2` for nodes 1..128.
        let mut probs = [0x800u16; 512];
        let mut st = state(0x1000000, 0x100000);
        let base = probs.as_mut_ptr() as usize;
        assert_eq!(unsafe { fn_0040d1d0(base, st.as_mut_ptr(), 0) }, 0x100);
        // Mismatch lane: ctx cell at prob 0x40 gives 1 (`bound=range/32
        // <= code`), then the plain tail of ones reaches 0x1ff.
        // `range` stays `>= 0x1000000` throughout (no renormalize).
        let mut probs = [0x40u16; 512];
        let mut st = state(0x8000000, 0x4000000);
        let base = probs.as_mut_ptr() as usize;
        assert_eq!(unsafe { fn_0040d1d0(base, st.as_mut_ptr(), 0) }, 0x1ff);
    }
}
