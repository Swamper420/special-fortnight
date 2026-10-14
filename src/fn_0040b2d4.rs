//! Original procedure `0x0040b2d4` (10 bytes, `0x40b2d4–0x40b2dd`).
//! Evidence: `evidence/0040b2d4_fn_0040b2d4.md`.

/// Adds `param_2` into u64 slot at `param_1`; returns true if no 64-bit
/// overflow. Register lanes observed: `param_1` in EAX, `param_2` in EDX,
/// return in AL.
pub unsafe fn fn_0040b2d4(param_1: *mut u32, param_2: u32) -> bool {
    let lo = core::ptr::read_unaligned(param_1);
    let (new_lo, c0) = lo.overflowing_add(param_2);
    core::ptr::write_unaligned(param_1, new_lo);
    let hi_ptr = param_1.wrapping_add(1);
    let hi = core::ptr::read_unaligned(hi_ptr);
    let (new_hi, c1) = hi.overflowing_add(c0 as u32);
    core::ptr::write_unaligned(hi_ptr, new_hi);
    !c1
}

#[cfg(test)]
mod tests {
    use super::fn_0040b2d4;

    #[test]
    fn adds_u32_into_u64_with_inverted_carry() {
        unsafe {
            let mut slot: [u32; 2] = [0x0000_0005, 0x0000_0000];
            assert!(fn_0040b2d4(slot.as_mut_ptr(), 3));
            assert_eq!(slot, [8, 0]);
            slot = [0xffff_ffff, 0x0000_0002];
            assert!(fn_0040b2d4(slot.as_mut_ptr(), 1));
            assert_eq!(slot, [0, 3]);
            slot = [0xffff_ffff, 0xffff_ffff];
            assert!(!fn_0040b2d4(slot.as_mut_ptr(), 1));
            assert_eq!(slot, [0, 0]);
            slot = [0x1234_5678, 0x9abc_def0];
            assert!(fn_0040b2d4(slot.as_mut_ptr(), 0));
            assert_eq!(slot, [0x1234_5678, 0x9abc_def0]);
        }
    }
}
