//! Original procedure `0x00405918` (7 bytes, `0x405918–0x40591e`).
//! Evidence: `evidence/00405918_fn_00405918.md`.

/// Length-minus-one: `fn_00405910(param_1).wrapping_sub(1)`.
/// Param `*const u8` reuses callee type (EAX in); `DEC EAX` wraps.
pub unsafe fn fn_00405918(param_1: *const u8) -> u32 {
    crate::fn_00405910::fn_00405910(param_1).wrapping_sub(1)
}

#[cfg(test)]
mod tests {
    use super::fn_00405918;

    #[test]
    fn len_minus_one_lanes() {
        let mut buf = [0u8; 8];
        let obj = unsafe { buf.as_ptr().add(4) };
        unsafe {
            core::ptr::write_unaligned(buf.as_mut_ptr() as *mut u32, 5);
            assert_eq!(fn_00405918(obj), 4);
            core::ptr::write_unaligned(buf.as_mut_ptr() as *mut u32, 1);
            assert_eq!(fn_00405918(obj), 0);
            core::ptr::write_unaligned(buf.as_mut_ptr() as *mut u32, 0);
            assert_eq!(fn_00405918(obj), 0xffff_ffff);
            assert_eq!(fn_00405918(core::ptr::null()), 0xffff_ffff);
        }
    }
}
