//! Original procedure `0x0040da28` (14 bytes, `0x0040da28–0x0040da35`).
//! Evidence: `evidence/0040da28_fn_0040da28.md`.

/// Triple field store; `param_1` EAX / `param_2` EDX / `param_3` ECX.
pub unsafe fn fn_0040da28(param_1: *mut u8, param_2: u32, param_3: u32) {
    core::ptr::write_unaligned(param_1.wrapping_byte_add(0x10) as *mut u32, param_2);
    core::ptr::write_unaligned(param_1.wrapping_byte_add(0x1c) as *mut u32, param_3);
    core::ptr::write_unaligned(param_1.wrapping_byte_add(0x48) as *mut u32, 0xfffffffe);
}

#[cfg(test)]
mod tests {
    use super::fn_0040da28;

    #[test]
    fn triple_store() {
        let mut s = [0u8; 0x50];
        unsafe { fn_0040da28(s.as_mut_ptr(), 0x11223344, 0x55667788) };
        unsafe {
            assert_eq!(
                core::ptr::read_unaligned(s.as_ptr().wrapping_byte_add(0x10) as *const u32),
                0x11223344
            );
            assert_eq!(
                core::ptr::read_unaligned(s.as_ptr().wrapping_byte_add(0x1c) as *const u32),
                0x55667788
            );
            assert_eq!(
                core::ptr::read_unaligned(s.as_ptr().wrapping_byte_add(0x48) as *const u32),
                0xfffffffe
            );
            assert_eq!(s[0], 0);
        }
    }
}
