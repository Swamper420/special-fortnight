//! Original procedure `0x00409a54` (4 bytes, `0x409a54–0x409a57`).
//! Evidence: `evidence/00409a54_fn_00409a54.md`.

/// `*(param_1+0x10) = param_2`. `param_1` arrives in EAX, `param_2` in
/// EDX per Ghidra `__register` observation.
pub unsafe fn fn_00409a54(param_1: *mut u8, param_2: u32) {
    core::ptr::write_unaligned(param_1.wrapping_byte_add(0x10) as *mut u32, param_2);
}

#[cfg(test)]
mod tests {
    use super::fn_00409a54;

    #[test]
    fn store_at_plus_0x10() {
        let mut buf = [0u32; 8];
        unsafe { fn_00409a54(buf.as_mut_ptr() as *mut u8, 0xAABB_CCDD) };
        assert_eq!(buf[4], 0xAABB_CCDD);
        assert!(buf[..4].iter().all(|&w| w == 0));
        assert!(buf[5..].iter().all(|&w| w == 0));
    }
}
