//! Original procedure `0x00405910` (8 bytes, `0x405910–0x405917`).
//! Evidence: `evidence/00405910_fn_00405910.md`.

/// `if p==0 {0} else {*(p-4)}`. Param arrives in EAX per `__register`
/// observation; 4-byte `MOV`, null-checked. Pointer link read
/// pointer-sized; dword slot stays `u32`.
pub unsafe fn fn_00405910(param_1: *const u8) -> u32 {
    if param_1.is_null() {
        return 0;
    }
    core::ptr::read_unaligned(param_1.wrapping_byte_sub(4) as *const u32)
}

#[cfg(test)]
mod tests {
    use super::fn_00405910;

    #[test]
    fn null_and_word_below_base() {
        let mut buf = [0u8; 8];
        let obj = unsafe { buf.as_ptr().add(4) };
        unsafe {
            core::ptr::write_unaligned(buf.as_mut_ptr() as *mut u32, 0x1122_3344);
            assert_eq!(fn_00405910(obj), 0x1122_3344);
            core::ptr::write_unaligned(buf.as_mut_ptr() as *mut u32, 0x5566_7788);
            assert_eq!(fn_00405910(obj), 0x5566_7788);
            assert_eq!(fn_00405910(core::ptr::null()), 0);
        }
    }
}
