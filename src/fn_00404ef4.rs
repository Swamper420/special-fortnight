//! Original procedure `0x00404ef4` (10 bytes, `0x00404ef4–0x00404efd`).
//! Evidence: `evidence/00404ef4_fn_00404ef4.md`.

/// Null-checked dword-at-`p-4`: `if p==0 {0} else {*(p-4)}`. Param arrives
/// in EAX per `__register` observation; 4-byte `MOV`, null-tested via
/// `TEST EAX,EAX` + `JZ` (EAX untouched on null path). Shape reuses proven
/// sibling `crate::fn_00405910::fn_00405910`; dword slot stays `u32`.
pub unsafe fn fn_00404ef4(param_1: *const u8) -> u32 {
    if param_1.is_null() {
        return 0;
    }
    core::ptr::read_unaligned(param_1.wrapping_byte_sub(4) as *const u32)
}

#[cfg(test)]
mod tests {
    use super::fn_00404ef4;

    #[test]
    fn null_and_word_below_base() {
        let mut buf = [0u8; 8];
        let obj = unsafe { buf.as_ptr().add(4) };
        unsafe {
            core::ptr::write_unaligned(buf.as_mut_ptr() as *mut u32, 0x1122_3344);
            assert_eq!(fn_00404ef4(obj), 0x1122_3344);
            core::ptr::write_unaligned(buf.as_mut_ptr() as *mut u32, 0);
            assert_eq!(fn_00404ef4(obj), 0);
            assert_eq!(fn_00404ef4(core::ptr::null()), 0);
        }
    }
}
