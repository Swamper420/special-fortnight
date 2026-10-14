//! Original procedure `0x0040385c` (6 bytes, `0x40385c–0x403861`).
//! Evidence: `evidence/0040385c_fn_0040385c.md`.

/// `*(obj-0x34)`. Param arrives in EAX per `__register` observation;
/// 4-byte `MOV`, no null check.
pub unsafe fn fn_0040385c(obj: *const u8) -> u32 {
    core::ptr::read_unaligned(obj.wrapping_byte_sub(0x34) as *const u32)
}

#[cfg(test)]
mod tests {
    use super::fn_0040385c;

    #[test]
    fn reads_word_below_base() {
        let mut buf = [0u8; 0x40];
        let obj = unsafe { buf.as_ptr().add(0x34) };
        unsafe {
            core::ptr::write_unaligned(
                buf.as_mut_ptr() as *mut u32,
                0x1122_3344,
            );
            // Neighbour word stays independent.
            core::ptr::write_unaligned(
                buf.as_mut_ptr().add(4) as *mut u32,
                0x99aa_bbcc,
            );
        }
        assert_eq!(unsafe { fn_0040385c(obj) }, 0x1122_3344);
        // Overwrite lane: plain load, not accumulate.
        unsafe {
            core::ptr::write_unaligned(buf.as_mut_ptr() as *mut u32, 0);
        }
        assert_eq!(unsafe { fn_0040385c(obj) }, 0);
        assert_eq!(
            unsafe { core::ptr::read_unaligned(buf.as_ptr().add(4) as *const u32) },
            0x99aa_bbcc
        );
    }
}
