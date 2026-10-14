//! Original procedure `0x00408a88` (13 bytes, `0x00408a88–0x00408a94`).
//! Evidence: `evidence/00408a88_fn_00408a88.md`.

/// Sign dash: `if flag != 0 { *dst = 0x2d; dst += 1 word }`,
/// else `dst` untouched. `flag` is the byte at caller frame
/// `[EBP-0x24]`; `dst` is the `EDI` cursor in/out, returned
/// updated. `MOV AX,0x2d` zeroes `AH`, so the stored word is
/// exactly `0x002d`.
pub unsafe fn fn_00408a88(flag: u8, dst: *mut u16) -> *mut u16 {
    if flag == 0 {
        return dst;
    }
    core::ptr::write_unaligned(dst, 0x2du16);
    dst.wrapping_byte_add(2)
}

#[cfg(test)]
mod tests {
    use super::fn_00408a88;

    #[test]
    fn dash_gate_lanes() {
        // No hooks/globals: locals only, no TEST_LOCK.
        let mut buf = [0u16; 4];
        let base = buf.as_mut_ptr();
        // Zero flag: cursor unchanged, memory untouched.
        let ret = unsafe { fn_00408a88(0, base) };
        assert_eq!(ret, base);
        assert_eq!(buf, [0u16; 4]);
        // Nonzero flag: '-' word stored, cursor +1 word.
        let ret = unsafe { fn_00408a88(1, base) };
        assert_eq!(ret, base.wrapping_byte_add(2));
        assert_eq!(buf[0], 0x2d);
        assert_eq!(&buf[1..], &[0u16; 3]);
    }
}
