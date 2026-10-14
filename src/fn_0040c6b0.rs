//! Original procedure `0x0040c6b0` (49 bytes, `0x0040c6b0–0x0040c6e0`).
//! Evidence: `evidence/0040c6b0_fn_0040c6b0.md`.

/// `void` / no args per Ghidra `__register` observation; writes 256-entry
/// `u32` table at `0x00417d9c` shared with `fn_0040c6e4`.
pub unsafe fn fn_0040c6b0() {
    // ponytail: writes through existing TABLE_00417d9c static, upgrade to real
    // image-relative import once data layout proven.
    let mut i: u32 = 0;
    loop {
        let mut crc: u32 = i;
        let mut bits: i32 = 8;
        loop {
            if crc & 1 == 0 {
                crc >>= 1;
            } else {
                crc = (crc >> 1) ^ 0xedb88320;
            }
            bits = bits.wrapping_sub(1);
            if bits == 0 {
                break;
            }
        }
        crate::fn_0040c6e4::TABLE_00417d9c[i as usize] = crc;
        i = i.wrapping_add(1);
        if i == 0x100 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fn_0040c6b0;

    #[test]
    fn builds_ieee_crc32_table() {
        let _guard = crate::fn_0040c6e4::TEST_LOCK.lock().unwrap();
        unsafe {
            crate::fn_0040c6e4::TABLE_00417d9c = [0xdead_beef; 256];
            fn_0040c6b0();
            let t = crate::fn_0040c6e4::TABLE_00417d9c;
            assert_eq!(t[0], 0x0000_0000);
            assert_eq!(t[1], 0x7707_3096);
            assert_eq!(t[2], 0xee0e_612c);
            assert_eq!(t[255], 0x2d02_ef8d);
        }
    }
}
