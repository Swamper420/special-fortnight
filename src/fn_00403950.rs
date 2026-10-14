//! Original procedure `0x00403950` (46 bytes, `0x00403950–0x0040397d`).
//! Evidence: `evidence/00403950_fn_00403950.md`.

/// Walk object chain matching `key` (incoming SI) against each
/// object's `{u16 count, u16 keys[N], u32 values[N]}` table at
/// `[obj-0x3c]`; on hit return `values[m]`; else follow the double
/// link at `[obj-0x30]`; null link returns 0.
///
/// ponytail: explicit index `while` mirrors `REPNE SCASW` forward
/// scan (first match wins); `values[m]` equals original
/// `[EDI+EAX*2-4]` address math. Links read pointer-sized, keys
/// `u16`, count/values `u32` per observed widths. Result surfaced
/// as Rust return (original carries it in ESI, EAX garbage).
pub unsafe fn fn_00403950(param_1: *const u8, key: u16) -> u32 {
    let mut obj = param_1;
    loop {
        let table = core::ptr::read_unaligned(
            obj.wrapping_byte_sub(0x3c) as *const *const u16,
        );
        if !table.is_null() {
            let count = core::ptr::read_unaligned(table) as usize;
            let keys = table.wrapping_add(1);
            let mut i = 0;
            while i < count {
                if core::ptr::read_unaligned(keys.wrapping_add(i)) == key {
                    let values =
                        (keys.wrapping_add(count) as *const u32).wrapping_add(i);
                    return core::ptr::read_unaligned(values);
                }
                i += 1;
            }
        }
        let link = core::ptr::read_unaligned(
            obj.wrapping_byte_sub(0x30) as *const *const u8,
        );
        if link.is_null() {
            return 0;
        }
        obj = core::ptr::read_unaligned(link as *const *const u8);
    }
}

#[cfg(test)]
mod tests {
    use super::fn_00403950;

    const OBJ_OFF: usize = 0x3c;
    const OBJ_LEN: usize = 0x40;

    unsafe fn set_table(obj: *mut u8, table: *const u16) {
        core::ptr::write_unaligned(
            obj.wrapping_byte_sub(0x3c) as *mut *const u16,
            table,
        );
    }

    unsafe fn set_link(obj: *mut u8, slot: *const *const u8) {
        core::ptr::write_unaligned(obj.wrapping_byte_sub(0x30) as *mut *const *const u8, slot);
    }

    #[test]
    fn chain_scan_hit_miss_lanes() {
        // Table A: count=2, keys [0x1111, 0x2222], values [0xaaaabbbb, 0xccccdddd].
        let mut a_words = [0u16; 3];
        a_words[0] = 2;
        a_words[1] = 0x1111;
        a_words[2] = 0x2222;
        let a_vals = [0xaaaabbbu32, 0xccccddddu32];
        let mut a_blob = [0u8; 3 * 2 + 2 * 4];
        unsafe {
            core::ptr::copy_nonoverlapping(
                a_words.as_ptr() as *const u8,
                a_blob.as_mut_ptr(),
                6,
            );
            core::ptr::copy_nonoverlapping(
                a_vals.as_ptr() as *const u8,
                a_blob.as_mut_ptr().add(6),
                8,
            );
        }
        // Table B: count=1, keys [0x3333], values [0x12345678].
        let mut b_blob = [0u8; 2 + 2 + 4];
        unsafe {
            core::ptr::write_unaligned(b_blob.as_mut_ptr() as *mut u16, 1);
            core::ptr::write_unaligned(b_blob.as_mut_ptr().add(2) as *mut u16, 0x3333);
            core::ptr::write_unaligned(b_blob.as_mut_ptr().add(4) as *mut u32, 0x12345678);
        }
        let mut obj_a = [0u8; OBJ_LEN];
        let mut obj_b = [0u8; OBJ_LEN];
        let next_slot: *const u8;
        unsafe {
            let pa = obj_a.as_mut_ptr().add(OBJ_OFF);
            let pb = obj_b.as_mut_ptr().add(OBJ_OFF);
            set_table(pa, a_blob.as_ptr() as *const u16);
            set_table(pb, b_blob.as_ptr() as *const u16);
            next_slot = pb as *const u8;
            set_link(pa, &next_slot as *const *const u8);
            set_link(pb, core::ptr::null());
            // Direct hit in first object (second key).
            assert_eq!(fn_00403950(pa, 0x2222), 0xccccdddd);
            // Miss in A, hit in B via double link.
            assert_eq!(fn_00403950(pa, 0x3333), 0x12345678);
            // Miss everywhere, null link at end.
            assert_eq!(fn_00403950(pa, 0x9999), 0);
            // Null table pointer skips scan, follows link.
            set_table(pa, core::ptr::null());
            assert_eq!(fn_00403950(pa, 0x3333), 0x12345678);
            // Empty-count table scans nothing.
            core::ptr::write_unaligned(b_blob.as_mut_ptr() as *mut u16, 0);
            assert_eq!(fn_00403950(pb, 0x3333), 0);
        }
    }
}
