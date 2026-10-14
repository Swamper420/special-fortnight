//! Original procedure `0x0040c738` (24 bytes, `0x0040c738–0x0040c74f`).
//! Evidence: `evidence/0040c738_fn_0040c738.md`.

/// Target `0x0040c6e4`, called with `(0xffffffff, param_1, param_2)`:
/// direct intra-reconstruction call (rewired; signatures verified
/// `fn(u32, *const u8, i32) -> u32`).

/// `FUN_0040c6e4(-1, buf, len) ^ -1`.
/// Register lanes observed: `param_1` in EAX, `param_2` in EDX.
pub unsafe fn fn_0040c738(param_1: *const u8, param_2: i32) -> u32 {
    crate::fn_0040c6e4::fn_0040c6e4(0xffffffff, param_1, param_2) ^ 0xffffffff
}

#[cfg(test)]
mod tests {
    use super::fn_0040c738;

    #[test]
    fn seeds_neg_one_and_inverts() {
        // Real `fn_0040c6e4` under its own TEST_LOCK (shared table);
        // rebuild the table, skip the builder via the flag.
        let _guard = crate::fn_0040c6e4::TEST_LOCK.lock().unwrap();
        let (old_cell, old_table);
        unsafe {
            old_cell = crate::fn_0040c6e4::CELL_00417d98;
            old_table = crate::fn_0040c6e4::TABLE_00417d9c;
            crate::fn_0040c6b0::fn_0040c6b0();
            crate::fn_0040c6e4::CELL_00417d98 = 1;
        }
        let data = *b"abcd";
        // Register without final-xor is 0x127d32ee; host inverts
        // to the standard CRC32 0xed82cd11.
        assert_eq!(unsafe { fn_0040c738(data.as_ptr(), 4) }, 0xed82_cd11);
        unsafe {
            crate::fn_0040c6e4::CELL_00417d98 = old_cell;
            crate::fn_0040c6e4::TABLE_00417d9c = old_table;
        }
    }
}
