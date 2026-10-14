//! Original procedure `0x00402efc` (12 bytes, `0x00402efc–0x00402f07`).
//! Evidence: `evidence/00402efc_fn_00402efc.md`.

/// Target `0x00406588` (`FUN_00406588`), context getter, no args:
/// direct intra-reconstruction call (rewired; signatures verified
/// `fn() -> *const u8`).

/// `*ctx()`. No params; returns head dword of context block.
/// Deref is a 4-byte `MOV`, no null check.
pub unsafe fn fn_00402efc() -> u32 {
    let ctx = crate::fn_00406588::fn_00406588();
    core::ptr::read_unaligned(ctx as *const u32)
}

#[cfg(test)]
mod tests {
    use super::fn_00402efc;

    /// Test-only serialization for this module's locals.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static mut WORDS: [u32; 2] = [0; 2];

    /// Stands in for the OS import behind real `fn_00406588`.
    unsafe extern "C" fn tls_value(_index: u32) -> *const u8 {
        core::ptr::addr_of!(WORDS) as *const u8
    }

    #[test]
    fn deref_hits_ctx_head() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _tls = crate::fn_00406588::TEST_LOCK.lock().unwrap();
        let (old_flag, old_hook, old_index);
        unsafe {
            old_flag = crate::fn_00406588::FLAG_00415b44;
            old_hook = crate::fn_00406588::TLS_GET_VALUE_00406520;
            old_index = crate::fn_00406588::TLS_INDEX_004127ac;
            crate::fn_00406588::FLAG_00415b44 = 1;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = tls_value;
            crate::fn_00406588::TLS_INDEX_004127ac = 0;
            WORDS = [0x11223344, 0x55667788];
        }
        assert_eq!(unsafe { fn_00402efc() }, 0x11223344);
        // Head lane independent of +4 word; overwrite lane.
        unsafe { WORDS = [0, 0x99] };
        assert_eq!(unsafe { fn_00402efc() }, 0);
        assert_eq!(unsafe { WORDS[1] }, 0x99);
        unsafe {
            WORDS = [0; 2];
            crate::fn_00406588::FLAG_00415b44 = old_flag;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = old_hook;
            crate::fn_00406588::TLS_INDEX_004127ac = old_index;
        }
    }
}
