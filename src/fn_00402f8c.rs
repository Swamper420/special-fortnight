//! Original procedure `0x00402f8c` (16 bytes, `0x00402f8c–0x00402f9b`).
//! Evidence: `evidence/00402f8c_fn_00402f8c.md`.

/// Target `0x00406588` (`FUN_00406588`), context getter, no args:
/// direct intra-reconstruction call (rewired; signatures verified
/// `fn() -> *const u8`).

/// `*(ctx()+4) = value`. Entry param arrives in `EAX`; stashed in
/// `EBX` across the call (`PUSH EBX / MOV EBX,EAX ... POP EBX` has no
/// Rust equivalent). Store is a 4-byte `MOV`, no null check.
pub unsafe fn fn_00402f8c(value: u32) {
    let ctx = crate::fn_00406588::fn_00406588();
    core::ptr::write_unaligned(ctx.wrapping_add(4) as *mut u32, value);
}

#[cfg(test)]
mod tests {
    use super::fn_00402f8c;

    /// Test-only serialization for this module's locals.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static mut WORDS: [u32; 2] = [0; 2];

    /// Stands in for the OS import behind real `fn_00406588`.
    unsafe extern "C" fn tls_value(_index: u32) -> *const u8 {
        core::ptr::addr_of!(WORDS) as *const u8
    }

    #[test]
    fn store_hits_ctx_plus_4() {
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
            WORDS = [0xaaaa, 0];
        }
        unsafe { fn_00402f8c(0x67) };
        assert_eq!(unsafe { WORDS[0] }, 0xaaaa);
        assert_eq!(unsafe { WORDS[1] }, 0x67);
        // Overwrite lane: setter, not or-accumulate.
        unsafe { fn_00402f8c(0) };
        assert_eq!(unsafe { WORDS[1] }, 0);
        unsafe {
            WORDS = [0; 2];
            crate::fn_00406588::FLAG_00415b44 = old_flag;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = old_hook;
            crate::fn_00406588::TLS_INDEX_004127ac = old_index;
        }
    }
}
