//! Original procedure `0x00402efc` (12 bytes, `0x402efc–0x402f07`).
//! Evidence: `evidence/00402efc_fn_00402efc.md`.

unsafe extern "C" fn default_ctx() -> *const u8 {
    core::ptr::null()
}

/// Target `0x406588` (`FUN_00406588`), context getter, no args.
///
/// ponytail: hook standing in for reconstructed `fn_00406588`, rewire to
/// real call once cross-module test serialization exists.
pub static mut HOOK_00406588: unsafe extern "C" fn() -> *const u8 = default_ctx;

/// `*ctx()`. No params; returns head dword of context block.
/// Deref is a 4-byte `MOV`, no null check.
pub unsafe fn fn_00402efc() -> u32 {
    let ctx = HOOK_00406588();
    core::ptr::read_unaligned(ctx as *const u32)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406588, fn_00402efc};

    /// Test-only serialization for tests sharing HOOK global.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static mut WORDS: [u32; 2] = [0; 2];

    unsafe extern "C" fn ctx() -> *const u8 {
        core::ptr::addr_of!(WORDS) as *const u8
    }

    #[test]
    fn deref_hits_ctx_head() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_00406588 = ctx;
            WORDS = [0x11223344, 0x55667788];
        }
        assert_eq!(unsafe { fn_00402efc() }, 0x11223344);
        // Head lane independent of +4 word; overwrite lane.
        unsafe { WORDS = [0, 0x99] };
        assert_eq!(unsafe { fn_00402efc() }, 0);
        assert_eq!(unsafe { WORDS[1] }, 0x99);
        unsafe { WORDS = [0; 2] };
    }
}
