//! Original procedure `0x00402f8c` (16 bytes, `0x00402f8c–0x00402f9b`).
//! Evidence: `evidence/00402f8c_fn_00402f8c.md`.

unsafe extern "C" fn default_ctx() -> *const u8 {
    core::ptr::null()
}

/// Target `0x00406588` (`FUN_00406588`), context getter, no args.
///
/// ponytail: hook standing in for reconstructed `fn_00406588`, rewire to
/// real call once cross-module test serialization exists.
pub static mut HOOK_00406588: unsafe extern "C" fn() -> *const u8 = default_ctx;

/// `*(ctx()+4) = value`. Entry param arrives in `EAX`; stashed in
/// `EBX` across the call (`PUSH EBX / MOV EBX,EAX ... POP EBX` has no
/// Rust equivalent). Store is a 4-byte `MOV`, no null check.
pub unsafe fn fn_00402f8c(value: u32) {
    let ctx = HOOK_00406588();
    core::ptr::write_unaligned(ctx.wrapping_add(4) as *mut u32, value);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406588, fn_00402f8c};

    /// Test-only serialization for tests sharing HOOK global.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static mut WORDS: [u32; 2] = [0; 2];

    unsafe extern "C" fn ctx() -> *const u8 {
        core::ptr::addr_of!(WORDS) as *const u8
    }

    #[test]
    fn store_hits_ctx_plus_4() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_00406588 = ctx;
            WORDS = [0xaaaa, 0];
        }
        unsafe { fn_00402f8c(0x67) };
        assert_eq!(unsafe { WORDS[0] }, 0xaaaa);
        assert_eq!(unsafe { WORDS[1] }, 0x67);
        // Overwrite lane: setter, not or-accumulate.
        unsafe { fn_00402f8c(0) };
        assert_eq!(unsafe { WORDS[1] }, 0);
        unsafe { WORDS = [0; 2] };
    }
}
