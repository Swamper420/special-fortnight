//! Original procedure `0x00402f9c` (29 bytes, `0x00402f9c–0x00402fb8`).
//! Evidence: `evidence/00402f9c_fn_00402f9c.md`.

unsafe extern "C" fn default_ctx() -> *const u8 {
    core::ptr::null()
}

/// Target `0x00406588` (`FUN_00406588`), context getter, no args.
///
/// ponytail: hook standing in for reconstructed `fn_00406588`, rewire to
/// real call once cross-module test serialization exists.
pub static mut HOOK_00406588: unsafe extern "C" fn() -> *const u8 = default_ctx;

/// `v = *(ctx()+4); *(ctx()+4) = 0; v`. Two calls kept distinct:
/// read hits first return, clear hits second. `PUSH/POP EBX` and
/// `XOR EDX,EDX` have no Rust equivalent. No null check.
pub unsafe fn fn_00402f9c() -> u32 {
    let first = HOOK_00406588();
    let v = core::ptr::read_unaligned(first.wrapping_add(4) as *const u32);
    let second = HOOK_00406588();
    core::ptr::write_unaligned(second.wrapping_add(4) as *mut u32, 0);
    v
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406588, fn_00402f9c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test-only serialization for tests sharing HOOK global.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static mut WORDS: [u32; 2] = [0; 2];
    static mut WORDS_B: [u32; 2] = [0; 2];
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static SPLIT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn ctx() -> *const u8 {
        CALLS.fetch_add(1, Ordering::SeqCst);
        if SPLIT.load(Ordering::SeqCst) == 0 {
            core::ptr::addr_of!(WORDS) as *const u8
        } else if CALLS.load(Ordering::SeqCst) % 2 == 1 {
            core::ptr::addr_of!(WORDS) as *const u8
        } else {
            core::ptr::addr_of!(WORDS_B) as *const u8
        }
    }

    #[test]
    fn take_clears_second_return() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_00406588 = ctx;
            WORDS = [0x11223344, 0x67];
            WORDS_B = [0xaaaa, 0xbbbb];
        }
        // Shared-pointer lane: return pre-clear word, clear it, head untouched.
        SPLIT.store(0, Ordering::SeqCst);
        CALLS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00402f9c() }, 0x67);
        assert_eq!(CALLS.load(Ordering::SeqCst), 2);
        assert_eq!(unsafe { WORDS[0] }, 0x11223344);
        assert_eq!(unsafe { WORDS[1] }, 0);
        // Second take returns 0 (already cleared).
        assert_eq!(unsafe { fn_00402f9c() }, 0);
        // Split-pointer lane: clear hits second return only.
        SPLIT.store(1, Ordering::SeqCst);
        CALLS.store(0, Ordering::SeqCst);
        unsafe {
            WORDS = [1, 0x99];
            WORDS_B = [2, 0x88];
        }
        assert_eq!(unsafe { fn_00402f9c() }, 0x99);
        assert_eq!(unsafe { WORDS[1] }, 0x99);
        assert_eq!(unsafe { WORDS_B[1] }, 0);
        unsafe {
            WORDS = [0; 2];
            WORDS_B = [0; 2];
        }
        SPLIT.store(0, Ordering::SeqCst);
    }
}
