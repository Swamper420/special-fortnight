//! Original procedure `0x00402f9c` (29 bytes, `0x00402f9c–0x00402fb8`).
//! Evidence: `evidence/00402f9c_fn_00402f9c.md`.

/// Target `0x00406588` (`FUN_00406588`), context getter, no args:
/// direct intra-reconstruction call (rewired; signatures verified
/// `fn() -> *const u8`).

/// `v = *(ctx()+4); *(ctx()+4) = 0; v`. Two calls kept distinct:
/// read hits first return, clear hits second. `PUSH/POP EBX` and
/// `XOR EDX,EDX` have no Rust equivalent. No null check.
pub unsafe fn fn_00402f9c() -> u32 {
    let first = crate::fn_00406588::fn_00406588();
    let v = core::ptr::read_unaligned(first.wrapping_add(4) as *const u32);
    let second = crate::fn_00406588::fn_00406588();
    core::ptr::write_unaligned(second.wrapping_add(4) as *mut u32, 0);
    v
}

#[cfg(test)]
mod tests {
    use super::fn_00402f9c;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test-only serialization for this module's locals.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static mut WORDS: [u32; 2] = [0; 2];
    static mut WORDS_B: [u32; 2] = [0; 2];
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static SPLIT: AtomicUsize = AtomicUsize::new(0);

    /// Stands in for the OS import behind real `fn_00406588`;
    /// per-call values model re-query.
    unsafe extern "C" fn tls_value(_index: u32) -> *const u8 {
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
        let _tls = crate::fn_00406588::TEST_LOCK.lock().unwrap();
        let (old_flag, old_hook, old_index);
        unsafe {
            old_flag = crate::fn_00406588::FLAG_00415b44;
            old_hook = crate::fn_00406588::TLS_GET_VALUE_00406520;
            old_index = crate::fn_00406588::TLS_INDEX_004127ac;
            crate::fn_00406588::FLAG_00415b44 = 1;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = tls_value;
            crate::fn_00406588::TLS_INDEX_004127ac = 0;
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
            crate::fn_00406588::FLAG_00415b44 = old_flag;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = old_hook;
            crate::fn_00406588::TLS_INDEX_004127ac = old_index;
        }
        SPLIT.store(0, Ordering::SeqCst);
    }
}
