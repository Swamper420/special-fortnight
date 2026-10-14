//! Original procedure `0x004046ac` (11 bytes, `0x004046ac–0x004046b6`).
//! Evidence: `evidence/004046ac_fn_004046ac.md`.

/// Target `0x00404580` (`FUN_00404580`), called with no register lane:
/// direct intra-reconstruction call (rewired; signatures verified `fn()`).

/// Cell observed as `dword ptr [0x00412000]`, written from EAX on entry.
///
/// ponytail: absolute-address cell modeled as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut CELL_00412000: u32 = 0;

/// `DAT_00412000 = param_1; FUN_00404580()`.
/// `param_1` arrives in EAX per Ghidra `__register` observation.
pub unsafe fn fn_004046ac(param_1: u32) {
    CELL_00412000 = param_1;
    crate::fn_00404580::fn_00404580();
}

/// Test-only serialization for tests sharing the cell.
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::{CELL_00412000, TEST_LOCK, fn_004046ac};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);

    static mut TAKE_CTX: *const u8 = core::ptr::null();

    /// TLS slot behind the real take chain: null inner → the work
    /// loop breaks immediately.
    unsafe extern "C" fn tls_empty(_index: u32) -> *const u8 {
        core::ptr::addr_of!(TAKE_CTX) as *const u8
    }

    /// Observer on the real `fn_00404580`'s loop `41dc` site (fires
    /// once on the zeroed quick-exit lane).
    unsafe extern "C" fn site41dc(_p: *mut u8) {
        HITS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn store_then_call() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _loop = crate::fn_00404580::TEST_LOCK.lock().unwrap();
        let _take = crate::fn_00402ec8::TEST_LOCK.lock().unwrap();
        let _tls = crate::fn_00406588::TEST_LOCK.lock().unwrap();
        // Zeroed quick-exit lane through the real main loop; empty
        // take queue behind the real work-query chain.
        let (old_c4, old_b18, old_struct, old_s48, old_s2c, old_41dc);
        let (old_flag, old_tls_hook, old_index, old_cb);
        unsafe {
            old_c4 = crate::fn_00404580::CELL_00412004;
            old_b18 = crate::fn_00404580::CELL_00415B18;
            old_struct = crate::fn_00404580::STRUCT_00415AE4;
            old_s48 = crate::fn_00404580::SLOT_00413048;
            old_s2c = crate::fn_00404580::SLOT_0041302C;
            old_41dc = crate::fn_00404580::HOOK_004041DC;
            old_flag = crate::fn_00406588::FLAG_00415b44;
            old_tls_hook = crate::fn_00406588::TLS_GET_VALUE_00406520;
            old_index = crate::fn_00406588::TLS_INDEX_004127ac;
            old_cb = crate::fn_00402ec8::HOOK_00413020;
            crate::fn_00404580::CELL_00412004 = 0;
            crate::fn_00404580::CELL_00415B18 = 0;
            crate::fn_00404580::STRUCT_00415AE4 = [0; 12];
            crate::fn_00404580::SLOT_00413048 = None;
            crate::fn_00404580::SLOT_0041302C = None;
            crate::fn_00404580::HOOK_004041DC = site41dc;
            crate::fn_00406588::FLAG_00415b44 = 1;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = tls_empty;
            crate::fn_00406588::TLS_INDEX_004127ac = 0;
            crate::fn_00402ec8::HOOK_00413020 = None;
            TAKE_CTX = core::ptr::null();
            fn_004046ac(0xAB);
        }
        assert_eq!(unsafe { CELL_00412000 }, 0xAB);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        unsafe {
            crate::fn_00404580::CELL_00412004 = old_c4;
            crate::fn_00404580::CELL_00415B18 = old_b18;
            crate::fn_00404580::STRUCT_00415AE4 = old_struct;
            crate::fn_00404580::SLOT_00413048 = old_s48;
            crate::fn_00404580::SLOT_0041302C = old_s2c;
            crate::fn_00404580::HOOK_004041DC = old_41dc;
            crate::fn_00406588::FLAG_00415b44 = old_flag;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = old_tls_hook;
            crate::fn_00406588::TLS_INDEX_004127ac = old_index;
            crate::fn_00402ec8::HOOK_00413020 = old_cb;
        }
    }
}
