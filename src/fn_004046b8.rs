//! Original procedure `0x004046b8` (11 bytes, `0x004046b8–0x004046c2`).
//! Evidence: `evidence/004046b8_fn_004046b8.md`.

/// Cell observed as `dword ptr [0x00412004]`, written by `POP` of stack-top dword on entry.
///
/// ponytail: absolute-address cell as mutable static, upgrade to real
/// image-relative import once data layout proven. Hermetic own-module copy;
/// unify with `fn_00402f08::CELL_00412004` in `data.rs` once layout proven.
pub static mut CELL_00412004: u32 = 0;

/// Test-only serialization for tests driving the real `fn_004046ac` chain
/// (shares the callee cell and main-loop globals).
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `POP [0x00412004]; JMP 0x004046ac(param_1)`.
/// `param_1` arrives in EAX per Ghidra `__register` observation; `stack_top`
/// is the explicit model of the `POP` source dword (host stack untouched).
///
/// ponytail: extra `stack_top` param names observed stack input; inline-asm
/// `POP` once semantics proven.
///
/// Target `0x004046ac` (`FUN_004046ac`): direct intra-reconstruction
/// call (rewired; signatures verified `fn(u32)`).
pub unsafe fn fn_004046b8(param_1: u32, stack_top: u32) {
    CELL_00412004 = stack_top;
    crate::fn_004046ac::fn_004046ac(param_1);
}

#[cfg(test)]
mod tests {
    use super::{CELL_00412004, TEST_LOCK, fn_004046b8};
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
    fn pop_then_tail_jump() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _callee = crate::fn_004046ac::TEST_LOCK.lock().unwrap();
        let _loop = crate::fn_00404580::TEST_LOCK.lock().unwrap();
        let _take = crate::fn_00402ec8::TEST_LOCK.lock().unwrap();
        let _tls = crate::fn_00406588::TEST_LOCK.lock().unwrap();
        // Zeroed quick-exit lane through the real chain; empty take
        // queue behind the real work-query chain.
        let (old_c4, old_b18, old_struct, old_s48, old_s2c, old_41dc, old_c0);
        let (old_flag, old_tls_hook, old_index, old_cb);
        unsafe {
            old_c4 = crate::fn_00404580::CELL_00412004;
            old_b18 = crate::fn_00404580::CELL_00415B18;
            old_struct = crate::fn_00404580::STRUCT_00415AE4;
            old_s48 = crate::fn_00404580::SLOT_00413048;
            old_s2c = crate::fn_00404580::SLOT_0041302C;
            old_41dc = crate::fn_00404580::HOOK_004041DC;
            old_c0 = crate::fn_004046ac::CELL_00412000;
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
            fn_004046b8(0xE2, 0xDEADBEEF);
        }
        assert_eq!(unsafe { CELL_00412004 }, 0xDEADBEEF);
        assert_eq!(unsafe { crate::fn_004046ac::CELL_00412000 }, 0xE2);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        unsafe {
            crate::fn_00404580::CELL_00412004 = old_c4;
            crate::fn_00404580::CELL_00415B18 = old_b18;
            crate::fn_00404580::STRUCT_00415AE4 = old_struct;
            crate::fn_00404580::SLOT_00413048 = old_s48;
            crate::fn_00404580::SLOT_0041302C = old_s2c;
            crate::fn_00404580::HOOK_004041DC = old_41dc;
            crate::fn_004046ac::CELL_00412000 = old_c0;
            crate::fn_00406588::FLAG_00415b44 = old_flag;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = old_tls_hook;
            crate::fn_00406588::TLS_INDEX_004127ac = old_index;
            crate::fn_00402ec8::HOOK_00413020 = old_cb;
        }
    }
}
