//! Original procedure `0x00409c60` (13 bytes, `0x00409c60–0x00409c6c`).
//! Evidence: `evidence/00409c60_fn_00409c60.md`.

/// Tail target `0x00403f88` (`FUN_00403f88`), reached by `JMP` with
/// `param_1` still in EAX: direct intra-reconstruction call (rewired;
/// signatures verified `fn(u32)`).

/// `*param_3 = param_2; tail(param_1)`. `param_1` EAX / `param_2` EDX /
/// `param_3` ECX per Ghidra `__register` observation. `MOV ESP,ECX`
/// is the store-address setup; `MOV EBP,[EBP]` frame restore has no
/// host equivalent.
pub unsafe fn fn_00409c60(param_1: u32, param_2: u32, param_3: *mut u32) {
    core::ptr::write_unaligned(param_3, param_2);
    crate::fn_00403f88::fn_00403f88(param_1);
}

#[cfg(test)]
mod tests {
    use super::fn_00409c60;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn tail() {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn store_then_tail() {
        // Real `fn_00403f88` with no raise hook: skips alloc/raise,
        // fires the tail. Owner lock matches its other callers.
        let _common = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let (old_raise, old_tail);
        unsafe {
            old_raise = crate::fn_00403f88::HOOK_0041301C;
            old_tail = crate::fn_00403f88::TAIL_00413014;
            crate::fn_00403f88::HOOK_0041301C = None;
            crate::fn_00403f88::TAIL_00413014 = tail;
        }
        let mut cell: u32 = 0;
        TAIL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00409c60(0x5A, 0xDEAD_BEEF, &mut cell as *mut u32) };
        assert_eq!(cell, 0xDEAD_BEEF);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        unsafe {
            crate::fn_00403f88::HOOK_0041301C = old_raise;
            crate::fn_00403f88::TAIL_00413014 = old_tail;
        }
    }
}
