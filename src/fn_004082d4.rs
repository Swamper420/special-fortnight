//! Original procedure `0x004082d4` (19 bytes, `0x004082d4–0x004082e6`).
//! Evidence: `evidence/004082d4_fn_004082d4.md`.

/// Arg-rotation wrapper: `fn_004082e8(p4, p1, p2, p3)`. `PUSH ECX`
/// spill and `RET 0x4` (one stack arg) have no host-visible effect.
/// `p4` is consumed downstream as the slot address.
pub unsafe fn fn_004082d4(param_1: *mut u16, param_2: u32, param_3: u32, param_4: *mut u8) {
    crate::fn_004082e8::fn_004082e8(param_4, param_1, param_2, param_3);
}

#[cfg(test)]
mod tests {
    use super::fn_004082d4;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SCAN_HITS: AtomicUsize = AtomicUsize::new(0);
    static SCAN_ARG: AtomicUsize = AtomicUsize::new(0);
    static SCAN_RET: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);

    const CANNED: u32 = 0x1122_3344;

    /// Exit block behind the real scanner (null-format lane fires it
    /// once with 0; the canned word steers the small lane).
    unsafe extern "C" fn scan_tail(n: u32) -> u32 {
        SCAN_HITS.fetch_add(1, Ordering::SeqCst);
        SCAN_ARG.store(n as usize, Ordering::SeqCst);
        SCAN_RET.load(Ordering::SeqCst) as u32
    }

    /// Char lane behind the real scanner (unreached, format is null).
    unsafe extern "C" fn scan_char(_a: u32, _b: usize, _c: *mut u16) {}

    unsafe extern "C" fn norm_callee(_a: *mut u32, _b: *mut u8) {}

    unsafe extern "C" fn alloc(_n: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        CANNED
    }

    unsafe extern "C" fn fill(_a: *mut u8, _b: u32, _c: u32) {
        FILL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn shuffle_lands_in_sibling() {
        // The wrapper owns no globals; the sibling chain's foreign
        // hooks do: hold the common lock first, then the sibling
        // format lock, then the real scanner lock. Save/restore after.
        let _common = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let _f74 = crate::fn_00408274::TEST_LOCK.lock().unwrap();
        let _scan = crate::fn_00408540::TEST_LOCK.lock().unwrap();
        let s_char = unsafe { crate::fn_00408540::HOOK_0040867D };
        let s_tail = unsafe { crate::fn_00408540::HOOK_00408914 };
        let s4820 = unsafe { crate::fn_00404820::CALLEE_00404E6C };
        let sdd_a = unsafe { crate::fn_00404dd4::HOOK_004054b4 };
        let sdd_f = unsafe { crate::fn_00404dd4::HOOK_00402fbc };
        unsafe {
            crate::fn_00408540::HOOK_0040867D = scan_char;
            crate::fn_00408540::HOOK_00408914 = scan_tail;
            crate::fn_00404820::CALLEE_00404E6C = norm_callee;
            crate::fn_00404dd4::HOOK_004054b4 = alloc;
            crate::fn_00404dd4::HOOK_00402fbc = fill;
        }
        // Null-object small lane: the real scanner sees an empty
        // format (cursor == end), exits with 0; the canned word
        // steers the small lane as the stub's 5 did.
        SCAN_RET.store(5, Ordering::SeqCst);
        let mut slot: *mut u8 = core::ptr::null_mut();
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;
        SCAN_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_004082d4(core::ptr::null_mut(), 0x2222_2222, 0x3333_3333, slot_ptr) };
        assert_eq!(SCAN_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(SCAN_ARG.load(Ordering::SeqCst), 0);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(slot, CANNED as usize as *mut u8);
        unsafe {
            crate::fn_00408540::HOOK_0040867D = s_char;
            crate::fn_00408540::HOOK_00408914 = s_tail;
            crate::fn_00404820::CALLEE_00404E6C = s4820;
            crate::fn_00404dd4::HOOK_004054b4 = sdd_a;
            crate::fn_00404dd4::HOOK_00402fbc = sdd_f;
        }
    }
}
