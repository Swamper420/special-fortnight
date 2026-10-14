//! Original procedure `0x00408218` (18 bytes, `0x408218–0x408229`).
//! Evidence: `evidence/00408218_fn_00408218.md`.

use crate::fn_00404e14::fn_00404e14;

/// Swap-forward wrapper: `404e14(param_2, param_1)` (EAX↔EDX swap).
/// `param_1` arrives in EAX, `param_2` in EDX per Ghidra `__register`
/// observation; return is void.
///
/// ponytail: direct call to done `fn_00404e14` (no hook); no
/// new hook — single thin wrapper.
pub unsafe fn fn_00408218(param_1: *mut u16, param_2: *mut u8) {
    fn_00404e14(param_2, param_1);
}

#[cfg(test)]
mod tests {
    use super::fn_00408218;
    use crate::fn_00404dd4::{HOOK_00402fbc, HOOK_004054b4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL_A: AtomicUsize = AtomicUsize::new(0);
    static FILL_B: AtomicUsize = AtomicUsize::new(0);
    static FILL_C: AtomicUsize = AtomicUsize::new(0);

    const CANNED: u32 = 0x1122_3344;

    unsafe extern "C" fn alloc(n: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        CANNED
    }

    unsafe extern "C" fn fill(a: *mut u8, b: u32, c: u32) {
        FILL_HITS.fetch_add(1, Ordering::SeqCst);
        FILL_A.store(a as usize, Ordering::SeqCst);
        FILL_B.store(b as usize, Ordering::SeqCst);
        FILL_C.store(c as usize, Ordering::SeqCst);
    }

    #[test]
    fn swap_forward_lanes() {
        // Chain reaches done fn_00404dd4/fn_004046c4, which read
        // hook globals: hold the common owner lock while writing
        // fn_00404dd4-owned hooks (that module declares no TEST_LOCK).
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_004054b4 = alloc;
            HOOK_00402fbc = fill;
        }

        // Arena mirroring fn_004046c4's own test: obj = base+12,
        // count cell = base+4 (`obj-8`); slot cell holds obj.
        let mut arena = [0u32; 4];
        unsafe { *arena.as_mut_ptr().wrapping_add(1) = 1 };
        let base = arena.as_mut_ptr() as *mut u8;
        let obj = unsafe { base.wrapping_byte_add(12) };
        let mut slot: *mut u8 = obj;
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;

        // Null string lane: len=0, result still stored.
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00408218(core::ptr::null_mut(), slot_ptr) };
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 0);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { core::ptr::read_unaligned(slot_ptr as *const u32) }, CANNED);

        // Wide-string lane: `"AB"` → len 2, fill(str, canned, 4).
        let s = [0x41u16, 0x42, 0];
        unsafe { *arena.as_mut_ptr().wrapping_add(1) = 1 };
        slot = obj;
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00408218(s.as_ptr() as *mut u16, slot_ptr) };
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 2);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FILL_A.load(Ordering::SeqCst), s.as_ptr() as usize);
        assert_eq!(FILL_B.load(Ordering::SeqCst), CANNED as usize);
        assert_eq!(FILL_C.load(Ordering::SeqCst), 4);
        assert_eq!(unsafe { core::ptr::read_unaligned(slot_ptr as *const u32) }, CANNED);
    }
}
