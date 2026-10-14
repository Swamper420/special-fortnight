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

    static FMT_CALLS: AtomicUsize = AtomicUsize::new(0);
    static FMT_A4: AtomicUsize = AtomicUsize::new(0);
    static FMT_A5: AtomicUsize = AtomicUsize::new(0);
    static FMT_A6: AtomicUsize = AtomicUsize::new(0);
    static FMT_A2: AtomicUsize = AtomicUsize::new(0);
    static FMT_A3: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);

    const CANNED: u32 = 0x1122_3344;

    unsafe extern "C" fn format_hook(
        _p1: *mut u16,
        p2: *mut u16,
        p3: *mut u16,
        p4: u32,
        p5: u32,
        p6: i32,
    ) -> u32 {
        FMT_CALLS.fetch_add(1, Ordering::SeqCst);
        FMT_A2.store(p2 as usize, Ordering::SeqCst);
        FMT_A3.store(p3 as usize, Ordering::SeqCst);
        FMT_A4.store(p4 as usize, Ordering::SeqCst);
        FMT_A5.store(p5 as usize, Ordering::SeqCst);
        FMT_A6.store(p6 as usize, Ordering::SeqCst);
        5
    }

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
        // format lock. Save/restore after.
        let _common = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let _f74 = crate::fn_00408274::TEST_LOCK.lock().unwrap();
        let s74 = unsafe { crate::fn_00408274::HOOK_00408540 };
        let s4820 = unsafe { crate::fn_00404820::CALLEE_00404E6C };
        let sdd_a = unsafe { crate::fn_00404dd4::HOOK_004054b4 };
        let sdd_f = unsafe { crate::fn_00404dd4::HOOK_00402fbc };
        unsafe {
            crate::fn_00408274::HOOK_00408540 = format_hook;
            crate::fn_00404820::CALLEE_00404E6C = norm_callee;
            crate::fn_00404dd4::HOOK_004054b4 = alloc;
            crate::fn_00404dd4::HOOK_00402fbc = fill;
        }
        // Null-object small lane: (p1=0, p2, p3) must arrive at the
        // sibling as (slot=p4, obj=0, p3, p4)=(slot, 0, p2, p3),
        // so format sees (buf, 0xfff, 0, p3, p2, 0).
        let mut slot: *mut u8 = core::ptr::null_mut();
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;
        FMT_CALLS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_004082d4(core::ptr::null_mut(), 0x2222_2222, 0x3333_3333, slot_ptr) };
        assert_eq!(FMT_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(FMT_A2.load(Ordering::SeqCst), 0xfff);
        assert_eq!(FMT_A3.load(Ordering::SeqCst), 0);
        assert_eq!(FMT_A4.load(Ordering::SeqCst), 0x3333_3333);
        assert_eq!(FMT_A5.load(Ordering::SeqCst), 0x2222_2222);
        assert_eq!(FMT_A6.load(Ordering::SeqCst), 0);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(slot, CANNED as usize as *mut u8);
        unsafe {
            crate::fn_00408274::HOOK_00408540 = s74;
            crate::fn_00404820::CALLEE_00404E6C = s4820;
            crate::fn_00404dd4::HOOK_004054b4 = sdd_a;
            crate::fn_00404dd4::HOOK_00402fbc = sdd_f;
        }
    }
}
