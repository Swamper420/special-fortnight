//! Original procedure `0x00406134` (99 bytes, `0x00406134–0x00406196`).
//! Evidence: `evidence/00406134_fn_00406134.md`.

unsafe extern "C" fn default_free(_ptr: usize, _size: u32) {}

/// Free `FUN_00402e20` (`CALL 0x00402e20` with node in EAX, `EDX=8`).
///
/// ponytail: hook standing in for done `fn_00402e20`, rewire to the real
/// call once cross-module linkage exists.
pub static mut HOOK_FN_00402e20: unsafe extern "C" fn(usize, u32) = default_free;

/// Unlink first node whose value slot matches `param_1`: head-match
/// lane first, else prev/cur walk; frees at most one node with size 8.
/// `param_1` arrives in EAX (callee-saved via EBP) per observation.
/// Head lives in `crate::fn_00406114::DAT_00412030` (no duplicate cell).
/// Host nodes carry two pointer slots; value slot at `NODE_VAL_OFF`.
pub unsafe fn fn_00406134(param_1: u32) {
    use crate::fn_00406114::NODE_VAL_OFF;
    unsafe {
        let head: *mut u8 = crate::fn_00406114::DAT_00412030;
        if head.is_null()
            || core::ptr::read_unaligned(head.wrapping_byte_add(NODE_VAL_OFF) as *const usize)
                != param_1 as usize
        {
            let mut prev: *mut u8 = head;
            while !prev.is_null() {
                let cur: *mut u8 =
                    core::ptr::read_unaligned(prev as *const *mut u8);
                if !cur.is_null()
                    && core::ptr::read_unaligned(cur.wrapping_byte_add(NODE_VAL_OFF) as *const usize)
                        == param_1 as usize
                {
                    let next: *mut u8 =
                        core::ptr::read_unaligned(cur as *const *mut u8);
                    core::ptr::write_unaligned(prev as *mut *mut u8, next);
                    HOOK_FN_00402e20(cur as usize, 8);
                    return;
                }
                prev = core::ptr::read_unaligned(prev as *const *mut u8);
            }
        } else {
            let next: *mut u8 =
                core::ptr::read_unaligned(head as *const *mut u8);
            crate::fn_00406114::DAT_00412030 = next;
            HOOK_FN_00402e20(head as usize, 8);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_FN_00402e20, fn_00406134};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static FREE_HITS: AtomicUsize = AtomicUsize::new(0);
    static FREE_PTR: AtomicUsize = AtomicUsize::new(0);
    static FREE_SIZE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn free(ptr: usize, size: u32) {
        FREE_HITS.fetch_add(1, Ordering::SeqCst);
        FREE_PTR.store(ptr, Ordering::SeqCst);
        FREE_SIZE.store(size as usize, Ordering::SeqCst);
    }

    fn node(next: usize, val: usize) -> usize {
        Box::into_raw(Box::new([next, val])) as usize
    }

    unsafe fn val(n: usize) -> usize {
        core::ptr::read_unaligned(
            (n as *const u8).wrapping_byte_add(crate::fn_00406114::NODE_VAL_OFF)
                as *const usize,
        )
    }

    unsafe fn next(n: usize) -> usize {
        core::ptr::read_unaligned(n as *const usize)
    }

    #[test]
    fn unlink_lanes() {
        let _guard = crate::fn_00406114::TEST_LOCK.lock().unwrap();
        unsafe { HOOK_FN_00402e20 = free };
        // Chain head -> m1(7) -> m2(9) -> null.
        let m2 = node(0, 9);
        let m1 = node(m2, 7);
        unsafe { crate::fn_00406114::DAT_00412030 = m1 as *mut u8 };
        // No match: no free, list intact.
        FREE_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00406134(3) };
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { crate::fn_00406114::DAT_00412030 } as usize, m1);
        // Mid-list removal: prev links past freed node.
        unsafe { fn_00406134(9) };
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FREE_PTR.load(Ordering::SeqCst), m2);
        assert_eq!(FREE_SIZE.load(Ordering::SeqCst), 8);
        assert_eq!(unsafe { crate::fn_00406114::DAT_00412030 } as usize, m1);
        assert_eq!(unsafe { next(m1) }, 0);
        // Head removal.
        unsafe { fn_00406134(7) };
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(FREE_PTR.load(Ordering::SeqCst), m1);
        assert!(unsafe { crate::fn_00406114::DAT_00412030 }.is_null());
        unsafe {
            assert_eq!(val(m1), 7);
            let _ = Box::from_raw(m1 as *mut [usize; 2]);
            let _ = Box::from_raw(m2 as *mut [usize; 2]);
        }
        // Empty list: no free.
        unsafe { fn_00406134(7) };
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 2);
    }
}
