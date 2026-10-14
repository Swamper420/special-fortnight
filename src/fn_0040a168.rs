//! Original procedure `0x0040a168` (30 bytes, `0x40a168–0x40a185`).
//! Evidence: `evidence/0040a168_fn_0040a168.md`.

unsafe extern "C" fn default_exchange(
    _dest: *mut i32,
    _ex: i32,
    _cmp: usize,
) -> usize {
    0
}

/// Exchange target `0x406698` (`FUN_00406698`),
/// `(dest, *slotval, slotval)`; EAX result is a DATA pointer
/// observed by the loop's `CMP EBX, EAX`.
///
/// ponytail: hook standing in for done `fn_00406698` (which
/// drops EAX as `void`), rewire to the direct call only once
/// it returns the observed EAX value. Result and comparand
/// stay pointer-sized (never `u32` for pointers).
pub static mut HOOK_00406698: unsafe extern "C" fn(*mut i32, i32, usize) -> usize =
    default_exchange;

/// Confirm-pointer loop: `b=*p1; if (b==0) return 0;
/// r=exch(p1, *b, b)` until `r == b`; returns the confirmed
/// slot value (pointer-sized). `param_1` arrives in EAX per
/// Ghidra `__register` observation. Do-while shape mirrors
/// the `JZ`-out / `JNZ`-back edges; callee-saved saves
/// omitted.
pub unsafe fn fn_0040a168(param_1: *mut i32) -> *mut i32 {
    loop {
        let b: *mut i32 = core::ptr::read_unaligned(param_1 as *const *mut i32);
        if b.is_null() {
            return core::ptr::null_mut();
        }
        let r = HOOK_00406698(
            param_1,
            core::ptr::read_unaligned(b as *const i32),
            b as usize,
        );
        if r == b as usize {
            return r as *mut i32;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406698, fn_0040a168};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_DEST: AtomicUsize = AtomicUsize::new(0);
    static GOT_EX: AtomicUsize = AtomicUsize::new(0);
    static GOT_CMP: AtomicUsize = AtomicUsize::new(0);
    static STALE_ONCE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn exch(dest: *mut i32, ex: i32, cmp: usize) -> usize {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_DEST.store(dest as usize, Ordering::SeqCst);
        GOT_EX.store(ex as usize, Ordering::SeqCst);
        GOT_CMP.store(cmp, Ordering::SeqCst);
        if STALE_ONCE.load(Ordering::SeqCst) == 1 && HITS.load(Ordering::SeqCst) == 1 {
            0x1000
        } else {
            cmp
        }
    }

    #[test]
    fn null_converge_retry_lanes() {
        // Own hook only: no foreign globals, no TEST_LOCK.
        unsafe { HOOK_00406698 = exch };
        let mut cell = 5i32;
        let b = &mut cell as *mut i32;
        let mut slot: *mut i32 = core::ptr::null_mut();
        let p1 = &mut slot as *mut *mut i32 as *mut i32;
        // Null lane: callee never fires, null returned.
        HITS.store(0, Ordering::SeqCst);
        STALE_ONCE.store(0, Ordering::SeqCst);
        assert!(unsafe { fn_0040a168(p1) }.is_null());
        assert_eq!(HITS.load(Ordering::SeqCst), 0);
        // Converge lane: single call, slot value returned.
        slot = b;
        HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_0040a168(p1) }, b);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_DEST.load(Ordering::SeqCst), p1 as usize);
        assert_eq!(GOT_EX.load(Ordering::SeqCst), 5);
        assert_eq!(GOT_CMP.load(Ordering::SeqCst), b as usize);
        // Retry lane: stale pointer once, then confirm.
        HITS.store(0, Ordering::SeqCst);
        STALE_ONCE.store(1, Ordering::SeqCst);
        assert_eq!(unsafe { fn_0040a168(p1) }, b);
        assert_eq!(HITS.load(Ordering::SeqCst), 2);
        assert_eq!(GOT_CMP.load(Ordering::SeqCst), b as usize);
    }
}
