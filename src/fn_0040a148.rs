//! Original procedure `0x0040a148` (30 bytes, `0x40a148–0x40a165`).
//! Evidence: `evidence/0040a148_fn_0040a148.md`.

unsafe extern "C" fn default_exchange(
    _dest: *mut i32,
    _ex: usize,
    _cmp: i32,
) -> i32 {
    0
}

/// Exchange target `0x406698` (`FUN_00406698`),
/// `(dest, slotaddr, comparand)`; EAX result observed by the
/// loop's `CMP EAX, [EBX]`.
///
/// ponytail: hook standing in for done `fn_00406698` (which
/// drops EAX as `void`), rewire to the direct call only once
/// it returns the observed EAX value. Middle arg widened to
/// pointer-sized (never `as u32` on pointers).
pub static mut HOOK_00406698: unsafe extern "C" fn(*mut i32, usize, i32) -> i32 =
    default_exchange;

/// Publish-and-confirm loop: `old=*p1; *p2=old;
/// r=exch(p1, p2, old)` until `r == *p2` (re-read after the
/// call). `param_1` EAX / `param_2` EDX per Ghidra
/// `__register` observation. Do-while shape mirrors the
/// `JNZ`-back-edge; callee-saved saves omitted.
pub unsafe fn fn_0040a148(param_1: *mut i32, param_2: *mut i32) {
    loop {
        let old: i32 = core::ptr::read_unaligned(param_1 as *const i32);
        core::ptr::write_unaligned(param_2, old);
        let r = HOOK_00406698(param_1, param_2 as usize, old);
        if r == core::ptr::read_unaligned(param_2 as *const i32) {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406698, fn_0040a148};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_DEST: AtomicUsize = AtomicUsize::new(0);
    static GOT_EX: AtomicUsize = AtomicUsize::new(0);
    static GOT_CMP: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn exch(dest: *mut i32, ex: usize, cmp: i32) -> i32 {
        let h = HITS.fetch_add(1, Ordering::SeqCst);
        GOT_DEST.store(dest as usize, Ordering::SeqCst);
        GOT_EX.store(ex, Ordering::SeqCst);
        GOT_CMP.store(cmp as usize, Ordering::SeqCst);
        if h == 0 && cmp == 5 {
            // Stale lane: concurrent update + stale read back.
            core::ptr::write_unaligned(dest, 8);
            9
        } else {
            core::ptr::read_unaligned(dest as *const i32)
        }
    }

    #[test]
    fn converge_and_retry_lanes() {
        // Own hook only: no foreign globals, no TEST_LOCK.
        unsafe { HOOK_00406698 = exch };
        let mut src = 7i32;
        let mut dst = 0i32;
        let (p1, p2) = (&mut src as *mut i32, &mut dst as *mut i32);
        // Converge: single call, slot takes the source value.
        HITS.store(1, Ordering::SeqCst);
        unsafe { fn_0040a148(p1, p2) };
        assert_eq!(HITS.load(Ordering::SeqCst), 2);
        assert_eq!(dst, 7);
        assert_eq!(GOT_DEST.load(Ordering::SeqCst), p1 as usize);
        assert_eq!(GOT_EX.load(Ordering::SeqCst), p2 as usize);
        assert_eq!(GOT_CMP.load(Ordering::SeqCst), 7);
        // Retry: stale read (9 != 5), then the updated value (8).
        src = 5;
        dst = 0;
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040a148(p1, p2) };
        assert_eq!(HITS.load(Ordering::SeqCst), 2);
        assert_eq!(dst, 8);
        assert_eq!(src, 8);
        assert_eq!(GOT_CMP.load(Ordering::SeqCst), 8);
    }
}
