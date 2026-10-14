//! Original procedure `0x00409810` (6 bytes, `0x00409810–0x00409815`).
//! Evidence: `evidence/00409810_fn_00409810.md`.

/// Target `0x004097f0` (`FUN_004097f0`), entered by `JMP` with the popped
/// `EAX` as its entry lane: direct intra-reconstruction call (rewired;
/// signatures verified `fn(usize)`).

/// `POP EAX; JMP 004097f0`: pops the guest return address into `EAX`
/// and enters `097f0` with it. No guest stack exists on host, so the
/// lane is a feasible `0`; `() -> void` per `__register` observation.
pub unsafe fn fn_00409810() {
    crate::fn_004097f0::fn_004097f0(0);
}

#[cfg(test)]
mod tests {
    use super::fn_00409810;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);
    static MAKE_HITS: AtomicUsize = AtomicUsize::new(0);
    static MAKE_A: AtomicUsize = AtomicUsize::new(0);
    static MAKE_B: AtomicUsize = AtomicUsize::new(0);
    static MAKE_C: AtomicUsize = AtomicUsize::new(0);
    static MAKE_D: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn make(slot: usize, flag: u8, ctx: usize, arg: usize) -> usize {
        MAKE_HITS.fetch_add(1, Ordering::SeqCst);
        MAKE_A.store(slot, Ordering::SeqCst);
        MAKE_B.store(flag as usize, Ordering::SeqCst);
        MAKE_C.store(ctx, Ordering::SeqCst);
        MAKE_D.store(arg, Ordering::SeqCst);
        0xd004
    }

    unsafe extern "C" fn tail(p: usize) {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(p, Ordering::SeqCst);
    }

    #[test]
    fn hands_off_to_097f0() {
        // Real `fn_004097f0` under its lock: maker args from its
        // cells, tail observes the maker result.
        let _guard = crate::fn_004097f0::TEST_LOCK.lock().unwrap();
        let (old_make, old_tail, old_d1, old_d2);
        unsafe {
            old_make = crate::fn_004097f0::HOOK_004098E0;
            old_tail = crate::fn_004097f0::TAIL_00403F88;
            old_d1 = crate::fn_004097f0::DAT_00406DD8;
            old_d2 = crate::fn_004097f0::DAT_00412BB8;
            crate::fn_004097f0::HOOK_004098E0 = make;
            crate::fn_004097f0::TAIL_00403F88 = tail;
            crate::fn_004097f0::DAT_00406DD8 = 0xa001;
            crate::fn_004097f0::DAT_00412BB8 = 0xb002;
        }
        unsafe { fn_00409810() };
        assert_eq!(MAKE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(MAKE_A.load(Ordering::SeqCst), 0xa001);
        assert_eq!(MAKE_B.load(Ordering::SeqCst), 1);
        assert_eq!(MAKE_C.load(Ordering::SeqCst), 0xb002);
        assert_eq!(MAKE_D.load(Ordering::SeqCst), 0);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 0xd004);
        unsafe {
            crate::fn_004097f0::HOOK_004098E0 = old_make;
            crate::fn_004097f0::TAIL_00403F88 = old_tail;
            crate::fn_004097f0::DAT_00406DD8 = old_d1;
            crate::fn_004097f0::DAT_00412BB8 = old_d2;
        }
    }
}
