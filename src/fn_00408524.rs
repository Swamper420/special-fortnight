//! Original procedure `0x00408524` (27 bytes, `0x00408524–0x0040853e`).
//! Evidence: `evidence/00408524_fn_00408524.md`.

/// Callee `0x00408988` (`FUN_00408988`): `EAX`/`EDX`/`ECX` pass through
/// untouched while three stack args are pushed right-to-left, so the
/// hook takes all six lanes in order. `RET 0xc` pops exactly the
/// three pushed dwords: direct intra-reconstruction call (rewired;
/// signatures verified `fn(*mut u16, u32, u8, u32, i32, u8)`).

/// Test-only serialization for tests sharing this module's hook.
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Shuffle-forwarder: `HOOK_00408988(p1, p2, p3, p4, p5, p6)`.
/// `PUSH EBP/POP EBP`, the `PUSH EBX` spill/`POP EBX`, and `RET 0xc`
/// have no host-visible effect.
pub unsafe fn fn_00408524(
    param_1: *mut u16,
    param_2: u32,
    param_3: u8,
    param_4: u32,
    param_5: i32,
    param_6: u8,
) {
    crate::fn_00408988::fn_00408988(param_1, param_2, param_3, param_4, param_5, param_6);
}

#[cfg(test)]
mod tests {
    use super::{TEST_LOCK, fn_00408524};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static C88_HITS: AtomicUsize = AtomicUsize::new(0);
    static C88_P2: AtomicUsize = AtomicUsize::new(0);
    static C88_P3: AtomicUsize = AtomicUsize::new(0);
    static C88_PREC: AtomicUsize = AtomicUsize::new(0);
    static C88_V: AtomicUsize = AtomicUsize::new(0);
    static TBL_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_ARG: AtomicUsize = AtomicUsize::new(0);

    /// Converter behind real `fn_00408988`: records lanes, emits a
    /// general-lane word (10).
    unsafe extern "C" fn c88(
        _buf: *mut u8,
        p2: u32,
        p3: u32,
        prec: u32,
        v: u32,
    ) {
        C88_HITS.fetch_add(1, Ordering::SeqCst);
        C88_P2.store(p2 as usize, Ordering::SeqCst);
        C88_P3.store(p3 as usize, Ordering::SeqCst);
        C88_PREC.store(prec as usize, Ordering::SeqCst);
        C88_V.store(v as usize, Ordering::SeqCst);
        core::ptr::write_unaligned(_buf as *mut u16, 10);
    }

    unsafe extern "C" fn a88(_arg: u32) -> u32 {
        1
    }

    unsafe extern "C" fn tbl() {
        TBL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn tail(count: u32) {
        TAIL_ARG.store(count as usize, Ordering::SeqCst);
    }

    #[test]
    fn forward_all_six() {
        // Real `fn_00408988` under its lock; general lane (`p6=0x46`
        // > 4 → table 0, cursor unmoved → tail 0).
        let _guard = TEST_LOCK.lock().unwrap();
        let _callee = crate::fn_00408988::TEST_LOCK.lock().unwrap();
        let (old_c88, old_a88, old_tail, old_tbl, old_blob);
        unsafe {
            old_c88 = crate::fn_00408988::HOOK_00408C88;
            old_a88 = crate::fn_00408988::HOOK_00408A88;
            old_tail = crate::fn_00408988::TAIL_00408C82;
            old_tbl = crate::fn_00408988::TBL_00408A5D;
            old_blob = crate::fn_00408988::DAT_00415B6C;
            crate::fn_00408988::HOOK_00408C88 = c88;
            crate::fn_00408988::HOOK_00408A88 = a88;
            crate::fn_00408988::TAIL_00408C82 = tail;
            crate::fn_00408988::TBL_00408A5D = [tbl, tbl, tbl, tbl, tbl];
            crate::fn_00408988::DAT_00415B6C = [0; 10];
        }
        let mut b1 = [0u16; 2];
        let p1 = b1.as_mut_ptr();
        C88_HITS.store(0, Ordering::SeqCst);
        TBL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00408524(p1, 0x2222_2222, 0x43, 0x44, -7, 0x46) };
        assert_eq!(C88_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(C88_P2.load(Ordering::SeqCst), 0x2222_2222);
        assert_eq!(C88_P3.load(Ordering::SeqCst), 0x43);
        assert_eq!(C88_PREC.load(Ordering::SeqCst), 0x13);
        assert_eq!(C88_V.load(Ordering::SeqCst), 0x44);
        assert_eq!(TBL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 0);
        unsafe {
            crate::fn_00408988::HOOK_00408C88 = old_c88;
            crate::fn_00408988::HOOK_00408A88 = old_a88;
            crate::fn_00408988::TAIL_00408C82 = old_tail;
            crate::fn_00408988::TBL_00408A5D = old_tbl;
            crate::fn_00408988::DAT_00415B6C = old_blob;
        }
    }
}
