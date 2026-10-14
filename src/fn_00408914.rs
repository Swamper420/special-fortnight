//! Original procedure `0x00408914` (15 bytes, `0x00408914–0x00408922`).
//! Evidence: `evidence/00408914_fn_00408914.md`.

/// Callee `0x00408904` (`FUN_00408904`): direct intra-reconstruction
/// call (rewired; signatures verified `fn(u32) -> u32`).

/// `return hook(param_1)`. `EAX` is untouched after the call, so the
/// callee's return passes through; pops/`MOV ESP,EBP`/`RET 0xc` are
/// the shared caller-frame epilogue with no data effect.
pub unsafe fn fn_00408914(param_1: u32) -> u32 {
    crate::fn_00408904::fn_00408904(param_1)
}

#[cfg(test)]
mod tests {
    use super::fn_00408914;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn inner(slot: *mut u32) {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(slot as usize, Ordering::SeqCst);
    }

    #[test]
    fn passthrough() {
        // Real `fn_00408904` under its lock: returns its arg, fires
        // the scratch-slot sub-hook once per call.
        let _guard = crate::fn_00408904::TEST_LOCK.lock().unwrap();
        let old = unsafe { crate::fn_00408904::HOOK_00404A8C };
        unsafe { crate::fn_00408904::HOOK_00404A8C = inner };
        for v in [0u32, 7] {
            HITS.store(0, Ordering::SeqCst);
            assert_eq!(unsafe { fn_00408914(v) }, v);
            assert_eq!(HITS.load(Ordering::SeqCst), 1);
            assert_ne!(ARG.load(Ordering::SeqCst), 0);
        }
        unsafe { crate::fn_00408904::HOOK_00404A8C = old };
    }
}
