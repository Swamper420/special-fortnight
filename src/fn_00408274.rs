//! Original procedure `0x00408274` (26 bytes, `0x00408274–0x0040828d`).
//! Evidence: `evidence/00408274_fn_00408274.md`.

/// Test-only serialization for tests driving the real `fn_00408540`
/// chain (also held by cross-module tests that reach it via
/// `fn_00408274`).
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Forward `(p1, p2, p3, p4, p5, p6)` to `0x00408540`; return leftover
/// `EAX`. `EAX/EDX/ECX` plus three stack slots per Ghidra
/// `__register` observation; `PUSH/POP EBX` spill and `RET 0xc`
/// have no host-visible effect.
///
/// Target `0x00408540` (`FUN_00408540`): direct intra-reconstruction
/// call (rewired; signatures verified
/// `fn(*mut u16, *mut u16, *mut u16, u32, u32, i32) -> u32`).
pub unsafe fn fn_00408274(
    param_1: *mut u16,
    param_2: *mut u16,
    param_3: *mut u16,
    param_4: u32,
    param_5: u32,
    param_6: i32,
) -> u32 {
    crate::fn_00408540::fn_00408540(param_1, param_2, param_3, param_4, param_5, param_6)
}

#[cfg(test)]
mod tests {
    use super::{TEST_LOCK, fn_00408274};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CALLEE_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_ARG: AtomicUsize = AtomicUsize::new(0);
    static TAIL_RET: AtomicUsize = AtomicUsize::new(0);

    /// Passthrough for the real scanner's char lane (unreached on
    /// the literal lane).
    unsafe extern "C" fn callee(_a: u32, _b: usize, _c: *mut u16) {
        CALLEE_HITS.fetch_add(1, Ordering::SeqCst);
    }

    /// Exit block behind the real scanner.
    unsafe extern "C" fn tail(n: u32) -> u32 {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
        TAIL_ARG.store(n as usize, Ordering::SeqCst);
        TAIL_RET.load(Ordering::SeqCst) as u32
    }

    #[test]
    fn forward_all_six() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _scan = crate::fn_00408540::TEST_LOCK.lock().unwrap();
        // Real `fn_00408540` behind the forward: literal lane.
        let (old_callee, old_tail);
        unsafe {
            old_callee = crate::fn_00408540::HOOK_0040867D;
            old_tail = crate::fn_00408540::HOOK_00408914;
            crate::fn_00408540::HOOK_0040867D = callee;
            crate::fn_00408540::HOOK_00408914 = tail;
        }
        TAIL_RET.store(0x2a, Ordering::SeqCst);
        let cap = 8 as *mut u16;
        let mut dst = [0u16; 4];
        let fmt = [0x41u16, 0x42];
        CALLEE_HITS.store(0, Ordering::SeqCst);
        TAIL_HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_00408274(dst.as_mut_ptr(), cap, fmt.as_ptr() as *mut u16, 0, 0, 2) };
        assert_eq!(r, 0x2a);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 2);
        assert_eq!(CALLEE_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(dst[0], 0x41);
        assert_eq!(dst[1], 0x42);
        unsafe {
            crate::fn_00408540::HOOK_0040867D = old_callee;
            crate::fn_00408540::HOOK_00408914 = old_tail;
        }
    }
}
