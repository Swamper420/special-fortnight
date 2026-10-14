//! Original procedure `0x00408274` (26 bytes, `0x00408274–0x0040828d`).
//! Evidence: `evidence/00408274_fn_00408274.md`.

unsafe extern "C" fn default_00408540(
    _p1: *mut u16,
    _p2: *mut u16,
    _p3: *mut u16,
    _p4: u32,
    _p5: u32,
    _p6: i32,
) -> u32 {
    0
}

/// Callee `0x00408540` (`FUN_00408540`), called with all six params
/// verbatim; `EAX` flows through untouched, so the hook result is
/// the procedure result.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_00408540` once it exists.
pub static mut HOOK_00408540: unsafe extern "C" fn(*mut u16, *mut u16, *mut u16, u32, u32, i32) -> u32 =
    default_00408540;

/// Test-only serialization for tests sharing `HOOK_00408540` (also
/// held by cross-module tests that reach it via `fn_00408274`).
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Forward `(p1, p2, p3, p4, p5, p6)` to `0x00408540`; return leftover
/// `EAX`. `EAX/EDX/ECX` plus three stack slots per Ghidra
/// `__register` observation; `PUSH/POP EBX` spill and `RET 0xc`
/// have no host-visible effect.
pub unsafe fn fn_00408274(
    param_1: *mut u16,
    param_2: *mut u16,
    param_3: *mut u16,
    param_4: u32,
    param_5: u32,
    param_6: i32,
) -> u32 {
    HOOK_00408540(param_1, param_2, param_3, param_4, param_5, param_6)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00408540, TEST_LOCK, fn_00408274};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);
    static A3: AtomicUsize = AtomicUsize::new(0);
    static A4: AtomicUsize = AtomicUsize::new(0);
    static A5: AtomicUsize = AtomicUsize::new(0);
    static A6: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn callee(
        p1: *mut u16,
        p2: *mut u16,
        p3: *mut u16,
        p4: u32,
        p5: u32,
        p6: i32,
    ) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        A1.store(p1 as usize, Ordering::SeqCst);
        A2.store(p2 as usize, Ordering::SeqCst);
        A3.store(p3 as usize, Ordering::SeqCst);
        A4.store(p4 as usize, Ordering::SeqCst);
        A5.store(p5 as usize, Ordering::SeqCst);
        A6.store(p6 as usize, Ordering::SeqCst);
        0x2a
    }

    #[test]
    fn forward_all_six() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe { HOOK_00408540 = callee };
        let mut b1 = [0u16; 2];
        let mut b2 = [0u16; 2];
        let mut b3 = [0u16; 2];
        let (p1, p2, p3) = (b1.as_mut_ptr(), b2.as_mut_ptr(), b3.as_mut_ptr());
        HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_00408274(p1, p2, p3, 0x44, 0x55, -7) };
        assert_eq!(r, 0x2a);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(A1.load(Ordering::SeqCst), p1 as usize);
        assert_eq!(A2.load(Ordering::SeqCst), p2 as usize);
        assert_eq!(A3.load(Ordering::SeqCst), p3 as usize);
        assert_eq!(A4.load(Ordering::SeqCst), 0x44);
        assert_eq!(A5.load(Ordering::SeqCst), 0x55);
        assert_eq!(A6.load(Ordering::SeqCst), (-7i32) as usize);
    }
}
