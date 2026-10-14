//! Original procedure `0x00408524` (27 bytes, `0x00408524–0x0040853e`).
//! Evidence: `evidence/00408524_fn_00408524.md`.

unsafe extern "C" fn default_00408988(
    _p1: *mut u16,
    _p2: u32,
    _p3: u8,
    _p4: u32,
    _p5: i32,
    _p6: u8,
) {
}

/// Callee `0x00408988` (`FUN_00408988`): `EAX`/`EDX`/`ECX` pass through
/// untouched while three stack args are pushed right-to-left, so the
/// hook takes all six lanes in order. `RET 0xc` pops exactly the
/// three pushed dwords.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_00408988` once it exists.
pub static mut HOOK_00408988: unsafe extern "C" fn(*mut u16, u32, u8, u32, i32, u8) =
    default_00408988;

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
    HOOK_00408988(param_1, param_2, param_3, param_4, param_5, param_6);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00408988, TEST_LOCK, fn_00408524};
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
        p2: u32,
        p3: u8,
        p4: u32,
        p5: i32,
        p6: u8,
    ) {
        HITS.fetch_add(1, Ordering::SeqCst);
        A1.store(p1 as usize, Ordering::SeqCst);
        A2.store(p2 as usize, Ordering::SeqCst);
        A3.store(p3 as usize, Ordering::SeqCst);
        A4.store(p4 as usize, Ordering::SeqCst);
        A5.store(p5 as usize, Ordering::SeqCst);
        A6.store(p6 as usize, Ordering::SeqCst);
    }

    #[test]
    fn forward_all_six() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe { HOOK_00408988 = callee };
        let mut b1 = [0u16; 2];
        let p1 = b1.as_mut_ptr();
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00408524(p1, 0x2222_2222, 0x43, 0x44, -7, 0x46) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(A1.load(Ordering::SeqCst), p1 as usize);
        assert_eq!(A2.load(Ordering::SeqCst), 0x2222_2222);
        assert_eq!(A3.load(Ordering::SeqCst), 0x43);
        assert_eq!(A4.load(Ordering::SeqCst), 0x44);
        assert_eq!(A5.load(Ordering::SeqCst), (-7i32) as usize);
        assert_eq!(A6.load(Ordering::SeqCst), 0x46);
    }
}
