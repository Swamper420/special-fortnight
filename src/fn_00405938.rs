//! Original procedure `0x00405938` (6 bytes, `0x405938–0x40593d`).
//! Evidence: `evidence/00405938_fn_00405938.md`.

unsafe extern "C" fn default_callee(_a: *mut usize, _b: *const u8) { }

/// Callee `0x405ae4` (`FUN_00405ae4`, 58 bytes, unreconstructed),
/// reached by bare `CALL` with `(EAX, EDX)` untouched.
///
/// ponytail: hook standing in for the unreconstructed callee;
/// rewire to real `fn_00405ae4` once it exists.
pub static mut HOOK_00405AE4: unsafe extern "C" fn(*mut usize, *const u8) =
    default_callee;

/// Test-only serialization for tests sharing `HOOK_00405AE4` (also
/// held by the `fn_00405940`/`fn_00405ad8` tests that forward
/// through this module).
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Tail-forward `(slot, desc)` to `0x405ae4`; params arrive in
/// EAX/EDX per Ghidra `__register` observation.
pub unsafe fn fn_00405938(param_1: *mut usize, param_2: *const u8) {
    HOOK_00405AE4(param_1, param_2);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00405AE4, TEST_LOCK, fn_00405938};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_A: AtomicUsize = AtomicUsize::new(0);
    static GOT_B: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn callee(a: *mut usize, b: *const u8) {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_A.store(a as usize, Ordering::SeqCst);
        GOT_B.store(b as usize, Ordering::SeqCst);
    }

    #[test]
    fn forwards_both_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe { HOOK_00405AE4 = callee; }
        let mut slot: usize = 0;
        let desc = [0u8; 8];
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00405938(&mut slot, desc.as_ptr()) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_A.load(Ordering::SeqCst), &mut slot as *mut usize as usize);
        assert_eq!(GOT_B.load(Ordering::SeqCst), desc.as_ptr() as usize);
    }
}
