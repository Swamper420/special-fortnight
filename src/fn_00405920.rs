//! Original procedure `0x00405920` (15 bytes, `0x405920–0x40592e`).
//! Evidence: `evidence/00405920_fn_00405920.md`.

unsafe extern "C" fn default_callee(_a: usize, _b: usize, _c: *mut u8, _d: u32) { }

/// Callee `0x4057bc` (`FUN_004057bc`), reached by `CALL` with
/// `(EAX, EDX, ECX)` untouched and the stack count re-pushed.
///
/// ponytail: hook standing in for done `fn_004057bc` (which takes
/// the first two lanes as `usize`); bases cross as `usize` so host
/// pointers stay whole. Rewire to the real call once cross-module
/// test serialization exists.
pub static mut HOOK_004057BC: unsafe extern "C" fn(usize, usize, *mut u8, u32) =
    default_callee;

/// Test-only serialization for tests sharing `HOOK_004057BC` (also
/// held by the `fn_00405940` test that forwards through this
/// module).
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Tail-forward `(dst, src, chars, count)` to `0x4057bc`; params
/// arrive in EAX/EDX/ECX (+stack count) per Ghidra `__register`
/// observation. `RET 0x4` modeled as by-value `u32`.
pub unsafe fn fn_00405920(
    param_1: *mut u8,
    param_2: *mut u8,
    param_3: *mut u8,
    param_4: u32,
) {
    HOOK_004057BC(param_1 as usize, param_2 as usize, param_3, param_4);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004057BC, TEST_LOCK, fn_00405920};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_A: AtomicUsize = AtomicUsize::new(0);
    static GOT_B: AtomicUsize = AtomicUsize::new(0);
    static GOT_C: AtomicUsize = AtomicUsize::new(0);
    static GOT_D: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn callee(a: usize, b: usize, c: *mut u8, d: u32) {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_A.store(a, Ordering::SeqCst);
        GOT_B.store(b, Ordering::SeqCst);
        GOT_C.store(c as usize, Ordering::SeqCst);
        GOT_D.store(d as usize, Ordering::SeqCst);
    }

    #[test]
    fn forwards_all_four_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe { HOOK_004057BC = callee; }
        let mut x = [0u8; 4];
        let mut y = [0u8; 4];
        let mut z = [0u8; 4];
        let (a, b, c) = (x.as_mut_ptr(), y.as_mut_ptr(), z.as_mut_ptr());
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00405920(a, b, c, 0x1234) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_A.load(Ordering::SeqCst), a as usize);
        assert_eq!(GOT_B.load(Ordering::SeqCst), b as usize);
        assert_eq!(GOT_C.load(Ordering::SeqCst), c as usize);
        assert_eq!(GOT_D.load(Ordering::SeqCst), 0x1234);
    }
}
