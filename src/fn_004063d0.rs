//! Original procedure `0x004063d0` (18 bytes, `0x4063d0–0x4063e1`).
//! Evidence: `evidence/004063d0_fn_004063d0.md`.

unsafe extern "C" fn default_callee(_a: *const u8, _b: *mut u8) {}

/// Target `0x40633c` (`FUN_0040633c`), called with unchanged
/// `(param_1, param_2)`; register spills have no host-visible effect.
///
/// ponytail: hook standing in for same-batch `fn_0040633c`, rewire
/// to the real call once both modules are linked.
pub static mut CALLEE_0040633c: unsafe extern "C" fn(*const u8, *mut u8) = default_callee;

/// Forwarding wrapper: `callee(param_1, param_2)`. `param_1` EAX /
/// `param_2` EDX per Ghidra `__register` observation.
pub unsafe fn fn_004063d0(param_1: *const u8, param_2: *mut u8) {
    CALLEE_0040633c(param_1, param_2);
}

#[cfg(test)]
mod tests {
    use super::{CALLEE_0040633c, fn_004063d0};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_A: AtomicUsize = AtomicUsize::new(0);
    static GOT_B: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn callee(a: *const u8, b: *mut u8) {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_A.store(a as usize, Ordering::SeqCst);
        GOT_B.store(b as usize, Ordering::SeqCst);
    }

    #[test]
    fn forwards_both_args_once() {
        unsafe { CALLEE_0040633c = callee };
        let a = [1u8, 2];
        let mut b = [0u8; 4];
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_004063d0(a.as_ptr(), b.as_mut_ptr()) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_A.load(Ordering::SeqCst), a.as_ptr() as usize);
        assert_eq!(GOT_B.load(Ordering::SeqCst), b.as_mut_ptr() as usize);
    }
}
