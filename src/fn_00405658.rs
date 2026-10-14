//! Original procedure `0x00405658` (10 bytes, `0x00405658–0x00405661`).
//! Evidence: `evidence/00405658_fn_00405658.md`.

unsafe extern "C" fn default_target(_a: *mut u8, _b: *mut u8, _c: u32) {}

/// Target `0x00405548` (`FUN_00405548`), reached by `JMP` with `ECX=1`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00405548` once it exists.
pub static mut HOOK_00405548: unsafe extern "C" fn(*mut u8, *mut u8, u32) =
    default_target;

/// `tgt(param_1, param_2, 1)`; `ECX=1` set before the terminal `JMP`.
/// Params arrive in EAX/EDX per Ghidra `__register` observation.
pub unsafe fn fn_00405658(param_1: *mut u8, param_2: *mut u8) {
    HOOK_00405548(param_1, param_2, 1);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00405548, fn_00405658};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_A: AtomicUsize = AtomicUsize::new(0);
    static GOT_B: AtomicUsize = AtomicUsize::new(0);
    static GOT_C: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a: *mut u8, b: *mut u8, c: u32) {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_A.store(a as usize, Ordering::SeqCst);
        GOT_B.store(b as usize, Ordering::SeqCst);
        GOT_C.store(c as usize, Ordering::SeqCst);
    }

    #[test]
    fn forwards_with_const_third_lane() {
        unsafe { HOOK_00405548 = hook };
        HITS.store(0, Ordering::SeqCst);
        let mut x = [0u8; 4];
        let mut y = [0u8; 4];
        let (a, b) = (x.as_mut_ptr(), y.as_mut_ptr());
        unsafe { fn_00405658(a, b) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_A.load(Ordering::SeqCst), a as usize);
        assert_eq!(GOT_B.load(Ordering::SeqCst), b as usize);
        assert_eq!(GOT_C.load(Ordering::SeqCst), 1);
    }
}
