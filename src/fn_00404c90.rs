//! Original procedure `0x00404c90` (5 bytes, `0x404c90–0x404c94`).
//! Evidence: `evidence/00404c90_fn_00404c90.md`.

unsafe extern "C" fn default_target(_slot: *mut u32, _n: i32) {}

/// Target `0x4046e8` (`FUN_004046e8`), reached by terminal `JMP`.
///
/// ponytail: hook standing in for done `fn_004046e8`, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_004046E8: unsafe extern "C" fn(*mut u32, i32) = default_target;

/// `JMP 0x004046e8` with `(param_1, param_2)` in (EAX, EDX) per
/// Ghidra `__register` observation. Tail jump modeled as call+return.
pub unsafe fn fn_00404c90(param_1: *mut u32, param_2: i32) {
    HOOK_004046E8(param_1, param_2);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004046E8, fn_00404c90};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A: AtomicUsize = AtomicUsize::new(0);
    static B: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(slot: *mut u32, n: i32) {
        A.store(slot as usize, Ordering::SeqCst);
        B.store(n as usize, Ordering::SeqCst);
    }

    #[test]
    fn forwards_pair() {
        unsafe { HOOK_004046E8 = target };
        let mut slot = 0u32;
        let p = &mut slot as *mut u32;
        unsafe { fn_00404c90(p, 3) };
        assert_eq!(A.load(Ordering::SeqCst), p as usize);
        assert_eq!(B.load(Ordering::SeqCst), 3);
    }
}
