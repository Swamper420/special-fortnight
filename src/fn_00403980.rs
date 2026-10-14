//! Original procedure `0x00403980` (2 bytes, `0x403980–0x403981`).
//! Evidence: `evidence/00403980_fn_00403980.md`.

unsafe extern "C" fn default_target(_a: u32, _b: u32) -> u32 {
    0
}

/// Target `0x403984` (`FUN_00403984`), reached by terminal `JMP`.
///
/// ponytail: hook standing in for unreconstructed target, rewire to
/// real `fn_00403984` once cross-module linkage proven.
pub static mut HOOK_00403984: unsafe extern "C" fn(u32, u32) -> u32 = default_target;

/// `JMP 0x00403984` with `(param_1, param_2)` in (EAX, EDX) per
/// Ghidra `__register` observation. Tail jump modeled as call+return.
pub unsafe fn fn_00403980(param_1: u32, param_2: u32) -> u32 {
    HOOK_00403984(param_1, param_2)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00403984, fn_00403980};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A: AtomicUsize = AtomicUsize::new(0);
    static B: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(a: u32, b: u32) -> u32 {
        A.store(a as usize, Ordering::SeqCst);
        B.store(b as usize, Ordering::SeqCst);
        0xdead
    }

    #[test]
    fn forwards_args_and_return() {
        unsafe { HOOK_00403984 = target };
        assert_eq!(unsafe { fn_00403980(3, 4) }, 0xdead);
        assert_eq!(A.load(Ordering::SeqCst), 3);
        assert_eq!(B.load(Ordering::SeqCst), 4);
    }
}
