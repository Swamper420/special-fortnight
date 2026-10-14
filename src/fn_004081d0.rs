//! Original procedure `0x004081d0` (2 bytes, `0x4081d0–0x4081d1`).
//! Evidence: `evidence/004081d0_fn_004081d0.md`.

unsafe extern "C" fn default_target(_s: *const u16, _ch: u16) -> *const u16 {
    core::ptr::null()
}

/// Target `0x4081dd` (`FUN_004081dd`), reached by terminal `JMP`.
///
/// ponytail: hook standing in for unreconstructed target, rewire to
/// real `fn_004081dd` once cross-module linkage proven.
pub static mut HOOK_004081DD: unsafe extern "C" fn(*const u16, u16) -> *const u16 =
    default_target;

/// `JMP 0x004081dd` with `(param_1, param_2)` in (EAX, DX) per
/// Ghidra `__register` observation. Tail jump modeled as call+return.
pub unsafe fn fn_004081d0(param_1: *const u16, param_2: u16) -> *const u16 {
    HOOK_004081DD(param_1, param_2)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004081DD, fn_004081d0};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A: AtomicUsize = AtomicUsize::new(0);
    static B: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(s: *const u16, ch: u16) -> *const u16 {
        A.store(s as usize, Ordering::SeqCst);
        B.store(ch as usize, Ordering::SeqCst);
        s
    }

    #[test]
    fn forwards_pair_and_echoes() {
        unsafe { HOOK_004081DD = target };
        let s = [0x61u16, 0x0];
        assert_eq!(unsafe { fn_004081d0(s.as_ptr(), 0x61) }, s.as_ptr());
        assert_eq!(A.load(Ordering::SeqCst), s.as_ptr() as usize);
        assert_eq!(B.load(Ordering::SeqCst), 0x61);
    }
}
