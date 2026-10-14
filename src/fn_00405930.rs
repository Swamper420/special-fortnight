//! Original procedure `0x00405930` (5 bytes, `0x00405930–0x00405934`).
//! Evidence: `evidence/00405930_fn_00405930.md`.

unsafe extern "C" fn default_target(
    _slot: *mut u32,
    _fmt: *const u8,
    _n: i32,
) -> *mut u32 {
    core::ptr::null_mut()
}

/// Target `0x00405548` (`FUN_00405548`), reached by terminal `JMP`.
///
/// ponytail: hook standing in for unreconstructed target, rewire to
/// real `fn_00405548` once cross-module linkage proven.
pub static mut HOOK_00405548: unsafe extern "C" fn(*mut u32, *const u8, i32) -> *mut u32 =
    default_target;

/// `JMP 0x00405548` with `(param_1, param_2, param_3)` in
/// (EAX, EDX, ECX) per Ghidra `__register` observation. Tail jump
/// modeled as call+return.
pub unsafe fn fn_00405930(param_1: *mut u32, param_2: *const u8, param_3: i32) -> *mut u32 {
    HOOK_00405548(param_1, param_2, param_3)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00405548, fn_00405930};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A: AtomicUsize = AtomicUsize::new(0);
    static B: AtomicUsize = AtomicUsize::new(0);
    static C: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(slot: *mut u32, fmt: *const u8, n: i32) -> *mut u32 {
        A.store(slot as usize, Ordering::SeqCst);
        B.store(fmt as usize, Ordering::SeqCst);
        C.store(n as usize, Ordering::SeqCst);
        slot
    }

    #[test]
    fn forwards_triple_and_echoes() {
        unsafe { HOOK_00405548 = target };
        let mut slot = 0u32;
        let p = &mut slot as *mut u32;
        let fmt = b"\x11\0".as_ptr();
        assert_eq!(unsafe { fn_00405930(p, fmt, 2) }, p);
        assert_eq!(A.load(Ordering::SeqCst), p as usize);
        assert_eq!(B.load(Ordering::SeqCst), fmt as usize);
        assert_eq!(C.load(Ordering::SeqCst), 2);
    }
}
