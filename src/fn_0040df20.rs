//! Original procedure `0x0040df20` (33 bytes, `0x40df20–0x40df40`).
//! Evidence: `evidence/0040df20_fn_0040df20.md`.

unsafe extern "C" fn default_def0(_p1: u32, _p2: *mut u32, _p3: i32, _o: *mut u8) {}

/// Target `0x40def0` (`FUN_0040def0`).
///
/// ponytail: hook standing in for same-batch `fn_0040def0`.
pub static mut HOOK_0040DEF0: unsafe extern "C" fn(u32, *mut u32, i32, *mut u8) = default_def0;

/// Spill `param_2` to stack slot, forward slot address + 0.
/// `param_1` EAX / `param_2` EDX / `param_3` ECX per `__register` observation.
pub unsafe fn fn_0040df20(param_1: u32, param_2: u32, param_3: *mut u8) {
    // ponytail: slot address is pointer-sized (EDX in target); `*mut u32` keeps host width.
    let mut slot = param_2;
    HOOK_0040DEF0(param_1, &mut slot, 0, param_3);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040DEF0, fn_0040df20};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static P1: AtomicUsize = AtomicUsize::new(0);
    static P3: AtomicUsize = AtomicUsize::new(0);
    static VAL: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn def0(p1: u32, p2: *mut u32, p3: i32, _o: *mut u8) {
        P1.store(p1 as usize, Ordering::SeqCst);
        P3.store(p3 as usize, Ordering::SeqCst);
        VAL.store(core::ptr::read_unaligned(p2) as usize, Ordering::SeqCst);
    }

    #[test]
    fn spill_and_zero_forward() {
        unsafe { HOOK_0040DEF0 = def0 };
        unsafe { fn_0040df20(0x36, 0xDEAD, core::ptr::null_mut()) };
        assert_eq!(P1.load(Ordering::SeqCst), 0x36);
        assert_eq!(P3.load(Ordering::SeqCst), 0);
        assert_eq!(VAL.load(Ordering::SeqCst), 0xDEAD);
    }
}
