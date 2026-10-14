//! Original procedure `0x004058d4` (13 bytes, `0x4058d4–0x4058e0`).
//! Evidence: `evidence/004058d4_fn_004058d4.md`.

unsafe extern "C" fn default_first(_a: *mut u8, _b: *mut u8) {}
unsafe extern "C" fn default_second(_a: usize) {}

/// First call `0x405658` (`FUN_00405658`), args `(param_1, param_2)`.
///
/// ponytail: hook standing in for sibling `fn_00405658` (same work
/// package), rewire to real call once modules are declared.
pub static mut HOOK_00405658: unsafe extern "C" fn(*mut u8, *mut u8) = default_first;

/// Second call `0x402e20` (`FUN_00402e20`), arg is the preserved
/// `param_1`.
///
/// ponytail: hook standing in for done `fn_00402e20` (which takes the
/// lane as `u32`); `usize` keeps the host pointer whole, narrow at
/// the real call once address-width unification is decided.
pub static mut HOOK_00402E20: unsafe extern "C" fn(usize) = default_second;

/// `first(p1, p2); second(p1)`; `PUSH EAX` preserves `param_1` across
/// the first call. Params arrive in EAX/EDX per Ghidra `__register`
/// observation.
pub unsafe fn fn_004058d4(param_1: *mut u8, param_2: *mut u8) {
    HOOK_00405658(param_1, param_2);
    HOOK_00402E20(param_1 as usize);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00402E20, HOOK_00405658, fn_004058d4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQ: AtomicUsize = AtomicUsize::new(0);
    static FIRST_AT: AtomicUsize = AtomicUsize::new(0);
    static SECOND_AT: AtomicUsize = AtomicUsize::new(0);
    static GOT_P2: AtomicUsize = AtomicUsize::new(0);
    static GOT_P1B: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn first(a: *mut u8, b: *mut u8) {
        FIRST_AT.store(SEQ.fetch_add(1, Ordering::SeqCst), Ordering::SeqCst);
        GOT_P2.store(b as usize, Ordering::SeqCst);
        let _ = a;
    }

    unsafe extern "C" fn second(a: usize) {
        SECOND_AT.store(SEQ.fetch_add(1, Ordering::SeqCst), Ordering::SeqCst);
        GOT_P1B.store(a, Ordering::SeqCst);
    }

    #[test]
    fn order_and_preserved_param() {
        unsafe {
            HOOK_00405658 = first;
            HOOK_00402E20 = second;
        }
        SEQ.store(0, Ordering::SeqCst);
        let mut x = [0u8; 4];
        let mut y = [0u8; 4];
        let (a, b) = (x.as_mut_ptr(), y.as_mut_ptr());
        unsafe { fn_004058d4(a, b) };
        assert_eq!(FIRST_AT.load(Ordering::SeqCst), 0);
        assert_eq!(SECOND_AT.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_P2.load(Ordering::SeqCst), b as usize);
        assert_eq!(GOT_P1B.load(Ordering::SeqCst), a as usize);
    }
}
