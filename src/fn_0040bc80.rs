//! Original procedure `0x0040bc80` (10 bytes, `0x0040bc80–0x0040bc89`).
//! Evidence: `evidence/0040bc80_fn_0040bc80.md`.

unsafe extern "C" fn default_bb34(
    _h: u32,
    _s: *const u16,
    _o: *mut u32,
    _a: u32,
    _b: u32,
) {
}

/// Target `0x0040bb34` (`FUN_0040bb34`), called with
/// `(param_1, param_2, param_3, 2, 1)`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_0040bb34` once it exists.
pub static mut HOOK_0040BB34: unsafe extern "C" fn(u32, *const u16, *mut u32, u32, u32) =
    default_bb34;

/// `bb34(p1, p2, p3, 2, 1)`. Params arrive in EAX/EDX/ECX per
/// Ghidra `__register` observation (`PUSH 1; PUSH 2; CALL; RET`).
pub unsafe fn fn_0040bc80(param_1: u32, param_2: *const u16, param_3: *mut u32) {
    HOOK_0040BB34(param_1, param_2, param_3, 2, 1);
}

/// Test-only serialization for tests sharing the lane hook.
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::{HOOK_0040BB34, fn_0040bc80};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);
    static A3: AtomicUsize = AtomicUsize::new(0);
    static A4: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn bb34(h: u32, s: *const u16, o: *mut u32, a: u32, b: u32) {
        HITS.fetch_add(1, Ordering::SeqCst);
        A0.store(h as usize, Ordering::SeqCst);
        A1.store(s as usize, Ordering::SeqCst);
        A2.store(o as usize, Ordering::SeqCst);
        A3.store(a as usize, Ordering::SeqCst);
        A4.store(b as usize, Ordering::SeqCst);
    }

    #[test]
    fn forwards_with_const_tail() {
        // Own hook only: hold the owner lock so the rewired
        // `fn_0040bcb4` test (which pins this hook behind the real
        // call) can't race us.
        let _guard = super::TEST_LOCK.lock().unwrap();
        unsafe { HOOK_0040BB34 = bb34 };
        let sub = [0x41u16, 0];
        let mut out = 0u32;
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040bc80(0x8000_0002, sub.as_ptr(), &mut out) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(A0.load(Ordering::SeqCst), 0x8000_0002);
        assert_eq!(A1.load(Ordering::SeqCst), sub.as_ptr() as usize);
        assert_eq!(A2.load(Ordering::SeqCst), &out as *const u32 as usize);
        assert_eq!(A3.load(Ordering::SeqCst), 2);
        assert_eq!(A4.load(Ordering::SeqCst), 1);
    }
}
