//! Original procedure `0x0040b5d4` (38 bytes, `0x40b5d4–0x40b5f9`).
//! Evidence: `evidence/0040b5d4_fn_0040b5d4.md`.

unsafe extern "C" fn default_scan(_s: usize, _unit: u8) -> i32 {
    0
}

unsafe extern "C" fn default_emit(_a: *mut u8, _b: i32, _c: i32, _d: *mut u8) {}

/// Callee `0x40b4b4` (`FUN_0040b4b4`), called with `(p1, 1)`;
/// returns the base index.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_0040b4b4` once it exists.
pub static mut HOOK_0040B4B4: unsafe extern "C" fn(usize, u8) -> i32 = default_scan;

/// Callee `0x40525c` (`FUN_0040525c`), called with
/// `(p1, r+1, 0x7fffffff, p2)`; shape mirrors done `fn_0040525c`.
///
/// ponytail: hook mirroring done `fn_0040525c`'s shape, rewire to
/// the real call once cross-module test serialization exists (its
/// own test mutates shared hook globals under its own locks).
pub static mut HOOK_0040525C: unsafe extern "C" fn(*mut u8, i32, i32, *mut u8) = default_emit;

/// Test-only serialization for tests sharing this module's globals.
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `emit(p1, scan(p1,1)+1, 0x7fffffff, p2)`. Straight line, void
/// return; `LEA` increment wraps.
pub unsafe fn fn_0040b5d4(param_1: *mut u8, param_2: *mut u8) {
    let i = HOOK_0040B4B4(param_1 as usize, 1);
    HOOK_0040525C(param_1, i.wrapping_add(1), 0x7fffffff, param_2);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040525C, HOOK_0040B4B4, TEST_LOCK, fn_0040b5d4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A: AtomicUsize = AtomicUsize::new(0);
    static B: AtomicUsize = AtomicUsize::new(0);
    static C: AtomicUsize = AtomicUsize::new(0);
    static D: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn scan(_s: usize, _unit: u8) -> i32 {
        5
    }

    unsafe extern "C" fn emit(a: *mut u8, b: i32, c: i32, d: *mut u8) {
        HITS.fetch_add(1, Ordering::SeqCst);
        A.store(a as usize, Ordering::SeqCst);
        B.store(b as usize, Ordering::SeqCst);
        C.store(c as usize, Ordering::SeqCst);
        D.store(d as usize, Ordering::SeqCst);
    }

    #[test]
    fn forward_order() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_0040B4B4 = scan;
            HOOK_0040525C = emit;
        }
        let mut o = 0u8;
        let mut s = 0u8;
        let p1 = &mut o as *mut u8;
        let p2 = &mut s as *mut u8;
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040b5d4(p1, p2) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(A.load(Ordering::SeqCst), p1 as usize);
        assert_eq!(B.load(Ordering::SeqCst), 6);
        assert_eq!(C.load(Ordering::SeqCst), 0x7fff_ffff);
        assert_eq!(D.load(Ordering::SeqCst), p2 as usize);
    }
}
