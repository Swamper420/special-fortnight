//! Original procedure `0x00406690` (6 bytes, `0x00406690–0x00406695`).
//! Evidence: `evidence/00406690_fn_00406690.md`.

unsafe extern "C" fn default_target(_dst: *mut i32, _ex: i32, _cmp: i32) -> i32 {
    0
}

/// Import slot `dword ptr [0x004194b8]` (`KERNEL32.DLL::InterlockedCompareExchange`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00406690: unsafe extern "C" fn(*mut i32, i32, i32) -> i32 = default_target;

/// `JMP dword ptr [0x004194b8]` — tail-forward with identical args.
pub unsafe fn fn_00406690(dst: *mut i32, ex: i32, cmp: i32) -> i32 {
    HOOK_00406690(dst, ex, cmp)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406690, fn_00406690};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(d: *mut i32, e: i32, _c: i32) -> i32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(e as usize, Ordering::SeqCst);
        unsafe { core::ptr::write_unaligned(d, e) };
        e
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_00406690 = target };
        let mut v = 0i32;
        let r = unsafe { fn_00406690(&mut v, 5, 0) };
        assert_eq!(r, 5);
        assert_eq!(v, 5);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 5);
    }
}
