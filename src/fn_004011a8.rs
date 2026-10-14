//! Original procedure `0x004011a8` (6 bytes, `0x004011a8–0x004011ad`).
//! Evidence: `evidence/004011a8_fn_004011a8.md`.

unsafe extern "C" fn default_target(_counter: *mut i64) -> i32 {
    0
}

/// Import slot `dword ptr [0x00419350]` (`KERNEL32.DLL::QueryPerformanceCounter`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_004011A8: unsafe extern "C" fn(*mut i64) -> i32 = default_target;

/// `JMP dword ptr [0x00419350]` — tail-forward with identical args.
pub unsafe fn fn_004011a8(counter: *mut i64) -> i32 {
    HOOK_004011A8(counter)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004011A8, fn_004011a8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(c: *mut i64) -> i32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(c as usize, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_004011A8 = target };
        let mut q: i64 = 0;
        let r = unsafe { fn_004011a8(&mut q) };
        assert_eq!(r, 1);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), &q as *const i64 as usize);
    }
}
