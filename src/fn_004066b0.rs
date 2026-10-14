//! Original procedure `0x004066b0` (6 bytes, `0x004066b0–0x004066b5`).
//! Evidence: `evidence/004066b0_fn_004066b0.md`.

unsafe extern "C" fn default_target(_dst: *mut i32, _val: i32) -> i32 {
    0
}

/// Import slot `dword ptr [0x004194b4]` (`KERNEL32.DLL::InterlockedExchange`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_004066B0: unsafe extern "C" fn(*mut i32, i32) -> i32 = default_target;

/// `JMP dword ptr [0x004194b4]` — tail-forward with identical args.
pub unsafe fn fn_004066b0(dst: *mut i32, val: i32) -> i32 {
    HOOK_004066B0(dst, val)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004066B0, fn_004066b0};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(d: *mut i32, v: i32) -> i32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(v as usize, Ordering::SeqCst);
        unsafe { core::ptr::write_unaligned(d, v) };
        v
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_004066B0 = target };
        let mut v = 0i32;
        let r = unsafe { fn_004066b0(&mut v, 3) };
        assert_eq!(r, 3);
        assert_eq!(v, 3);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 3);
    }
}
