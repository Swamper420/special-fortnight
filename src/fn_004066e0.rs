//! Original procedure `0x004066e0` (6 bytes, `0x004066e0–0x004066e5`).
//! Evidence: `evidence/004066e0_fn_004066e0.md`.

unsafe extern "C" fn default_target(_process: usize, _code: *mut u32) -> u32 {
    0
}

/// Import slot `dword ptr [0x0041949c]` (`KERNEL32.DLL::GetExitCodeProcess`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_004066E0: unsafe extern "C" fn(usize, *mut u32) -> u32 = default_target;

/// `JMP dword ptr [0x0041949c]` — tail-forward with identical args.
pub unsafe fn fn_004066e0(process: usize, code: *mut u32) -> u32 {
    HOOK_004066E0(process, code)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004066E0, fn_004066e0};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(p: usize, _c: *mut u32) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(p, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_004066E0 = target };
        let mut code = 0u32;
        assert_eq!(unsafe { fn_004066e0(0xE0, &mut code) }, 1);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 0xE0);
    }
}
