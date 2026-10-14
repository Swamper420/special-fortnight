//! Original procedure `0x004066f0` (6 bytes, `0x004066f0–0x004066f5`).
//! Evidence: `evidence/004066f0_fn_004066f0.md`.

unsafe extern "C" fn default_target(_file: usize, _high: *mut u32) -> u32 {
    0
}

/// Import slot `dword ptr [0x00419494]` (`KERNEL32.DLL::GetFileSize`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_004066F0: unsafe extern "C" fn(usize, *mut u32) -> u32 = default_target;

/// `JMP dword ptr [0x00419494]` — tail-forward with identical args.
pub unsafe fn fn_004066f0(file: usize, high: *mut u32) -> u32 {
    HOOK_004066F0(file, high)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004066F0, fn_004066f0};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(f: usize, _h: *mut u32) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(f, Ordering::SeqCst);
        0x100
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_004066F0 = target };
        let mut high = 0u32;
        assert_eq!(unsafe { fn_004066f0(0xF0, &mut high) }, 0x100);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 0xF0);
    }
}
