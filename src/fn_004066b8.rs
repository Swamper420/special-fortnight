//! Original procedure `0x004066b8` (6 bytes, `0x004066b8–0x004066bd`).
//! Evidence: `evidence/004066b8_fn_004066b8.md`.

unsafe extern "C" fn default_target(_page: u32, _info: *mut u8) -> u32 {
    0
}

/// Import slot `dword ptr [0x004194b0]` (`KERNEL32.DLL::GetCPInfo`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_004066B8: unsafe extern "C" fn(u32, *mut u8) -> u32 = default_target;

/// `JMP dword ptr [0x004194b0]` — tail-forward with identical args.
pub unsafe fn fn_004066b8(page: u32, info: *mut u8) -> u32 {
    HOOK_004066B8(page, info)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004066B8, fn_004066b8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(p: u32, _i: *mut u8) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(p as usize, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_004066B8 = target };
        let mut info = [0u8; 36];
        assert_eq!(unsafe { fn_004066b8(1, info.as_mut_ptr()) }, 1);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 1);
    }
}
