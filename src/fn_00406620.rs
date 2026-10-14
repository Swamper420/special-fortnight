//! Original procedure `0x00406620` (6 bytes, `0x00406620–0x00406625`).
//! Evidence: `evidence/00406620_fn_00406620.md`.

unsafe extern "C" fn default_target(
    _process_handle: usize,
    _desired_access: u32,
    _token_handle: *mut usize,
) -> u32 {
    0
}

/// Import slot `dword ptr [0x004194f4]` (`ADVAPI32.DLL::OpenProcessToken`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00406620: unsafe extern "C" fn(usize, u32, *mut usize) -> u32 = default_target;

/// `JMP dword ptr [0x004194f4]` — tail-forward with identical args.
pub unsafe fn fn_00406620(
    process_handle: usize,
    desired_access: u32,
    token_handle: *mut usize,
) -> u32 {
    HOOK_00406620(process_handle, desired_access, token_handle)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406620, fn_00406620};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(h: usize, _d: u32, _t: *mut usize) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(h, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_00406620 = target };
        let r = unsafe { fn_00406620(0x44, 0x8, core::ptr::null_mut()) };
        assert_eq!(r, 1);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 0x44);
    }
}
