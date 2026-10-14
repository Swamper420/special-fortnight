//! Original procedure `0x004011b8` (6 bytes, `0x004011b8–0x004011bd`).
//! Evidence: `evidence/004011b8_fn_004011b8.md`.

unsafe extern "C" fn default_target(_info: *mut u8) {}

/// Import slot `dword ptr [0x00419348]` (`KERNEL32.DLL::GetSystemInfo`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_004011B8: unsafe extern "C" fn(*mut u8) = default_target;

/// `JMP dword ptr [0x00419348]` — tail-forward with identical args.
pub unsafe fn fn_004011b8(info: *mut u8) {
    HOOK_004011B8(info);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004011B8, fn_004011b8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(info: *mut u8) {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(info as usize, Ordering::SeqCst);
    }

    #[test]
    fn forwards() {
        unsafe { HOOK_004011B8 = target };
        let mut buf = [0u8; 36];
        unsafe { fn_004011b8(buf.as_mut_ptr()) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), buf.as_mut_ptr() as usize);
    }
}
