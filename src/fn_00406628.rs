//! Original procedure `0x00406628` (6 bytes, `0x00406628–0x0040662d`).
//! Evidence: `evidence/00406628_fn_00406628.md`.

unsafe extern "C" fn default_target(_hkey: usize) -> u32 {
    0
}

/// Import slot `dword ptr [0x004194f0]` (`ADVAPI32.DLL::RegCloseKey`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00406628: unsafe extern "C" fn(usize) -> u32 = default_target;

/// `JMP dword ptr [0x004194f0]` — tail-forward with identical args.
pub unsafe fn fn_00406628(hkey: usize) -> u32 {
    HOOK_00406628(hkey)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406628, fn_00406628};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(h: usize) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(h, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_00406628 = target };
        assert_eq!(unsafe { fn_00406628(0x11) }, 1);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 0x11);
    }
}
