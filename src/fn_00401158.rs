//! Original procedure `0x00401158` (6 bytes, `0x00401158–0x0040115d`).
//! Evidence: `evidence/00401158_fn_00401158.md`.

unsafe extern "C" fn default_target(_hkey: usize) -> i32 {
    0
}

/// Import slot `dword ptr [0x0041931c]` (`ADVAPI32.DLL::RegCloseKey`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00401158: unsafe extern "C" fn(usize) -> i32 = default_target;

/// `JMP dword ptr [0x0041931c]` — tail-forward with identical args.
pub unsafe fn fn_00401158(hkey: usize) -> i32 {
    HOOK_00401158(hkey)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00401158, fn_00401158};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(h: usize) -> i32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(h, Ordering::SeqCst);
        3
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_00401158 = target };
        let r = unsafe { fn_00401158(0x9c) };
        assert_eq!(r, 3);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 0x9c);
    }
}
