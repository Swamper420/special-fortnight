//! Original procedure `0x00406688` (6 bytes, `0x00406688–0x0040668d`).
//! Evidence: `evidence/00406688_fn_00406688.md`.

unsafe extern "C" fn default_target(_module: usize) -> u32 {
    0
}

/// Import slot `dword ptr [0x004194bc]` (`KERNEL32.DLL::FreeLibrary`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00406688: unsafe extern "C" fn(usize) -> u32 = default_target;

/// `JMP dword ptr [0x004194bc]` — tail-forward with identical args.
pub unsafe fn fn_00406688(module: usize) -> u32 {
    HOOK_00406688(module)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406688, fn_00406688};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(m: usize) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(m, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_00406688 = target };
        assert_eq!(unsafe { fn_00406688(0x88) }, 1);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 0x88);
    }
}
