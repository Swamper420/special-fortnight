//! Original procedure `0x004066c8` (6 bytes, `0x004066c8–0x004066cd`).
//! Evidence: `evidence/004066c8_fn_004066c8.md`.

unsafe extern "C" fn default_target() -> usize {
    0
}

/// Import slot `dword ptr [0x004194a8]` (`KERNEL32.DLL::GetCurrentProcess`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_004066C8: unsafe extern "C" fn() -> usize = default_target;

/// `JMP dword ptr [0x004194a8]` — tail-forward with identical args.
pub unsafe fn fn_004066c8() -> usize {
    HOOK_004066C8()
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004066C8, fn_004066c8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target() -> usize {
        HITS.fetch_add(1, Ordering::SeqCst);
        0xC8
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_004066C8 = target };
        assert_eq!(unsafe { fn_004066c8() }, 0xC8);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
