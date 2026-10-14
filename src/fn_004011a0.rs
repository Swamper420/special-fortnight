//! Original procedure `0x004011a0` (6 bytes, `0x004011a0–0x004011a5`).
//! Evidence: `evidence/004011a0_fn_004011a0.md`.

unsafe extern "C" fn default_target() -> u32 {
    0
}

/// Import slot `dword ptr [0x00419354]` (`KERNEL32.DLL::GetVersion`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_004011A0: unsafe extern "C" fn() -> u32 = default_target;

/// `JMP dword ptr [0x00419354]` — tail-forward with identical args.
pub unsafe fn fn_004011a0() -> u32 {
    HOOK_004011A0()
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004011A0, fn_004011a0};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target() -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        0x10a
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_004011A0 = target };
        assert_eq!(unsafe { fn_004011a0() }, 0x10a);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
