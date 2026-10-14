//! Original procedure `0x004011b0` (6 bytes, `0x004011b0–0x004011b5`).
//! Evidence: `evidence/004011b0_fn_004011b0.md`.

unsafe extern "C" fn default_target() -> u32 {
    0
}

/// Import slot `dword ptr [0x0041934c]` (`KERNEL32.DLL::GetTickCount`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_004011B0: unsafe extern "C" fn() -> u32 = default_target;

/// `JMP dword ptr [0x0041934c]` — tail-forward with identical args.
pub unsafe fn fn_004011b0() -> u32 {
    HOOK_004011B0()
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004011B0, fn_004011b0};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target() -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        0xabcd
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_004011B0 = target };
        assert_eq!(unsafe { fn_004011b0() }, 0xabcd);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
