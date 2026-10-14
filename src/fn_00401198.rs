//! Original procedure `0x00401198` (6 bytes, `0x00401198–0x0040119d`).
//! Evidence: `evidence/00401198_fn_00401198.md`.

unsafe extern "C" fn default_target() -> u32 {
    0
}

/// Import slot `dword ptr [0x00419358]` (`KERNEL32.DLL::GetCurrentThreadId`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00401198: unsafe extern "C" fn() -> u32 = default_target;

/// `JMP dword ptr [0x00419358]` — tail-forward with identical args.
pub unsafe fn fn_00401198() -> u32 {
    HOOK_00401198()
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00401198, fn_00401198};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target() -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        0x1234
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_00401198 = target };
        assert_eq!(unsafe { fn_00401198() }, 0x1234);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
