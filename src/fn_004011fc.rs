//! Original procedure `0x004011fc` (6 bytes, `0x004011fc–0x00401201`).
//! Evidence: `evidence/004011fc_fn_004011fc.md`.

unsafe extern "C" fn default_target(_ms: u32) {}

/// Import slot `dword ptr [0x0041933c]` (`KERNEL32.DLL::Sleep`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_004011FC: unsafe extern "C" fn(u32) = default_target;

/// `JMP dword ptr [0x0041933c]` — tail-forward with identical args.
pub unsafe fn fn_004011fc(ms: u32) {
    HOOK_004011FC(ms);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004011FC, fn_004011fc};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static MS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(ms: u32) {
        HITS.fetch_add(1, Ordering::SeqCst);
        MS.store(ms as usize, Ordering::SeqCst);
    }

    #[test]
    fn forwards() {
        unsafe { HOOK_004011FC = target };
        unsafe { fn_004011fc(50) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(MS.load(Ordering::SeqCst), 50);
    }
}
