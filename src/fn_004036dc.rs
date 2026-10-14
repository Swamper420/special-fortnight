//! Original procedure `0x004036dc` (6 bytes, `0x004036dc–0x004036e1`).
//! Evidence: `evidence/004036dc_fn_004036dc.md`.

unsafe extern "C" fn default_target(_flag: i32) -> i32 {
    0
}

/// Import slot `dword ptr [0x00419324]` (`USER32.DLL::GetKeyboardType`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_004036DC: unsafe extern "C" fn(i32) -> i32 = default_target;

/// `JMP dword ptr [0x00419324]` — tail-forward with identical args.
pub unsafe fn fn_004036dc(flag: i32) -> i32 {
    HOOK_004036DC(flag)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004036DC, fn_004036dc};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static FLAG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(flag: i32) -> i32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        FLAG.store(flag as usize, Ordering::SeqCst);
        4
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_004036DC = target };
        assert_eq!(unsafe { fn_004036dc(1) }, 4);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FLAG.load(Ordering::SeqCst), 1);
    }
}
