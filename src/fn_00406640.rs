//! Original procedure `0x00406640` (6 bytes, `0x00406640–0x00406645`).
//! Evidence: `evidence/00406640_fn_00406640.md`.

unsafe extern "C" fn default_target(_handle: usize) -> u32 {
    0
}

/// Import slot `dword ptr [0x004194e0]` (`KERNEL32.DLL::CloseHandle`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00406640: unsafe extern "C" fn(usize) -> u32 = default_target;

/// `JMP dword ptr [0x004194e0]` — tail-forward with identical args.
pub unsafe fn fn_00406640(handle: usize) -> u32 {
    HOOK_00406640(handle)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406640, fn_00406640};
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
        unsafe { HOOK_00406640 = target };
        assert_eq!(unsafe { fn_00406640(0x44) }, 1);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 0x44);
    }
}
