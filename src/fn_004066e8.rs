//! Original procedure `0x004066e8` (6 bytes, `0x004066e8–0x004066ed`).
//! Evidence: `evidence/004066e8_fn_004066e8.md`.

unsafe extern "C" fn default_target(_name: *const u16) -> u32 {
    0
}

/// Import slot `dword ptr [0x00419498]` (`KERNEL32.DLL::GetFileAttributesW`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_004066E8: unsafe extern "C" fn(*const u16) -> u32 = default_target;

/// `JMP dword ptr [0x00419498]` — tail-forward with identical args.
pub unsafe fn fn_004066e8(name: *const u16) -> u32 {
    HOOK_004066E8(name)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004066E8, fn_004066e8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(n: *const u16) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(n as usize, Ordering::SeqCst);
        0x80
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_004066E8 = target };
        let name = [0x41u16, 0];
        assert_eq!(unsafe { fn_004066e8(name.as_ptr()) }, 0x80);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), name.as_ptr() as usize);
    }
}
