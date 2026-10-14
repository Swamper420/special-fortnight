//! Original procedure `0x004066d8` (6 bytes, `0x004066d8–0x004066dd`).
//! Evidence: `evidence/004066d8_fn_004066d8.md`.

unsafe extern "C" fn default_target(_name: *const u16, _buf: *mut u16, _size: u32) -> u32 {
    0
}

/// Import slot `dword ptr [0x004194a0]` (`KERNEL32.DLL::GetEnvironmentVariableW`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_004066D8: unsafe extern "C" fn(*const u16, *mut u16, u32) -> u32 = default_target;

/// `JMP dword ptr [0x004194a0]` — tail-forward with identical args.
pub unsafe fn fn_004066d8(name: *const u16, buf: *mut u16, size: u32) -> u32 {
    HOOK_004066D8(name, buf, size)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004066D8, fn_004066d8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(_n: *const u16, _b: *mut u16, s: u32) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(s as usize, Ordering::SeqCst);
        s
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_004066D8 = target };
        let mut buf = [0u16; 4];
        let name = [0x50u16, 0];
        assert_eq!(unsafe { fn_004066d8(name.as_ptr(), buf.as_mut_ptr(), 4) }, 4);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 4);
    }
}
