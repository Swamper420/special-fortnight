//! Original procedure `0x00401178` (6 bytes, `0x00401178–0x0040117d`).
//! Evidence: `evidence/00401178_fn_00401178.md`.

unsafe extern "C" fn default_target(_addr: *const u8, _buf: *mut u8, _len: u32) -> u32 {
    0
}

/// Import slot `dword ptr [0x0041935c]` (`KERNEL32.DLL::VirtualQuery`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00401178: unsafe extern "C" fn(*const u8, *mut u8, u32) -> u32 = default_target;

/// `JMP dword ptr [0x0041935c]` — tail-forward with identical args.
pub unsafe fn fn_00401178(addr: *const u8, buf: *mut u8, len: u32) -> u32 {
    HOOK_00401178(addr, buf, len)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00401178, fn_00401178};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static LEN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(_a: *const u8, _b: *mut u8, n: u32) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        LEN.store(n as usize, Ordering::SeqCst);
        0x1c
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_00401178 = target };
        let r = unsafe {
            fn_00401178(core::ptr::null(), core::ptr::null_mut(), 0x1c)
        };
        assert_eq!(r, 0x1c);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(LEN.load(Ordering::SeqCst), 0x1c);
    }
}
