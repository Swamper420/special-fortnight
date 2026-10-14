//! Original procedure `0x00401188` (6 bytes, `0x00401188–0x0040118d`).
//! Evidence: `evidence/00401188_fn_00401188.md`.

unsafe extern "C" fn default_target(_pbstr: *mut *mut u16, _src: *const u16, _len: u32) -> i32 {
    0
}

/// Import slot `dword ptr [0x00419308]` (`OLEAUT32.DLL::SysReAllocStringLen`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00401188: unsafe extern "C" fn(*mut *mut u16, *const u16, u32) -> i32 = default_target;

/// `JMP dword ptr [0x00419308]` — tail-forward with identical args.
pub unsafe fn fn_00401188(pbstr: *mut *mut u16, src: *const u16, len: u32) -> i32 {
    HOOK_00401188(pbstr, src, len)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00401188, fn_00401188};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static LEN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(
        _p: *mut *mut u16,
        _s: *const u16,
        n: u32,
    ) -> i32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        LEN.store(n as usize, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_00401188 = target };
        let r = unsafe {
            fn_00401188(core::ptr::null_mut(), core::ptr::null(), 12)
        };
        assert_eq!(r, 1);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(LEN.load(Ordering::SeqCst), 12);
    }
}
