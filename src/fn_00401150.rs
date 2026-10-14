//! Original procedure `0x00401150` (6 bytes, `0x00401150–0x00401155`).
//! Evidence: `evidence/00401150_fn_00401150.md`.

unsafe extern "C" fn default_target(_code_page: u32, _flags: u32, _mb: *const u8, _cb_mb: i32, _wc: *mut u16, _cch_wc: i32) -> i32 {
    0
}

/// Import slot `dword ptr [0x00419364]` (`KERNEL32.DLL::MultiByteToWideChar`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00401150: unsafe extern "C" fn(u32, u32, *const u8, i32, *mut u16, i32) -> i32 = default_target;

/// `JMP dword ptr [0x00419364]` — tail-forward with identical args.
pub unsafe fn fn_00401150(code_page: u32, flags: u32, mb: *const u8, cb_mb: i32, wc: *mut u16, cch_wc: i32) -> i32 {
    HOOK_00401150(code_page, flags, mb, cb_mb, wc, cch_wc)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00401150, fn_00401150};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static CP: AtomicUsize = AtomicUsize::new(0);
    static CBM: AtomicUsize = AtomicUsize::new(0);
    static CCH: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(
        cp: u32,
        _fl: u32,
        _mb: *const u8,
        cb: i32,
        _wc: *mut u16,
        cch: i32,
    ) -> i32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        CP.store(cp as usize, Ordering::SeqCst);
        CBM.store(cb as usize, Ordering::SeqCst);
        CCH.store(cch as usize, Ordering::SeqCst);
        7
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_00401150 = target };
        let r = unsafe {
            fn_00401150(0x3a4, 0, core::ptr::null(), -1, core::ptr::null_mut(), 9)
        };
        assert_eq!(r, 7);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CP.load(Ordering::SeqCst), 0x3a4);
        assert_eq!(CBM.load(Ordering::SeqCst), -1i32 as usize);
        assert_eq!(CCH.load(Ordering::SeqCst), 9);
    }
}
