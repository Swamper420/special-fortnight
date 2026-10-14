//! Original procedure `0x00401170` (6 bytes, `0x00401170–0x00401175`).
//! Evidence: `evidence/00401170_fn_00401170.md`.

unsafe extern "C" fn default_target(_code_page: u32, _flags: u32, _wc: *const u16, _cch_wc: i32, _mb: *mut u8, _cb_mb: i32, _default_char: *const u8, _used: *mut i32) -> i32 {
    0
}

/// Import slot `dword ptr [0x00419360]` (`KERNEL32.DLL::WideCharToMultiByte`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00401170: unsafe extern "C" fn(u32, u32, *const u16, i32, *mut u8, i32, *const u8, *mut i32) -> i32 = default_target;

/// `JMP dword ptr [0x00419360]` — tail-forward with identical args.
pub unsafe fn fn_00401170(code_page: u32, flags: u32, wc: *const u16, cch_wc: i32, mb: *mut u8, cb_mb: i32, default_char: *const u8, used: *mut i32) -> i32 {
    HOOK_00401170(code_page, flags, wc, cch_wc, mb, cb_mb, default_char, used)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00401170, fn_00401170};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static CP: AtomicUsize = AtomicUsize::new(0);
    static CCH: AtomicUsize = AtomicUsize::new(0);
    static CBM: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(
        cp: u32,
        _fl: u32,
        _wc: *const u16,
        cch: i32,
        _mb: *mut u8,
        cb: i32,
        _d: *const u8,
        _u: *mut i32,
    ) -> i32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        CP.store(cp as usize, Ordering::SeqCst);
        CCH.store(cch as usize, Ordering::SeqCst);
        CBM.store(cb as usize, Ordering::SeqCst);
        11
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_00401170 = target };
        let r = unsafe {
            fn_00401170(
                0xfde9,
                0,
                core::ptr::null(),
                4,
                core::ptr::null_mut(),
                8,
                core::ptr::null(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(r, 11);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CP.load(Ordering::SeqCst), 0xfde9);
        assert_eq!(CCH.load(Ordering::SeqCst), 4);
        assert_eq!(CBM.load(Ordering::SeqCst), 8);
    }
}
