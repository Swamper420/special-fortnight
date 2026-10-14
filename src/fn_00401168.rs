//! Original procedure `0x00401168` (6 bytes, `0x00401168–0x0040116d`).
//! Evidence: `evidence/00401168_fn_00401168.md`.

unsafe extern "C" fn default_target(_hkey: usize, _value: *const u16, _reserved: *mut u32, _ty: *mut u32, _data: *mut u8, _cb: *mut u32) -> i32 {
    0
}

/// Import slot `dword ptr [0x00419314]` (`ADVAPI32.DLL::RegQueryValueExW`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00401168: unsafe extern "C" fn(usize, *const u16, *mut u32, *mut u32, *mut u8, *mut u32) -> i32 = default_target;

/// `JMP dword ptr [0x00419314]` — tail-forward with identical args.
pub unsafe fn fn_00401168(hkey: usize, value: *const u16, reserved: *mut u32, ty: *mut u32, data: *mut u8, cb: *mut u32) -> i32 {
    HOOK_00401168(hkey, value, reserved, ty, data, cb)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00401168, fn_00401168};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static HKEY: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(
        h: usize,
        _v: *const u16,
        _r: *mut u32,
        _t: *mut u32,
        _d: *mut u8,
        _c: *mut u32,
    ) -> i32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        HKEY.store(h, Ordering::SeqCst);
        9
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_00401168 = target };
        let r = unsafe {
            fn_00401168(
                0x44,
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(r, 9);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(HKEY.load(Ordering::SeqCst), 0x44);
    }
}
