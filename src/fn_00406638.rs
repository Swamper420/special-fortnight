//! Original procedure `0x00406638` (6 bytes, `0x00406638–0x0040663d`).
//! Evidence: `evidence/00406638_fn_00406638.md`.

unsafe extern "C" fn default_target(
    _hkey: usize,
    _value: *const u16,
    _reserved: *mut u32,
    _kind: *mut u32,
    _data: *mut u8,
    _len: *mut u32,
) -> u32 {
    0
}

/// Import slot `dword ptr [0x004194e8]` (`ADVAPI32.DLL::RegQueryValueExW`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00406638: unsafe extern "C" fn(usize, *const u16, *mut u32, *mut u32, *mut u8, *mut u32) -> u32 =
    default_target;

/// `JMP dword ptr [0x004194e8]` — tail-forward with identical args.
pub unsafe fn fn_00406638(
    hkey: usize,
    value: *const u16,
    reserved: *mut u32,
    kind: *mut u32,
    data: *mut u8,
    len: *mut u32,
) -> u32 {
    HOOK_00406638(hkey, value, reserved, kind, data, len)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406638, fn_00406638};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(
        h: usize,
        _v: *const u16,
        _r: *mut u32,
        _k: *mut u32,
        _d: *mut u8,
        _l: *mut u32,
    ) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(h, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_00406638 = target };
        let r = unsafe {
            fn_00406638(
                0x33,
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(r, 1);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 0x33);
    }
}
