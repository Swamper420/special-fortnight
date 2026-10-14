//! Original procedure `0x00406630` (6 bytes, `0x00406630–0x00406635`).
//! Evidence: `evidence/00406630_fn_00406630.md`.

unsafe extern "C" fn default_target(
    _hkey: usize,
    _sub_key: *const u16,
    _options: u32,
    _sam: u32,
    _result: *mut usize,
) -> u32 {
    0
}

/// Import slot `dword ptr [0x004194ec]` (`ADVAPI32.DLL::RegOpenKeyExW`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00406630: unsafe extern "C" fn(usize, *const u16, u32, u32, *mut usize) -> u32 =
    default_target;

/// `JMP dword ptr [0x004194ec]` — tail-forward with identical args.
pub unsafe fn fn_00406630(
    hkey: usize,
    sub_key: *const u16,
    options: u32,
    sam: u32,
    result: *mut usize,
) -> u32 {
    HOOK_00406630(hkey, sub_key, options, sam, result)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406630, fn_00406630};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(h: usize, _s: *const u16, _o: u32, _m: u32, _r: *mut usize) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(h, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_00406630 = target };
        let r = unsafe { fn_00406630(0x22, core::ptr::null(), 0, 0x20019, core::ptr::null_mut()) };
        assert_eq!(r, 1);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 0x22);
    }
}
