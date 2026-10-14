//! Original procedure `0x00401160` (6 bytes, `0x00401160–0x00401165`).
//! Evidence: `evidence/00401160_fn_00401160.md`.

unsafe extern "C" fn default_target(_hkey: usize, _subkey: *const u16, _options: u32, _sam: u32, _out: *mut usize) -> i32 {
    0
}

/// Import slot `dword ptr [0x00419318]` (`ADVAPI32.DLL::RegOpenKeyExW`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00401160: unsafe extern "C" fn(usize, *const u16, u32, u32, *mut usize) -> i32 = default_target;

/// `JMP dword ptr [0x00419318]` — tail-forward with identical args.
pub unsafe fn fn_00401160(hkey: usize, subkey: *const u16, options: u32, sam: u32, out: *mut usize) -> i32 {
    HOOK_00401160(hkey, subkey, options, sam, out)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00401160, fn_00401160};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static HKEY: AtomicUsize = AtomicUsize::new(0);
    static OPT: AtomicUsize = AtomicUsize::new(0);
    static SAM: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(
        h: usize,
        _sub: *const u16,
        opt: u32,
        sam: u32,
        _out: *mut usize,
    ) -> i32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        HKEY.store(h, Ordering::SeqCst);
        OPT.store(opt as usize, Ordering::SeqCst);
        SAM.store(sam as usize, Ordering::SeqCst);
        5
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_00401160 = target };
        let r = unsafe {
            fn_00401160(
                0x11,
                core::ptr::null(),
                0x22,
                0x33,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(r, 5);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(HKEY.load(Ordering::SeqCst), 0x11);
        assert_eq!(OPT.load(Ordering::SeqCst), 0x22);
        assert_eq!(SAM.load(Ordering::SeqCst), 0x33);
    }
}
