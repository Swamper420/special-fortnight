//! Original procedure `0x00406658` (6 bytes, `0x00406658–0x0040665d`).
//! Evidence: `evidence/00406658_fn_00406658.md`.

unsafe extern "C" fn default_target(
    _name: *const u16,
    _access: u32,
    _share: u32,
    _attrs: *mut u8,
    _disposition: u32,
    _flags: u32,
    _template: usize,
) -> usize {
    0
}

/// Import slot `dword ptr [0x004194d4]` (`KERNEL32.DLL::CreateFileW`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00406658: unsafe extern "C" fn(*const u16, u32, u32, *mut u8, u32, u32, usize) -> usize =
    default_target;

/// `JMP dword ptr [0x004194d4]` — tail-forward with identical args.
pub unsafe fn fn_00406658(
    name: *const u16,
    access: u32,
    share: u32,
    attrs: *mut u8,
    disposition: u32,
    flags: u32,
    template: usize,
) -> usize {
    HOOK_00406658(name, access, share, attrs, disposition, flags, template)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406658, fn_00406658};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(
        _n: *const u16,
        a: u32,
        _s: u32,
        _t: *mut u8,
        _d: u32,
        _f: u32,
        _h: usize,
    ) -> usize {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(a as usize, Ordering::SeqCst);
        0x58
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_00406658 = target };
        let r = unsafe {
            fn_00406658(
                core::ptr::null(),
                0x80000000,
                0,
                core::ptr::null_mut(),
                3,
                0x80,
                0,
            )
        };
        assert_eq!(r, 0x58);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 0x80000000);
    }
}
