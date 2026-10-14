//! Original procedure `0x00406680` (6 bytes, `0x00406680–0x00406685`).
//! Evidence: `evidence/00406680_fn_00406680.md`.

unsafe extern "C" fn default_target(
    _flags: u32,
    _source: *const u8,
    _id: u32,
    _lang: u32,
    _buf: *mut u16,
    _size: u32,
    _args: *mut u8,
) -> u32 {
    0
}

/// Import slot `dword ptr [0x004194c0]` (`KERNEL32.DLL::FormatMessageW`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00406680: unsafe extern "C" fn(u32, *const u8, u32, u32, *mut u16, u32, *mut u8) -> u32 =
    default_target;

/// `JMP dword ptr [0x004194c0]` — tail-forward with identical args.
pub unsafe fn fn_00406680(
    flags: u32,
    source: *const u8,
    id: u32,
    lang: u32,
    buf: *mut u16,
    size: u32,
    args: *mut u8,
) -> u32 {
    HOOK_00406680(flags, source, id, lang, buf, size, args)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406680, fn_00406680};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(
        f: u32,
        _s: *const u8,
        _i: u32,
        _l: u32,
        _b: *mut u16,
        _n: u32,
        _a: *mut u8,
    ) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(f as usize, Ordering::SeqCst);
        7
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_00406680 = target };
        let mut buf = [0u16; 8];
        let r = unsafe {
            fn_00406680(
                0x100,
                core::ptr::null(),
                2,
                0,
                buf.as_mut_ptr(),
                8,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(r, 7);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 0x100);
    }
}
