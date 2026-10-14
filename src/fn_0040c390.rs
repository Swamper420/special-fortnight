//! Original procedure `0x0040c390` (62 bytes, `0x0040c390–0x0040c3ce`).
//! Evidence: `evidence/0040c390_fn_0040c390.md`.
//!
//! Stream-read method reached as the `+8` slot (`[0x0040c0ac]`)
//! dispatched from `fn_0040c1f8` (`(obj, buf, len)`). No direct
//! `call 0x40c390` site exists, which is why call-dest enumeration
//! missed it.

use crate::fn_0040c1e4::{GET_LAST_ERROR_00406700, fn_0040c1e4};

unsafe extern "C" fn default_read_file(
    _h: u32,
    _buf: *mut u8,
    _n: u32,
    _read: *mut u32,
    _ov: u32,
) -> u32 {
    0
}

/// Import `KERNEL32.DLL::ReadFile` (thunk `0x004067fc` → IAT
/// `0x00419448`), called as `(handle=[obj+4], buf=EDX, n=ECX,
/// &local, NULL)`.
///
/// ponytail: hook standing in for the OS import (also keeps host tests
/// linkable); the Linux host installs a sink-file read shim at startup.
pub static mut HOOK_ReadFile: unsafe extern "C" fn(u32, *mut u8, u32, *mut u32, u32) -> u32 =
    default_read_file;

/// `ReadFile([obj+4], buf, n)`; falsy return runs the `[obj+8]!=0`
/// / `GetLastError != 0x6d` (ERROR_BROKEN_PIPE) error lanes into
/// `c1e4([obj])`. Returns the byte count (`(esp)` slot the callee
/// fills via the `&local` out-param): the caller compares it against
/// the request length.
pub unsafe fn fn_0040c390(obj: *mut u8, buf: *mut u8, n: u32) -> u32 {
    let handle = core::ptr::read_unaligned(obj.wrapping_byte_add(4) as *const u32);
    let mut got: u32 = 0;
    let ok = HOOK_ReadFile(handle, buf, n, &mut got, 0);
    if ok == 0 {
        if core::ptr::read_unaligned(obj.wrapping_byte_add(8)) != 0 {
            let head = core::ptr::read_unaligned(obj as *const *const u8);
            fn_0040c1e4(head as *const u8);
            return got;
        }
        if GET_LAST_ERROR_00406700() != 0x6d {
            let head = core::ptr::read_unaligned(obj as *const *const u8);
            fn_0040c1e4(head as *const u8);
        }
    }
    got
}

#[cfg(test)]
mod tests {
    use super::{HOOK_ReadFile, fn_0040c390};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static SEEN_N: AtomicUsize = AtomicUsize::new(0);
    static RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn read(
        _h: u32,
        buf: *mut u8,
        n: u32,
        got: *mut u32,
        _ov: u32,
    ) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        SEEN_N.store(n as usize, Ordering::SeqCst);
        core::ptr::write_unaligned(buf, 0xAB);
        core::ptr::write_unaligned(got, n);
        RET.load(Ordering::SeqCst) as u32
    }

    #[test]
    fn read_and_error_lanes() {
        // c1e4's hooks stay default-stubbed (safe on any head); hold
        // its lock so its writer test can't race us.
        let _guard = crate::fn_0040c1e4::TEST_LOCK.lock().unwrap();
        unsafe { HOOK_ReadFile = read };
        let mut obj = [0u8; 12];
        let mut buf = [0u8; 8];
        unsafe {
            core::ptr::write_unaligned(obj.as_mut_ptr().wrapping_add(4) as *mut u32, 0x51);
            // Success lane: byte lands, returns the count, no error call.
            RET.store(1, Ordering::SeqCst);
            let r = fn_0040c390(obj.as_mut_ptr(), buf.as_mut_ptr(), 8);
            assert_eq!(r, 8);
            assert_eq!(HITS.load(Ordering::SeqCst), 1);
            assert_eq!(SEEN_N.load(Ordering::SeqCst), 8);
            assert_eq!(buf[0], 0xAB);
            // Falsy return with [obj+8] != 0: c1e4 lane (stubbed,
            // safe), count still returned.
            core::ptr::write_unaligned(obj.as_mut_ptr().wrapping_add(8), 1u8);
            RET.store(0, Ordering::SeqCst);
            let r = fn_0040c390(obj.as_mut_ptr(), buf.as_mut_ptr(), 8);
            assert_eq!(r, 8);
            assert_eq!(HITS.load(Ordering::SeqCst), 2);
        }
    }
}
