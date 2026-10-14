//! Original procedure `0x0040c328` (51 bytes, `0x0040c328–0x0040c359`,
//! `0x0040c35a` padding).
//! Evidence: `evidence/0040c328_fn_0040c328.md`.
//!
//! Stream-position method reached as the `+0` slot (`[0x0040c0a4]`)
//! dispatched from `fn_0040c854`'s getter. No direct `call 0x40c328`
//! site exists, which is why call-dest enumeration missed it.

use crate::fn_0040c1e4::{GET_LAST_ERROR_00406700, fn_0040c1e4};

unsafe extern "C" fn default_set_file_pointer(
    _h: u32,
    _low: u32,
    _high: *mut u32,
    _origin: u32,
) -> u32 {
    0
}

/// Import `KERNEL32.DLL::SetFilePointer` (thunk `0x0040682c` → IAT
/// `0x00419430`), called as `(handle=[stream+4], 0, &out[1], 1)`.
///
/// ponytail: hook standing in for the OS import (also keeps host tests
/// linkable); the Linux host installs a seek shim at startup.
pub static mut HOOK_SetFilePointer: unsafe extern "C" fn(u32, u32, *mut u32, u32) -> u32 =
    default_set_file_pointer;

/// `SetFilePointer([stream+4], 0, &out[1], CURRENT)`; position lands
/// in `out[0]`, high word in `out[1]`. `-1` with a nonzero last
/// error runs `c1e4([stream])`.
pub unsafe fn fn_0040c328(stream: *const u8, out: *mut u32) {
    unsafe { core::ptr::write_unaligned(out.wrapping_add(1), 0) };
    let handle = core::ptr::read_unaligned(stream.wrapping_byte_add(4) as *const u32);
    let pos = HOOK_SetFilePointer(handle, 0, out.wrapping_add(1), 1);
    core::ptr::write_unaligned(out, pos);
    if pos == 0xffff_ffff {
        let err = GET_LAST_ERROR_00406700();
        if err != 0 {
            let head = core::ptr::read_unaligned(stream as *const *const u8);
            fn_0040c1e4(head as *const u8);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_SetFilePointer, fn_0040c328};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static SEEN_ORIGIN: AtomicUsize = AtomicUsize::new(0);
    static RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn seek(h: u32, low: u32, high: *mut u32, origin: u32) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        assert_eq!((h, low, origin), (0x51, 0, 1));
        core::ptr::write_unaligned(high, 0x99);
        RET.load(Ordering::SeqCst) as u32
    }

    #[test]
    fn position_and_error_lanes() {
        // c1e4's hooks stay default-stubbed (safe on any head); hold
        // its lock so its writer test can't race us.
        let _guard = crate::fn_0040c1e4::TEST_LOCK.lock().unwrap();
        unsafe { HOOK_SetFilePointer = seek };
        let mut stream = [0u8; 8];
        let mut out = [0u32; 2];
        unsafe {
            core::ptr::write_unaligned(stream.as_mut_ptr().wrapping_add(4) as *mut u32, 0x51);
            // Success lane: position + high word land.
            RET.store(0x200, Ordering::SeqCst);
            fn_0040c328(stream.as_ptr(), out.as_mut_ptr());
            assert_eq!(HITS.load(Ordering::SeqCst), 1);
            assert_eq!(out, [0x200, 0x99]);
            // -1 lane with stubbed last-error 0: stores land, no call.
            RET.store(0xffff_ffff, Ordering::SeqCst);
            fn_0040c328(stream.as_ptr(), out.as_mut_ptr());
            assert_eq!(HITS.load(Ordering::SeqCst), 2);
            assert_eq!(out, [0xffff_ffff, 0x99]);
        }
    }
}
