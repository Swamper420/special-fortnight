//! Original procedure `0x0040c360` (40 bytes, `0x0040c360–0x0040c387`,
//! `0x0040c38d` padding).
//! Evidence: `evidence/0040c360_fn_0040c360.md`.
//!
//! Stream-size method reached as the `+4` slot (`[0x0040c0a8]`)
//! dispatched from the entry's stream reads (`fn_0040c238` callers
//! pass `(stream, buf, 8)`; the body takes `(EAX=stream, EDX=buf)`).
//! No direct `call 0x40c360` site exists, which is why call-dest
//! enumeration missed it.

use crate::fn_0040c1e4::{GET_LAST_ERROR_00406700, fn_0040c1e4};

unsafe extern "C" fn default_get_file_size(_h: u32, _high: *mut u32) -> u32 {
    0
}

/// Import `KERNEL32.DLL::GetFileSize` (thunk `0x004066f0` → IAT
/// `0x00419494`), called as `(handle=[stream+4], &(buf[1]))`; low
/// dword returns in EAX, stored to `buf[0]`.
///
/// ponytail: hook standing in for the OS import (also keeps host tests
/// linkable); the Linux host installs a file-size shim at startup.
pub static mut HOOK_GetFileSize: unsafe extern "C" fn(u32, *mut u32) -> u32 =
    default_get_file_size;

/// `size=GetFileSize([stream+4], &buf[1]); buf[0]=size;` `-1` runs
/// the `GetLastError`/`c1e4([stream])` lane. The `n` lane of the
/// entry's `(stream, buf, 8)` call shape is unread by the body.
pub unsafe fn fn_0040c360(stream: *const u8, buf: *mut u32) {
    let handle = core::ptr::read_unaligned(stream.wrapping_byte_add(4) as *const u32);
    let mut high: u32 = 0;
    let low = HOOK_GetFileSize(handle, &mut high);
    core::ptr::write_unaligned(buf, low);
    core::ptr::write_unaligned(buf.wrapping_add(1), high);
    if low == 0xffff_ffff {
        let err = GET_LAST_ERROR_00406700();
        if err != 0 {
            let head = core::ptr::read_unaligned(stream as *const *const u8);
            fn_0040c1e4(head as *const u8);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_GetFileSize, fn_0040c360};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static SEEN_H: AtomicUsize = AtomicUsize::new(0);
    static LOW: AtomicUsize = AtomicUsize::new(0);
    static HIGH: AtomicUsize = AtomicUsize::new(0xdead);

    unsafe extern "C" fn get_size(h: u32, high: *mut u32) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        SEEN_H.store(h as usize, Ordering::SeqCst);
        core::ptr::write_unaligned(high, HIGH.load(Ordering::SeqCst) as u32);
        LOW.load(Ordering::SeqCst) as u32
    }

    #[test]
    fn size_and_error_lanes() {
        // c1e4's hooks stay default-stubbed (safe on any head); hold
        // its lock so its writer test can't race us.
        let _guard = crate::fn_0040c1e4::TEST_LOCK.lock().unwrap();
        unsafe { HOOK_GetFileSize = get_size };
        let mut stream = [0u8; 8];
        let mut buf = [0u32; 2];
        unsafe {
            // Handle lane: [stream+4] forwarded, low/high stored.
            core::ptr::write_unaligned(stream.as_mut_ptr().wrapping_add(4) as *mut u32, 0x51);
            LOW.store(0x1122, Ordering::SeqCst);
            HIGH.store(0x3344, Ordering::SeqCst);
            fn_0040c360(stream.as_ptr(), buf.as_mut_ptr());
            assert_eq!(HITS.load(Ordering::SeqCst), 1);
            assert_eq!(SEEN_H.load(Ordering::SeqCst), 0x51);
            assert_eq!(buf, [0x1122, 0x3344]);
            // -1 lane with stubbed last-error 0: no c1e4 call (would
            // need a valid head otherwise); stores still land.
            LOW.store(0xffff_ffff, Ordering::SeqCst);
            HIGH.store(0x77, Ordering::SeqCst);
            fn_0040c360(stream.as_ptr(), buf.as_mut_ptr());
            assert_eq!(HITS.load(Ordering::SeqCst), 2);
            assert_eq!(buf, [0xffff_ffff, 0x77]);
        }
    }
}
