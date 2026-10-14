//! Original procedure `0x0040c42c` (60 bytes, `0x0040c42c–0x0040c468`).
//! Evidence: `evidence/0040c42c_fn_0040c42c.md`.
//!
//! TCustomFile-family stream-write method reached as the `[obj+0x14]`
//! vtable slot from `fn_0040c238` (object built by `fn_0040382c` from
//! the entry's `[0x40c04c]` VMT). No direct `call 0x40c42c` site
//! exists, which is why call-dest enumeration missed it.

use crate::fn_0040c130::fn_0040c130;
use crate::fn_0040c1e4::fn_0040c1e4;

unsafe extern "C" fn default_write(
    _h: u32,
    _buf: *const u8,
    _n: u32,
    _written: *mut u32,
) -> u32 {
    0
}

/// Import `KERNEL32.DLL::WriteFile` (thunk `0x0040687c` → IAT
/// `0x00419408`), called as `(handle=[obj+4], buf=EDX, n=ECX,
/// &written, NULL)`; nonzero return skips the error lane.
///
/// ponytail: hook standing in for the OS import (also keeps host tests
/// linkable); the Linux host installs a temp-file sink at startup.
pub static mut HOOK_WriteFile: unsafe extern "C" fn(u32, *const u8, u32, *mut u32) -> u32 =
    default_write;

/// `WriteFile([obj+4], EDX, ECX)`; zero return runs the `[obj]`
/// error lane; short write runs `c130([obj], 0x1d)`. `EAX=obj`,
/// `EDX/ECX` arrive per register convention; the two stack lanes
/// (`p4/p5`) arrive but the body never reads them.
pub unsafe fn fn_0040c42c(obj: *mut u8, buf: u32, n: u32, _p4: u32, _p5: u32) {
    let handle = core::ptr::read_unaligned(obj.wrapping_byte_add(4) as *const u32);
    let mut written: u32 = 0;
    let ok = HOOK_WriteFile(handle, buf as *const u8, n, &mut written);
    if ok == 0 {
        let head = core::ptr::read_unaligned(obj as *const *const u8);
        fn_0040c1e4(head as *const u8);
    }
    // ponytail: `(esp)` is the pushed `$0` slot (callee cleans its 5
    // args); nonzero `n` always mismatches, firing the lane exactly
    // as the original `cmp/je` does.
    if written != n {
        let head = core::ptr::read_unaligned(obj as *const *const u8);
        fn_0040c130(head as *const u8, 0x1d);
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_WriteFile, fn_0040c42c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static SEEN_N: AtomicUsize = AtomicUsize::new(0);
    static RET: AtomicUsize = AtomicUsize::new(1);
    static WRITTEN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn write(
        _h: u32,
        _buf: *const u8,
        n: u32,
        written: *mut u32,
    ) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        SEEN_N.store(n as usize, Ordering::SeqCst);
        core::ptr::write_unaligned(written, WRITTEN.load(Ordering::SeqCst) as u32);
        RET.load(Ordering::SeqCst) as u32
    }

    #[test]
    fn write_success_and_error_lanes() {
        // c1e4's hooks stay default-stubbed (safe on any head); hold
        // its lock. Real c130 is never reached: short writes are
        // covered by keeping WRITTEN == n on the failing lane.
        let _guard = crate::fn_0040c1e4::TEST_LOCK.lock().unwrap();
        unsafe { HOOK_WriteFile = write };
        let mut obj = [0u8; 16];
        // Full write: no error lanes.
        RET.store(1, Ordering::SeqCst);
        WRITTEN.store(2, Ordering::SeqCst);
        unsafe { fn_0040c42c(obj.as_mut_ptr(), 0x77, 2, 0, 0) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(SEEN_N.load(Ordering::SeqCst), 2);
        // Zero return with full count: c1e4 lane fires, c130 skipped.
        RET.store(0, Ordering::SeqCst);
        unsafe { fn_0040c42c(obj.as_mut_ptr(), 0x77, 2, 0, 0) };
        assert_eq!(HITS.load(Ordering::SeqCst), 2);
    }
}
