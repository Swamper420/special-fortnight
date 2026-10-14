//! Original procedure `0x0040c3d0` (63 bytes, `0x0040c3d0–0x0040c40e`).
//! Evidence: `evidence/0040c3d0_fn_0040c3d0.md`.

unsafe extern "C" fn default_set_ptr(
    _handle: u32,
    _low: i32,
    _high: *mut i32,
    _how: u32,
) -> u32 {
    0
}

unsafe extern "C" fn default_get_err() -> u32 {
    0
}

unsafe extern "C" fn default_report(_first: *const u8) {}

/// Import `KERNEL32.DLL::SetFilePointer` (`CALL 0x0040682c`).
///
/// ponytail: hook standing in for the import (also keeps host tests
/// linkable), rewire to raw `extern "system" SetFilePointer` once
/// Windows-target linkage proven.
pub static mut HOOK_SetFilePointer: unsafe extern "C" fn(u32, i32, *mut i32, u32) -> u32 =
    default_set_ptr;

/// Import `KERNEL32.DLL::GetLastError` (`CALL 0x00406700`).
///
/// ponytail: hook standing in for the import (also keeps host tests
/// linkable), rewire to raw `extern "system" GetLastError` once
/// Windows-target linkage proven.
pub static mut HOOK_GetLastError: unsafe extern "C" fn() -> u32 = default_get_err;

/// Target `0x0040c1e4` (`FUN_0040c1e4`), `(*param_1)` on the
/// failed-with-code lane.
///
/// ponytail: hook standing in for done `fn_0040c1e4`, rewire to the real
/// call once cross-module linkage proven.
pub static mut HOOK_0040C1E4: unsafe extern "C" fn(*const u8) = default_report;

/// `if SetFilePointer(obj[1], off[0], &copy(off[1]), 0)==-1 &&
/// GetLastError()!=0 { report(*obj) }`. `param_1` in EAX, `param_2`
/// in EDX per `__register`. The high word travels as a stack-local
/// copy (`MOVSD ×2`), so import writes never reach caller memory.
pub unsafe fn fn_0040c3d0(param_1: *const u8, param_2: *const i32) {
    let low: i32 = core::ptr::read_unaligned(param_2);
    let mut high: i32 = core::ptr::read_unaligned(param_2.wrapping_add(1));
    // ponytail: second slot via pointer-sized stride (`[param_1+4]`
    // on target; `+8` on a 64-bit host) — see `fn_004063e4`.
    let handle: u32 = core::ptr::read_unaligned(
        (param_1 as usize).wrapping_add(core::mem::size_of::<usize>()) as *const u32
    );
    let r = HOOK_SetFilePointer(handle, low, &mut high, 0);
    if r == 0xffffffff {
        if HOOK_GetLastError() != 0 {
            HOOK_0040C1E4(core::ptr::read_unaligned(param_1 as *const *const u8));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040C1E4, HOOK_GetLastError, HOOK_SetFilePointer, fn_0040c3d0};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static RET: AtomicUsize = AtomicUsize::new(0);
    static ERR: AtomicUsize = AtomicUsize::new(0);
    static SET_HITS: AtomicUsize = AtomicUsize::new(0);
    static SET_HANDLE: AtomicUsize = AtomicUsize::new(0);
    static SET_LOW: AtomicUsize = AtomicUsize::new(0);
    static SET_HIGH_PTR: AtomicUsize = AtomicUsize::new(0);
    static SET_HIGH_VAL: AtomicUsize = AtomicUsize::new(0);
    static SET_HOW: AtomicUsize = AtomicUsize::new(0);
    static ERR_HITS: AtomicUsize = AtomicUsize::new(0);
    static REPORT_HITS: AtomicUsize = AtomicUsize::new(0);
    static REPORT_ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn set_ptr(handle: u32, low: i32, high: *mut i32, how: u32) -> u32 {
        SET_HITS.fetch_add(1, Ordering::SeqCst);
        SET_HANDLE.store(handle as usize, Ordering::SeqCst);
        SET_LOW.store(low as usize, Ordering::SeqCst);
        SET_HIGH_PTR.store(high as usize, Ordering::SeqCst);
        SET_HIGH_VAL.store(*high as usize, Ordering::SeqCst);
        // Scribble proves the import only sees a local copy.
        *high = 0x77;
        SET_HOW.store(how as usize, Ordering::SeqCst);
        RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn get_err() -> u32 {
        ERR_HITS.fetch_add(1, Ordering::SeqCst);
        ERR.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn report(first: *const u8) {
        REPORT_HITS.fetch_add(1, Ordering::SeqCst);
        REPORT_ARG.store(first as usize, Ordering::SeqCst);
    }

    #[test]
    fn seek_lanes() {
        unsafe {
            HOOK_SetFilePointer = set_ptr;
            HOOK_GetLastError = get_err;
            HOOK_0040C1E4 = report;
        }
        let target = 0x1234 as *const u8;
        let mut obj = [target as usize, 0x44usize];
        let p1 = obj.as_mut_ptr() as *const u8;
        let mut off = [0x11i32, 0x22i32];
        let p2 = off.as_mut_ptr() as *const i32;
        // Success lane: no error/report calls, high word copied not aliased.
        RET.store(5, Ordering::SeqCst);
        SET_HITS.store(0, Ordering::SeqCst);
        ERR_HITS.store(0, Ordering::SeqCst);
        REPORT_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040c3d0(p1, p2) };
        assert_eq!(SET_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(SET_HANDLE.load(Ordering::SeqCst), 0x44);
        assert_eq!(SET_LOW.load(Ordering::SeqCst), 0x11);
        assert_eq!(SET_HIGH_VAL.load(Ordering::SeqCst), 0x22);
        assert_eq!(SET_HOW.load(Ordering::SeqCst), 0);
        assert_ne!(
            SET_HIGH_PTR.load(Ordering::SeqCst),
            core::ptr::addr_of!(off[1]) as *const i32 as usize
        );
        assert_eq!(off[1], 0x22);
        assert_eq!(ERR_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(REPORT_HITS.load(Ordering::SeqCst), 0);
        // Fail-without-code lane: error call only.
        RET.store(0xffffffff, Ordering::SeqCst);
        ERR.store(0, Ordering::SeqCst);
        unsafe { fn_0040c3d0(p1, p2) };
        assert_eq!(SET_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(ERR_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REPORT_HITS.load(Ordering::SeqCst), 0);
        // Fail-with-code lane: report fires with *param_1.
        ERR.store(7, Ordering::SeqCst);
        unsafe { fn_0040c3d0(p1, p2) };
        assert_eq!(ERR_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(REPORT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REPORT_ARG.load(Ordering::SeqCst), target as usize);
    }
}
