//! Original procedure `0x0040c410` (25 bytes, `0x0040c410–0x0040c428`).
//! Evidence: `evidence/0040c410_fn_0040c410.md`.

unsafe extern "C" fn default_set_eof(_handle: u32) -> u32 {
    0
}

unsafe extern "C" fn default_report(_first: *const u8) {}

/// Import `KERNEL32.DLL::SetEndOfFile` (`CALL 0x00406814`).
///
/// ponytail: hook standing in for the import (also keeps host tests
/// linkable), rewire to raw `extern "system" SetEndOfFile` once
/// Windows-target linkage proven.
pub static mut HOOK_SetEndOfFile: unsafe extern "C" fn(u32) -> u32 = default_set_eof;

/// Target `0x0040c1e4` (`FUN_0040c1e4`), `(*param_1)` on the zero lane.
///
/// ponytail: hook standing in for done `fn_0040c1e4`, rewire to the real
/// call once cross-module linkage proven.
pub static mut HOOK_0040C1E4: unsafe extern "C" fn(*const u8) = default_report;

/// `if SetEndOfFile(obj[1])==0 { report(*obj) }`. `param_1` in EAX
/// per `__register`. Zero (`TEST/JNZ`) is the failure lane.
pub unsafe fn fn_0040c410(param_1: *const u8) {
    // ponytail: second slot via pointer-sized stride (`[param_1+4]`
    // on target; `+8` on a 64-bit host) — see `fn_004063e4`.
    let handle: u32 = core::ptr::read_unaligned(
        (param_1 as usize).wrapping_add(core::mem::size_of::<usize>()) as *const u32
    );
    if HOOK_SetEndOfFile(handle) == 0 {
        HOOK_0040C1E4(core::ptr::read_unaligned(param_1 as *const *const u8));
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040C1E4, HOOK_SetEndOfFile, fn_0040c410};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static RET: AtomicUsize = AtomicUsize::new(0);
    static EOF_HITS: AtomicUsize = AtomicUsize::new(0);
    static EOF_HANDLE: AtomicUsize = AtomicUsize::new(0);
    static REPORT_HITS: AtomicUsize = AtomicUsize::new(0);
    static REPORT_ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn set_eof(handle: u32) -> u32 {
        EOF_HITS.fetch_add(1, Ordering::SeqCst);
        EOF_HANDLE.store(handle as usize, Ordering::SeqCst);
        RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn report(first: *const u8) {
        REPORT_HITS.fetch_add(1, Ordering::SeqCst);
        REPORT_ARG.store(first as usize, Ordering::SeqCst);
    }

    #[test]
    fn truncate_lanes() {
        unsafe {
            HOOK_SetEndOfFile = set_eof;
            HOOK_0040C1E4 = report;
        }
        let target = 0x1234 as *const u8;
        let mut obj = [target as usize, 0x55usize];
        let p = obj.as_mut_ptr() as *const u8;
        // Success lane: nonzero, no report.
        RET.store(1, Ordering::SeqCst);
        EOF_HITS.store(0, Ordering::SeqCst);
        REPORT_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040c410(p) };
        assert_eq!(EOF_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(EOF_HANDLE.load(Ordering::SeqCst), 0x55);
        assert_eq!(REPORT_HITS.load(Ordering::SeqCst), 0);
        // Failure lane: zero, report fires with *param_1.
        RET.store(0, Ordering::SeqCst);
        unsafe { fn_0040c410(p) };
        assert_eq!(EOF_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(REPORT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REPORT_ARG.load(Ordering::SeqCst), target as usize);
    }
}
