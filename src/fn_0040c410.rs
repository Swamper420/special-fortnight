//! Original procedure `0x0040c410` (25 bytes, `0x0040c410–0x0040c428`).
//! Evidence: `evidence/0040c410_fn_0040c410.md`.

unsafe extern "C" fn default_set_eof(_handle: u32) -> u32 {
    0
}

/// Import `KERNEL32.DLL::SetEndOfFile` (`CALL 0x00406814`).
///
/// ponytail: hook standing in for the import (also keeps host tests
/// linkable), rewire to raw `extern "system" SetEndOfFile` once
/// Windows-target linkage proven.
pub static mut HOOK_SetEndOfFile: unsafe extern "C" fn(u32) -> u32 = default_set_eof;

/// Target `0x0040c1e4` (`FUN_0040c1e4`), `(*param_1)` on the zero lane:
/// direct intra-reconstruction call (rewired; signatures verified
/// `fn(*const u8)`).

/// `if SetEndOfFile(obj[1])==0 { report(*obj) }`. `param_1` in EAX
/// per `__register`. Zero (`TEST/JNZ`) is the failure lane.
pub unsafe fn fn_0040c410(param_1: *const u8) {
    // ponytail: second slot via pointer-sized stride (`[param_1+4]`
    // on target; `+8` on a 64-bit host) — see `fn_004063e4`.
    let handle: u32 = core::ptr::read_unaligned(
        (param_1 as usize).wrapping_add(core::mem::size_of::<usize>()) as *const u32
    );
    if HOOK_SetEndOfFile(handle) == 0 {
        crate::fn_0040c1e4::fn_0040c1e4(core::ptr::read_unaligned(param_1 as *const *const u8));
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_SetEndOfFile, fn_0040c410};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static RET: AtomicUsize = AtomicUsize::new(0);
    static EOF_HITS: AtomicUsize = AtomicUsize::new(0);
    static EOF_HANDLE: AtomicUsize = AtomicUsize::new(0);
    static DOWN_P1: AtomicUsize = AtomicUsize::new(0);
    static DOWN_ERR: AtomicUsize = AtomicUsize::new(0);
    static DOWN_ERR_ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn set_eof(handle: u32) -> u32 {
        EOF_HITS.fetch_add(1, Ordering::SeqCst);
        EOF_HANDLE.store(handle as usize, Ordering::SeqCst);
        RET.load(Ordering::SeqCst) as u32
    }

    /// Observers behind the real `fn_0040c1e4` report chain.
    unsafe extern "C" fn down_err() -> u32 {
        DOWN_ERR.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn down_report(p1: *const u8, err: u32) {
        DOWN_P1.store(p1 as usize, Ordering::SeqCst);
        DOWN_ERR_ARG.store(err as usize, Ordering::SeqCst);
    }

    #[test]
    fn truncate_lanes() {
        // Real `fn_0040c1e4` behind the report lane: hold the owner
        // lock so its writer test can't race us.
        let _down = crate::fn_0040c1e4::TEST_LOCK.lock().unwrap();
        let (old_err, old_rep);
        unsafe {
            HOOK_SetEndOfFile = set_eof;
            old_err = crate::fn_0040c1e4::GET_LAST_ERROR_00406700;
            old_rep = crate::fn_0040c1e4::REPORT_0040c130;
            crate::fn_0040c1e4::GET_LAST_ERROR_00406700 = down_err;
            crate::fn_0040c1e4::REPORT_0040c130 = down_report;
        }
        let target = 0x1234 as *const u8;
        let mut obj = [target as usize, 0x55usize];
        let p = obj.as_mut_ptr() as *const u8;
        // Success lane: nonzero, no report.
        RET.store(1, Ordering::SeqCst);
        EOF_HITS.store(0, Ordering::SeqCst);
        DOWN_P1.store(0, Ordering::SeqCst);
        unsafe { fn_0040c410(p) };
        assert_eq!(EOF_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(EOF_HANDLE.load(Ordering::SeqCst), 0x55);
        assert_eq!(DOWN_P1.load(Ordering::SeqCst), 0);
        // Failure lane: zero, real chain forwards (*param_1, err).
        RET.store(0, Ordering::SeqCst);
        DOWN_ERR.store(7, Ordering::SeqCst);
        unsafe { fn_0040c410(p) };
        assert_eq!(EOF_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(DOWN_P1.load(Ordering::SeqCst), target as usize);
        assert_eq!(DOWN_ERR_ARG.load(Ordering::SeqCst), 7);
        unsafe {
            crate::fn_0040c1e4::GET_LAST_ERROR_00406700 = old_err;
            crate::fn_0040c1e4::REPORT_0040c130 = old_rep;
        }
    }
}
