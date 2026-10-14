//! Original procedure `0x0040c1e4` (19 bytes, `0x40c1e4–0x40c1f6`).
//! Evidence: `evidence/0040c1e4_fn_0040c1e4.md`.

unsafe extern "C" fn default_get_last_error() -> u32 {
    0
}

unsafe extern "C" fn default_report(_p1: *const u8, _err: u32) {}

/// Thunk `0x406700` (`KERNEL32.DLL::GetLastError`).
///
/// ponytail: hook standing in for OS import (also keeps host tests
/// linkable), rewire to raw `extern "system" GetLastError` once
/// Windows-target linkage proven.
pub static mut GET_LAST_ERROR_00406700: unsafe extern "C" fn() -> u32 =
    default_get_last_error;

/// Target `0x40c130` (`FUN_0040c130`), called as `(param_1, GetLastError())`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_0040c130` once it exists.
pub static mut REPORT_0040c130: unsafe extern "C" fn(*const u8, u32) = default_report;

/// `FUN_0040c130(param_1, GetLastError())`, `param_1` saved across import call.
/// Register lane observed: `param_1` in EAX, error out of EAX into EDX.
///
/// ponytail: hooks are `extern "C"` placeholders, upgrade to real
/// Borland register convention / `extern "system"` once linkage proven.
pub unsafe fn fn_0040c1e4(param_1: *const u8) {
    let saved = param_1;
    let err = GET_LAST_ERROR_00406700();
    REPORT_0040c130(saved, err);
}

#[cfg(test)]
mod tests {
    use super::{GET_LAST_ERROR_00406700, REPORT_0040c130, fn_0040c1e4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test-only serialization for tests sharing GET_LAST_ERROR/REPORT globals.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static ERR_RET: AtomicUsize = AtomicUsize::new(0);
    static GOT_P1: AtomicUsize = AtomicUsize::new(0);
    static GOT_ERR: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn get_err() -> u32 {
        ERR_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn report(p1: *const u8, err: u32) {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_P1.store(p1 as usize, Ordering::SeqCst);
        GOT_ERR.store(err as usize, Ordering::SeqCst);
    }

    #[test]
    fn forwards_saved_param_and_last_error() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            GET_LAST_ERROR_00406700 = get_err;
            REPORT_0040c130 = report;
        }
        ERR_RET.store(0x26, Ordering::SeqCst);
        HITS.store(0, Ordering::SeqCst);
        let p = 0x1234 as *const u8;
        unsafe { fn_0040c1e4(p) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_P1.load(Ordering::SeqCst), p as usize);
        assert_eq!(GOT_ERR.load(Ordering::SeqCst), 0x26);
    }
}
