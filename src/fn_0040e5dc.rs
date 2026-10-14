//! Original procedure `0x0040e5dc` (98 bytes, `0x0040e5dc–0x0040e63d`).
//! Evidence: `evidence/0040e5dc_fn_0040e5dc.md`.

unsafe extern "C" fn default_sleep(_ms: u32) {}
unsafe extern "C" fn default_lasterror() -> u32 {
    0
}

/// `KERNEL32.DLL::Sleep` (`0x0040abcc`).
///
/// ponytail: hook standing in for the raw import call at the original site.
pub static mut HOOK_Sleep: unsafe extern "C" fn(u32) = default_sleep;
/// Target `0x0040e168` gated delete: direct intra-reconstruction
/// call (rewired; signatures verified `fn(u8, *mut u8) -> i32`).
/// Its convert/delete hooks plus the real gate/teardown pins stay,
/// pinned by the tests under the callee + gate locks.
/// `KERNEL32.DLL::GetLastError`.
///
/// ponytail: hook standing in for the raw import call at the original site.
pub static mut HOOK_GetLastError: unsafe extern "C" fn() -> u32 = default_lasterror;

/// Retry-delete loop: attempt 0 bare, attempt 1 sleeps `param_5`, later sleep `param_4`.
/// Stops on success or lasterror 2/3 or count exhaustion.
/// `param_1` EAX / `param_2` EDX / `param_3` ECX per `__register` observation.
pub unsafe fn fn_0040e5dc(
    param_1: u8,
    param_2: *mut u8,
    mut param_3: i32,
    param_4: u32,
    param_5: u32,
) {
    // ponytail: `DEC; TEST; JL` entry matches `param_3<=0 → return`.
    if param_3.wrapping_sub(1) < 0 {
        return;
    }
    let mut attempt = 0;
    loop {
        if attempt == 1 {
            HOOK_Sleep(param_5);
        } else if attempt > 1 {
            HOOK_Sleep(param_4);
        }
        if crate::fn_0040e168::fn_0040e168(param_1, param_2) != 0 {
            return;
        }
        // ponytail: double GetLastError call (not cached) matches.
        if HOOK_GetLastError() == 2 {
            return;
        }
        if HOOK_GetLastError() == 3 {
            return;
        }
        attempt += 1;
        param_3 -= 1;
        if param_3 == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TRIES: AtomicUsize = AtomicUsize::new(0);
    static SLEEPS: AtomicUsize = AtomicUsize::new(0);
    static SLEEP_MS: AtomicUsize = AtomicUsize::new(0);
    static SUCCEED_AT: AtomicUsize = AtomicUsize::new(0);
    static ERR: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn sleep(ms: u32) {
        SLEEPS.fetch_add(1, Ordering::SeqCst);
        SLEEP_MS.store(ms as usize, Ordering::SeqCst);
    }
    /// Real `fn_0040e168`'s delete hook behind the retry loop:
    /// succeeds (nonzero BOOL) on the scripted try, fails before.
    unsafe extern "C" fn delete(_p: *mut u16) -> i32 {
        let n = TRIES.fetch_add(1, Ordering::SeqCst) + 1;
        if n == SUCCEED_AT.load(Ordering::SeqCst) { 7 } else { 0 }
    }
    unsafe extern "C" fn convert(_p: *mut u8) -> *mut u16 {
        0xABCD as *mut u16
    }
    /// Probe behind the real gate (always enabled here).
    unsafe extern "C" fn probe(_c: *mut u8) -> u32 {
        1
    }
    /// Teardown dispatch observer behind the real `fn_0040e158`.
    unsafe extern "C" fn dispatch(_a: u32) {}
    unsafe extern "C" fn lasterror() -> u32 {
        ERR.load(Ordering::SeqCst) as u32
    }

    fn reset() {
        // Real `fn_0040e168` behind the tries (its convert/delete
        // hooks plus the real gate/teardown pins shared): hold the
        // callee lock and both gate locks, enable the gate,
        // save/restore.
        unsafe {
            HOOK_Sleep = sleep;
            HOOK_GetLastError = lasterror;
        }
        TRIES.store(0, Ordering::SeqCst);
        SLEEPS.store(0, Ordering::SeqCst);
    }

    /// Observer behind the real `fn_0040e11c` lanes.
    unsafe extern "C" fn set_last_error(_c: u32) {}

    /// Pin the real-delete lane behind every try below; returns the
    /// saved gate hooks/cell for restore at the end of the test.
    macro_rules! pin_callee {
        ($sle:ident, $probe:ident, $dat:ident, $disp:ident) => {
            let ($sle, $probe, $dat, $disp);
            unsafe {
                crate::fn_0040e168::HOOK_00404D24 = convert;
                crate::fn_0040e168::HOOK_DeleteFileW = delete;
                $sle = crate::fn_0040e11c::HOOK_SetLastError;
                $probe = crate::fn_0040e11c::HOOK_0041851C;
                $dat = crate::fn_0040e11c::DAT_00418524;
                $disp = crate::fn_0040e158::HOOK_00418520;
                crate::fn_0040e11c::HOOK_SetLastError = set_last_error;
                crate::fn_0040e11c::HOOK_0041851C = probe;
                crate::fn_0040e11c::DAT_00418524 = 1;
                crate::fn_0040e158::HOOK_00418520 = dispatch;
            }
        };
    }

    macro_rules! unpin_callee {
        ($sle:ident, $probe:ident, $dat:ident, $disp:ident) => {
            unsafe {
                crate::fn_0040e11c::HOOK_SetLastError = $sle;
                crate::fn_0040e11c::HOOK_0041851C = $probe;
                crate::fn_0040e11c::DAT_00418524 = $dat;
                crate::fn_0040e158::HOOK_00418520 = $disp;
            }
        };
    }

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn zero_count_no_calls() {
        let _lock = LOCK.lock().unwrap();
        reset();
        SUCCEED_AT.store(1, Ordering::SeqCst);
        ERR.store(0, Ordering::SeqCst);
        unsafe { fn_0040e5dc(0, core::ptr::null_mut(), 0, 100, 10) };
        assert_eq!(TRIES.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn success_first_try_and_not_found_stop() {
        let _lock = LOCK.lock().unwrap();
        // Real `fn_0040e168` behind the tries: hold the callee lock
        // and both gate locks, enable the gate.
        let _callee = crate::fn_0040e168::TEST_LOCK.lock().unwrap();
        let _g11 = crate::fn_0040e11c::TEST_LOCK.lock().unwrap();
        let _g58 = crate::fn_0040e158::TEST_LOCK.lock().unwrap();
        pin_callee!(old_sle, old_probe, old_dat, old_disp);
        reset();
        SUCCEED_AT.store(1, Ordering::SeqCst);
        ERR.store(0, Ordering::SeqCst);
        unsafe { fn_0040e5dc(0, core::ptr::null_mut(), 3, 100, 10) };
        assert_eq!(TRIES.load(Ordering::SeqCst), 1);
        assert_eq!(SLEEPS.load(Ordering::SeqCst), 0);
        // Never succeeds, error 2 → stops after 1 try.
        reset();
        SUCCEED_AT.store(99, Ordering::SeqCst);
        ERR.store(2, Ordering::SeqCst);
        unsafe { fn_0040e5dc(0, core::ptr::null_mut(), 3, 100, 10) };
        assert_eq!(TRIES.load(Ordering::SeqCst), 1);
        // Error 3 same.
        reset();
        ERR.store(3, Ordering::SeqCst);
        unsafe { fn_0040e5dc(0, core::ptr::null_mut(), 3, 100, 10) };
        assert_eq!(TRIES.load(Ordering::SeqCst), 1);
        unpin_callee!(old_sle, old_probe, old_dat, old_disp);
    }

    #[test]
    fn retry_sleeps_select() {
        let _lock = LOCK.lock().unwrap();
        let _callee = crate::fn_0040e168::TEST_LOCK.lock().unwrap();
        let _g11 = crate::fn_0040e11c::TEST_LOCK.lock().unwrap();
        let _g58 = crate::fn_0040e158::TEST_LOCK.lock().unwrap();
        pin_callee!(old_sle2, old_probe2, old_dat2, old_disp2);
        reset();
        SUCCEED_AT.store(3, Ordering::SeqCst); // attempts 1,2 fail; 3 succeeds
        ERR.store(0, Ordering::SeqCst);
        unsafe { fn_0040e5dc(0, core::ptr::null_mut(), 5, 100, 10) };
        assert_eq!(TRIES.load(Ordering::SeqCst), 3);
        assert_eq!(SLEEPS.load(Ordering::SeqCst), 2);
        assert_eq!(SLEEP_MS.load(Ordering::SeqCst), 100); // attempt idx 2 → param_4
        unpin_callee!(old_sle2, old_probe2, old_dat2, old_disp2);
    }
}
