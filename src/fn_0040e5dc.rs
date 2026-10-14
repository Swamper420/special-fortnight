//! Original procedure `0x0040e5dc` (98 bytes, `0x40e5dc–0x40e63d`).
//! Evidence: `evidence/0040e5dc_fn_0040e5dc.md`.

unsafe extern "C" fn default_sleep(_ms: u32) {}
unsafe extern "C" fn default_delete(_f: u8, _p: *mut u8) -> i32 {
    0
}
unsafe extern "C" fn default_lasterror() -> u32 {
    0
}

/// `KERNEL32.DLL::Sleep` (`0x40abcc`).
///
/// ponytail: hook standing in for the raw import call at the original site.
pub static mut HOOK_Sleep: unsafe extern "C" fn(u32) = default_sleep;
/// Target `0x40e168` gated delete.
///
/// ponytail: hook standing in for same-batch `fn_0040e168`.
pub static mut HOOK_0040E168: unsafe extern "C" fn(u8, *mut u8) -> i32 = default_delete;
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
        if HOOK_0040E168(param_1, param_2) != 0 {
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
    unsafe extern "C" fn delete(_f: u8, _p: *mut u8) -> i32 {
        let n = TRIES.fetch_add(1, Ordering::SeqCst) + 1;
        if n == SUCCEED_AT.load(Ordering::SeqCst) { 1 } else { 0 }
    }
    unsafe extern "C" fn lasterror() -> u32 {
        ERR.load(Ordering::SeqCst) as u32
    }

    fn reset() {
        unsafe {
            HOOK_Sleep = sleep;
            HOOK_0040E168 = delete;
            HOOK_GetLastError = lasterror;
        }
        TRIES.store(0, Ordering::SeqCst);
        SLEEPS.store(0, Ordering::SeqCst);
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
    }

    #[test]
    fn retry_sleeps_select() {
        let _lock = LOCK.lock().unwrap();
        reset();
        SUCCEED_AT.store(3, Ordering::SeqCst); // attempts 1,2 fail; 3 succeeds
        ERR.store(0, Ordering::SeqCst);
        unsafe { fn_0040e5dc(0, core::ptr::null_mut(), 5, 100, 10) };
        assert_eq!(TRIES.load(Ordering::SeqCst), 3);
        assert_eq!(SLEEPS.load(Ordering::SeqCst), 2);
        assert_eq!(SLEEP_MS.load(Ordering::SeqCst), 100); // attempt idx 2 → param_4
    }
}
