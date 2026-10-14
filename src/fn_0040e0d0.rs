//! Original procedure `0x0040e0d0` (65 bytes, `0x0040e0d0–0x0040e110`).
//! Evidence: `evidence/0040e0d0_fn_0040e0d0.md`.

unsafe extern "C" fn default_reset() {}
unsafe extern "C" fn default_build(_t: *mut u32, _f: u32, _n: u32) {}

/// Target `0x0040df44` table reset.
///
/// ponytail: hook standing in for same-batch `fn_0040df44`.
pub static mut HOOK_0040DF44: unsafe extern "C" fn() = default_reset;
/// Target `0x00405548` table build.
///
/// ponytail: hook standing in for out-of-batch `fn_00405548`.
pub static mut HOOK_00405548: unsafe extern "C" fn(*mut u32, u32, u32) = default_build;

/// Once-guard `DAT_00418514`.
///
/// ponytail: address-named static; init-once counter, wraps to trigger.
pub static mut DAT_00418514: u32 = 0;
/// Format-word slot `DAT_00401018` value (`EDX` arg of build).
///
/// ponytail: address-named static; referent unproven.
pub static mut DAT_00401018: u32 = 0;

/// Increment once-guard; on wrap to 0 reset + build table. No args.
pub unsafe fn fn_0040e0d0() {
    // ponytail: `INC m32; JNZ skip` — wrapping increment matches.
    DAT_00418514 = DAT_00418514.wrapping_add(1);
    if DAT_00418514 == 0 {
        HOOK_0040DF44();
        HOOK_00405548(
            crate::fn_0040def0::DAT_004181A0.as_mut_ptr(),
            DAT_00401018,
            0xdd,
        );
    }
    // ponytail: SEH frame (`0x0040e111/18`) not modeled — test-platform init detail.
}

#[cfg(test)]
mod tests {
    use super::{DAT_00401018, DAT_00418514, HOOK_00405548, fn_0040e0d0};
    use super::HOOK_0040DF44 as HRESET;
    use super::HOOK_00405548 as HBUILD;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static RESET: AtomicUsize = AtomicUsize::new(0);
    static BUILD: AtomicUsize = AtomicUsize::new(0);
    static GOTN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn reset() {
        RESET.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn build(_t: *mut u32, _f: u32, n: u32) {
        BUILD.fetch_add(1, Ordering::SeqCst);
        GOTN.store(n as usize, Ordering::SeqCst);
    }

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn inc_without_wrap_no_hooks() {
        let _lock = LOCK.lock().unwrap();
        unsafe {
            HRESET = reset;
            HBUILD = build;
            DAT_00418514 = 41;
        }
        RESET.store(0, Ordering::SeqCst);
        BUILD.store(0, Ordering::SeqCst);
        unsafe { fn_0040e0d0() };
        unsafe { assert_eq!(DAT_00418514, 42) };
        assert_eq!(RESET.load(Ordering::SeqCst), 0);
        assert_eq!(BUILD.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn wrap_triggers_both() {
        let _lock = LOCK.lock().unwrap();
        unsafe {
            HRESET = reset;
            HBUILD = build;
            DAT_00418514 = 0xffffffff;
            DAT_00401018 = 0x77;
        }
        RESET.store(0, Ordering::SeqCst);
        BUILD.store(0, Ordering::SeqCst);
        unsafe { fn_0040e0d0() };
        unsafe { assert_eq!(DAT_00418514, 0) };
        assert_eq!(RESET.load(Ordering::SeqCst), 1);
        assert_eq!(BUILD.load(Ordering::SeqCst), 1);
        assert_eq!(GOTN.load(Ordering::SeqCst), 0xdd);
    }
}
