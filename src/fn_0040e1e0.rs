//! Original procedure `0x0040e1e0` (96 bytes, non-contiguous).
//! Evidence: `evidence/0040e1e0_fn_0040e1e0.md`.

unsafe extern "C" fn default_work(_p: *mut u8) -> u8 {
    0
}
unsafe extern "C" fn default_lasterror() -> u32 {
    0
}

/// ponytail: hook for same-batch `fn_0040e11c`: direct
/// intra-reconstruction call (rewired; signatures verified
/// `fn(u8, *mut u8) -> bool`).
/// Target `0x0040b700` (`FUN_0040b700`).
///
/// ponytail: hook standing in for out-of-batch `fn_0040b700`.
pub static mut HOOK_0040B700: unsafe extern "C" fn(*mut u8) -> u8 = default_work;
/// `KERNEL32.DLL::GetLastError`.
///
/// ponytail: hook standing in for the raw import call at the original site.
pub static mut HOOK_GetLastError: unsafe extern "C" fn() -> u32 = default_lasterror;
/// ponytail: hook for same-batch `fn_0040e158`: direct
/// intra-reconstruction call (rewired; signatures verified
/// `fn(*mut u8)`).

/// Gated status-byte worker; returns stored byte (0 on gate-fail).
/// `param_1` EAX / `param_2` EDX per `__register` observation.
pub unsafe fn fn_0040e1e0(param_1: u8, param_2: *mut u8) -> u8 {
    let mut ctx = [0u8; 12];
    if !crate::fn_0040e11c::fn_0040e11c(param_1, ctx.as_mut_ptr()) {
        return 0;
    }
    let b = HOOK_0040B700(param_2);
    let _err: u32 = HOOK_GetLastError();
    // ponytail: SEH frame (`0x0040e236/3d`) not modeled — test-platform init detail.
    crate::fn_0040e158::fn_0040e158(ctx.as_mut_ptr());
    // ponytail: pass-path EAX after void call indeterminate; stored byte is deterministic reading.
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static WORK: AtomicUsize = AtomicUsize::new(0);
    static PROBE_RET: AtomicUsize = AtomicUsize::new(0);
    static DISP_HITS: AtomicUsize = AtomicUsize::new(0);

    /// Probe behind the real `fn_0040e11c` enabled lane.
    unsafe extern "C" fn probe(_c: *mut u8) -> u32 {
        PROBE_RET.load(Ordering::SeqCst) as u32
    }

    /// Dispatch observer behind the real `fn_0040e158`.
    unsafe extern "C" fn dispatch(_a: u32) {
        DISP_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn work(_p: *mut u8) -> u8 {
        WORK.fetch_add(1, Ordering::SeqCst);
        0x5A
    }

    /// Test-only serialization: real `fn_0040e11c`/`fn_0040e158`
    /// run under their owner locks.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn gate_shapes_return() {
        let _lock = LOCK.lock().unwrap();
        let _g11 = crate::fn_0040e11c::TEST_LOCK.lock().unwrap();
        let _g58 = crate::fn_0040e158::TEST_LOCK.lock().unwrap();
        let (old_sle, old_probe, old_dat, old_disp);
        unsafe {
            HOOK_0040B700 = work;
            old_sle = crate::fn_0040e11c::HOOK_SetLastError;
            old_probe = crate::fn_0040e11c::HOOK_0041851C;
            old_dat = crate::fn_0040e11c::DAT_00418524;
            old_disp = crate::fn_0040e158::HOOK_00418520;
            crate::fn_0040e11c::HOOK_0041851C = probe;
            crate::fn_0040e158::HOOK_00418520 = dispatch;
        }
        // Gate-fail lane: disabled cell → real false, no work.
        unsafe { crate::fn_0040e11c::DAT_00418524 = 0 };
        WORK.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_0040e1e0(1, core::ptr::null_mut()) }, 0);
        assert_eq!(WORK.load(Ordering::SeqCst), 0);
        // Gate-pass lane: enabled + probe 1 → work runs, teardown
        // dispatches once.
        unsafe { crate::fn_0040e11c::DAT_00418524 = 1 };
        PROBE_RET.store(1, Ordering::SeqCst);
        DISP_HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_0040e1e0(1, core::ptr::null_mut()) }, 0x5A);
        assert_eq!(WORK.load(Ordering::SeqCst), 1);
        assert_eq!(DISP_HITS.load(Ordering::SeqCst), 1);
        unsafe {
            crate::fn_0040e11c::HOOK_SetLastError = old_sle;
            crate::fn_0040e11c::HOOK_0041851C = old_probe;
            crate::fn_0040e11c::DAT_00418524 = old_dat;
            crate::fn_0040e158::HOOK_00418520 = old_disp;
        }
    }
}
