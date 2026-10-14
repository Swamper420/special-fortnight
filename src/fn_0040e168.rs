//! Original procedure `0x0040e168` (102 bytes, non-contiguous `0x0040e168–0x0040e1c4` + `0x0040e1d5–0x0040e1dd`).
//! Evidence: `evidence/0040e168_fn_0040e168.md`.

unsafe extern "C" fn default_convert(_p: *mut u8) -> *mut u16 {
    core::ptr::null_mut()
}
unsafe extern "C" fn default_delete(_p: *mut u16) -> i32 {
    0
}
unsafe extern "C" fn default_lasterror() -> u32 {
    0
}

/// ponytail: hook for `fn_00404d24` (name conversion).
pub static mut HOOK_00404D24: unsafe extern "C" fn(*mut u8) -> *mut u16 = default_convert;
/// `KERNEL32.DLL::DeleteFileW` (`0x00406668`).
///
/// ponytail: hook standing in for the raw import call at the original site.
pub static mut HOOK_DeleteFileW: unsafe extern "C" fn(*mut u16) -> i32 = default_delete;
/// `KERNEL32.DLL::GetLastError` (`0x00406700`).
///
/// ponytail: hook standing in for the raw import call at the original site.
pub static mut HOOK_GetLastError: unsafe extern "C" fn() -> u32 = default_lasterror;
/// Target `0x0040e11c` probe gate: direct intra-reconstruction call
/// (rewired; signatures verified `fn(u8, *mut u8) -> bool`).
/// Target `0x0040e158` teardown dispatch: direct intra-reconstruction
/// call (rewired; signatures verified `fn(*mut u8)`).

/// Gated file delete; returns stored `DeleteFileW` BOOL (0 on gate-fail).
/// `param_1` EAX / `param_2` EDX per `__register` observation.
pub unsafe fn fn_0040e168(param_1: u8, param_2: *mut u8) -> i32 {
    let mut ctx = [0u8; 8];
    if !crate::fn_0040e11c::fn_0040e11c(param_1, ctx.as_mut_ptr()) {
        return 0;
    }
    let name = HOOK_00404D24(param_2);
    let ok = HOOK_DeleteFileW(name);
    let _err: u32 = HOOK_GetLastError();
    // ponytail: SEH frame (`0x0040e1c5/0x0040e1cc`) not modeled — test-platform init detail.
    crate::fn_0040e158::fn_0040e158(ctx.as_mut_ptr());
    // ponytail: pass-path EAX after void call indeterminate; stored BOOL is deterministic reading.
    ok
}

/// Test-only serialization for tests sharing the lane hooks (held
/// here and by the rewired `fn_0040e5dc` test driving the real
/// delete).
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DEL: AtomicUsize = AtomicUsize::new(0);
    static NAME: AtomicUsize = AtomicUsize::new(0);
    static SLE_HITS: AtomicUsize = AtomicUsize::new(0);
    static PROBE_RET: AtomicUsize = AtomicUsize::new(0);
    static DISP_HITS: AtomicUsize = AtomicUsize::new(0);
    static DISP_ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn convert(_p: *mut u8) -> *mut u16 {
        0xABCD as *mut u16
    }
    unsafe extern "C" fn delete(p: *mut u16) -> i32 {
        DEL.fetch_add(1, Ordering::SeqCst);
        NAME.store(p as usize, Ordering::SeqCst);
        7
    }

    /// Observer behind the real `fn_0040e11c` disabled lane.
    unsafe extern "C" fn set_last_error(_c: u32) {
        SLE_HITS.fetch_add(1, Ordering::SeqCst);
    }

    /// Probe behind the real `fn_0040e11c` enabled lane.
    unsafe extern "C" fn probe(_c: *mut u8) -> u32 {
        PROBE_RET.load(Ordering::SeqCst) as u32
    }

    /// Dispatch observer behind the real `fn_0040e158`.
    unsafe extern "C" fn dispatch(a: u32) {
        DISP_HITS.fetch_add(1, Ordering::SeqCst);
        DISP_ARG.store(a as usize, Ordering::SeqCst);
    }

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn gate_fail_returns_zero() {
        let _lock = LOCK.lock().unwrap();
        let _shared = super::TEST_LOCK.lock().unwrap();
        // Real gate with the cell disabled: SetLastError(1), false.
        let _g11 = crate::fn_0040e11c::TEST_LOCK.lock().unwrap();
        let (old_sle, old_probe, old_dat);
        unsafe {
            HOOK_00404D24 = convert;
            HOOK_DeleteFileW = delete;
            old_sle = crate::fn_0040e11c::HOOK_SetLastError;
            old_probe = crate::fn_0040e11c::HOOK_0041851C;
            old_dat = crate::fn_0040e11c::DAT_00418524;
            crate::fn_0040e11c::HOOK_SetLastError = set_last_error;
            crate::fn_0040e11c::HOOK_0041851C = probe;
            crate::fn_0040e11c::DAT_00418524 = 0;
        }
        SLE_HITS.store(0, Ordering::SeqCst);
        DEL.store(0, Ordering::SeqCst);
        let r = unsafe { fn_0040e168(1, core::ptr::null_mut()) };
        assert_eq!(r, 0);
        assert_eq!(DEL.load(Ordering::SeqCst), 0);
        assert_eq!(SLE_HITS.load(Ordering::SeqCst), 1);
        unsafe {
            crate::fn_0040e11c::HOOK_SetLastError = old_sle;
            crate::fn_0040e11c::HOOK_0041851C = old_probe;
            crate::fn_0040e11c::DAT_00418524 = old_dat;
        }
    }

    #[test]
    fn gate_pass_deletes() {
        let _lock = LOCK.lock().unwrap();
        let _shared = super::TEST_LOCK.lock().unwrap();
        // Real gate enabled with probe 1: ctx[0]=1; the real
        // teardown reads [ctx+4]==0 and dispatches it.
        let _g11 = crate::fn_0040e11c::TEST_LOCK.lock().unwrap();
        let _g58 = crate::fn_0040e158::TEST_LOCK.lock().unwrap();
        let (old_sle, old_probe, old_dat, old_disp);
        unsafe {
            HOOK_00404D24 = convert;
            HOOK_DeleteFileW = delete;
            old_sle = crate::fn_0040e11c::HOOK_SetLastError;
            old_probe = crate::fn_0040e11c::HOOK_0041851C;
            old_dat = crate::fn_0040e11c::DAT_00418524;
            old_disp = crate::fn_0040e158::HOOK_00418520;
            crate::fn_0040e11c::HOOK_SetLastError = set_last_error;
            crate::fn_0040e11c::HOOK_0041851C = probe;
            crate::fn_0040e11c::DAT_00418524 = 1;
            crate::fn_0040e158::HOOK_00418520 = dispatch;
        }
        PROBE_RET.store(1, Ordering::SeqCst);
        DEL.store(0, Ordering::SeqCst);
        DISP_HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_0040e168(1, core::ptr::null_mut()) };
        assert_eq!(r, 7);
        assert_eq!(DEL.load(Ordering::SeqCst), 1);
        assert_eq!(NAME.load(Ordering::SeqCst), 0xABCD);
        assert_eq!(DISP_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(DISP_ARG.load(Ordering::SeqCst), 0);
        unsafe {
            crate::fn_0040e11c::HOOK_SetLastError = old_sle;
            crate::fn_0040e11c::HOOK_0041851C = old_probe;
            crate::fn_0040e11c::DAT_00418524 = old_dat;
            crate::fn_0040e158::HOOK_00418520 = old_disp;
        }
    }
}
