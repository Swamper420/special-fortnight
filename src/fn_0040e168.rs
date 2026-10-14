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
unsafe extern "C" fn default_gate(_f: u8, _o: *mut u8) -> bool {
    false
}
unsafe extern "C" fn default_dispatch(_o: *mut u8) {}

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
/// Target `0x0040e11c` probe gate.
///
/// ponytail: hook standing in for same-batch `fn_0040e11c`.
pub static mut HOOK_0040E11C: unsafe extern "C" fn(u8, *mut u8) -> bool = default_gate;
/// Target `0x0040e158` teardown dispatch.
///
/// ponytail: hook standing in for same-batch `fn_0040e158`.
pub static mut HOOK_0040E158: unsafe extern "C" fn(*mut u8) = default_dispatch;

/// Gated file delete; returns stored `DeleteFileW` BOOL (0 on gate-fail).
/// `param_1` EAX / `param_2` EDX per `__register` observation.
pub unsafe fn fn_0040e168(param_1: u8, param_2: *mut u8) -> i32 {
    let mut ctx = [0u8; 8];
    if !HOOK_0040E11C(param_1, ctx.as_mut_ptr()) {
        return 0;
    }
    let name = HOOK_00404D24(param_2);
    let ok = HOOK_DeleteFileW(name);
    let _err: u32 = HOOK_GetLastError();
    // ponytail: SEH frame (`0x0040e1c5/0x0040e1cc`) not modeled — test-platform init detail.
    HOOK_0040E158(ctx.as_mut_ptr());
    // ponytail: pass-path EAX after void call indeterminate; stored BOOL is deterministic reading.
    ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static GATE: AtomicUsize = AtomicUsize::new(0);
    static DEL: AtomicUsize = AtomicUsize::new(0);
    static NAME: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn gate(_f: u8, _o: *mut u8) -> bool {
        GATE.load(Ordering::SeqCst) != 0
    }
    unsafe extern "C" fn convert(_p: *mut u8) -> *mut u16 {
        0xABCD as *mut u16
    }
    unsafe extern "C" fn delete(p: *mut u16) -> i32 {
        DEL.fetch_add(1, Ordering::SeqCst);
        NAME.store(p as usize, Ordering::SeqCst);
        7
    }

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn gate_fail_returns_zero() {
        let _lock = LOCK.lock().unwrap();
        unsafe {
            HOOK_0040E11C = gate;
            HOOK_00404D24 = convert;
            HOOK_DeleteFileW = delete;
        }
        GATE.store(0, Ordering::SeqCst);
        DEL.store(0, Ordering::SeqCst);
        let r = unsafe { fn_0040e168(1, core::ptr::null_mut()) };
        assert_eq!(r, 0);
        assert_eq!(DEL.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn gate_pass_deletes() {
        let _lock = LOCK.lock().unwrap();
        unsafe {
            HOOK_0040E11C = gate;
            HOOK_00404D24 = convert;
            HOOK_DeleteFileW = delete;
        }
        GATE.store(1, Ordering::SeqCst);
        DEL.store(0, Ordering::SeqCst);
        let r = unsafe { fn_0040e168(1, core::ptr::null_mut()) };
        assert_eq!(r, 7);
        assert_eq!(DEL.load(Ordering::SeqCst), 1);
        assert_eq!(NAME.load(Ordering::SeqCst), 0xABCD);
    }
}
