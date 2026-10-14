//! Original procedure `0x0040e1e0` (96 bytes, non-contiguous).
//! Evidence: `evidence/0040e1e0_fn_0040e1e0.md`.

unsafe extern "C" fn default_probe(_f: u8, _o: *mut u8) -> bool {
    false
}
unsafe extern "C" fn default_work(_p: *mut u8) -> u8 {
    0
}
unsafe extern "C" fn default_lasterror() -> u32 {
    0
}
unsafe extern "C" fn default_dispatch(_o: *mut u8) {}

/// ponytail: hook for same-batch `fn_0040e11c`.
pub static mut HOOK_0040E11C: unsafe extern "C" fn(u8, *mut u8) -> bool = default_probe;
/// Target `0x0040b700` (`FUN_0040b700`).
///
/// ponytail: hook standing in for out-of-batch `fn_0040b700`.
pub static mut HOOK_0040B700: unsafe extern "C" fn(*mut u8) -> u8 = default_work;
/// `KERNEL32.DLL::GetLastError`.
///
/// ponytail: hook standing in for the raw import call at the original site.
pub static mut HOOK_GetLastError: unsafe extern "C" fn() -> u32 = default_lasterror;
/// ponytail: hook for same-batch `fn_0040e158`.
pub static mut HOOK_0040E158: unsafe extern "C" fn(*mut u8) = default_dispatch;

/// Gated status-byte worker; returns stored byte (0 on gate-fail).
/// `param_1` EAX / `param_2` EDX per `__register` observation.
pub unsafe fn fn_0040e1e0(param_1: u8, param_2: *mut u8) -> u8 {
    let mut ctx = [0u8; 12];
    if !HOOK_0040E11C(param_1, ctx.as_mut_ptr()) {
        return 0;
    }
    let b = HOOK_0040B700(param_2);
    let _err: u32 = HOOK_GetLastError();
    // ponytail: SEH frame (`0x0040e236/3d`) not modeled — test-platform init detail.
    HOOK_0040E158(ctx.as_mut_ptr());
    // ponytail: pass-path EAX after void call indeterminate; stored byte is deterministic reading.
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static GATE: AtomicUsize = AtomicUsize::new(0);
    static WORK: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn gate(_f: u8, _o: *mut u8) -> bool {
        GATE.load(Ordering::SeqCst) != 0
    }
    unsafe extern "C" fn work(_p: *mut u8) -> u8 {
        WORK.fetch_add(1, Ordering::SeqCst);
        0x5A
    }

    #[test]
    fn gate_shapes_return() {
        unsafe {
            HOOK_0040E11C = gate;
            HOOK_0040B700 = work;
        }
        GATE.store(0, Ordering::SeqCst);
        WORK.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_0040e1e0(1, core::ptr::null_mut()) }, 0);
        assert_eq!(WORK.load(Ordering::SeqCst), 0);
        GATE.store(1, Ordering::SeqCst);
        assert_eq!(unsafe { fn_0040e1e0(1, core::ptr::null_mut()) }, 0x5A);
        assert_eq!(WORK.load(Ordering::SeqCst), 1);
    }
}
