//! Original procedure `0x0040e538` (66 bytes, non-contiguous).
//! Evidence: `evidence/0040e538_fn_0040e538.md`.

unsafe extern "C" fn default_curproc() -> u32 {
    0
}
unsafe extern "C" fn default_open(_p: u32, _a: u32, _t: *mut u32) -> i32 {
    0
}
unsafe extern "C" fn default_lookup(_s: *const u8, _n: *const u8, _l: *mut u64) {}
unsafe extern "C" fn default_adjust(_t: u32, _tp: *const u8) {}
unsafe extern "C" fn default_lasterror() -> u32 {
    0
}
unsafe extern "C" fn default_exit(_f: u32, _r: u32) -> i32 {
    0
}

/// `KERNEL32.DLL::GetCurrentProcess`.
/// ponytail: hook standing in for the raw import call at the original site.
pub static mut HOOK_GetCurrentProcess: unsafe extern "C" fn() -> u32 = default_curproc;
/// `ADVAPI32.DLL::OpenProcessToken`.
/// ponytail: hook standing in for the raw import call at the original site.
pub static mut HOOK_OpenProcessToken: unsafe extern "C" fn(u32, u32, *mut u32) -> i32 = default_open;
/// Privilege lookup (`func_0x00406618`, LookupPrivilegeValueW-shaped).
/// ponytail: hook standing in for the raw import call in the body gap.
pub static mut HOOK_LookupPrivilege: unsafe extern "C" fn(*const u8, *const u8, *mut u64) =
    default_lookup;
/// Privilege adjust (AdjustTokenPrivileges-shaped, gap call).
/// ponytail: hook standing in for the raw import call in the body gap.
pub static mut HOOK_AdjustToken: unsafe extern "C" fn(u32, *const u8) = default_adjust;
/// `KERNEL32.DLL::GetLastError`.
/// ponytail: hook standing in for the raw import call at the original site.
pub static mut HOOK_GetLastError: unsafe extern "C" fn() -> u32 = default_lasterror;
/// `USER32.DLL::ExitWindowsEx`.
/// ponytail: hook standing in for the raw import call at the original site.
pub static mut HOOK_ExitWindowsEx: unsafe extern "C" fn(u32, u32) -> i32 = default_exit;

/// Mode cell behind `PTR_DAT_00412c7c` (`*ptr==2` escalates).
///
/// ponytail: address-named static; mode semantics unproven.
pub static mut DAT_004127D8: u32 = 0;
/// ponytail: pointer slot; lazily points at `DAT_004127D8` to match `[ptr]` deref shape.
pub static mut PTR_DAT_00412C7C: *mut u32 = core::ptr::null_mut();

/// Reboot; escalates shutdown privilege when mode==2. No args.
pub unsafe fn fn_0040e538() -> bool {
    if PTR_DAT_00412C7C.is_null() {
        PTR_DAT_00412C7C = &mut DAT_004127D8;
    }
    if core::ptr::read_unaligned(PTR_DAT_00412C7C) == 2 {
        let proc = HOOK_GetCurrentProcess();
        let mut tok: u32 = 0;
        if HOOK_OpenProcessToken(proc, 0x28, &mut tok) == 0 {
            return false;
        }
        let mut luid: u64 = 0;
        HOOK_LookupPrivilege(core::ptr::null(), SE_SHUTDOWN.as_ptr(), &mut luid);
        // ponytail: `count=1, attrs=2` struct per pseudocode; packed inline.
        let mut tp = [0u8; 16];
        core::ptr::write_unaligned(tp.as_mut_ptr() as *mut u32, 1);
        core::ptr::write_unaligned(tp.as_mut_ptr().wrapping_byte_add(4) as *mut u64, luid);
        core::ptr::write_unaligned(tp.as_mut_ptr().wrapping_byte_add(12) as *mut u32, 2);
        HOOK_AdjustToken(tok, tp.as_ptr());
        if HOOK_GetLastError() != 0 {
            return false;
        }
    }
    // ponytail: `CMP EAX,1; SBB; INC` maps exactly 1→true, else→false.
    HOOK_ExitWindowsEx(2, 0) == 1
}

/// `"SeShutdownPrivilege"` at `0x0040e5b4` (observed bytes + NUL).
pub static SE_SHUTDOWN: &[u8] = b"SeShutdownPrivilege\0";

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static OPEN: AtomicUsize = AtomicUsize::new(0);
    static ERR: AtomicUsize = AtomicUsize::new(0);
    static EXIT: AtomicUsize = AtomicUsize::new(0);
    static EXITRET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn open(_p: u32, _a: u32, t: *mut u32) -> i32 {
        OPEN.fetch_add(1, Ordering::SeqCst);
        *t = 0x31;
        if OPEN.load(Ordering::SeqCst) == 99 { 0 } else { 1 }
    }
    unsafe extern "C" fn lasterror() -> u32 {
        ERR.load(Ordering::SeqCst) as u32
    }
    unsafe extern "C" fn exit(_f: u32, _r: u32) -> i32 {
        EXIT.fetch_add(1, Ordering::SeqCst);
        EXITRET.load(Ordering::SeqCst) as i32
    }

    fn reset() {
        unsafe {
            HOOK_OpenProcessToken = open;
            HOOK_GetLastError = lasterror;
            HOOK_ExitWindowsEx = exit;
        }
    }

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn skips_token_path_and_maps_exit() {
        let _lock = LOCK.lock().unwrap();
        reset();
        OPEN.store(0, Ordering::SeqCst);
        EXIT.store(0, Ordering::SeqCst);
        unsafe { DAT_004127D8 = 0 };
        EXITRET.store(1, Ordering::SeqCst);
        assert!(unsafe { fn_0040e538() });
        assert_eq!(OPEN.load(Ordering::SeqCst), 0);
        // Exit 0 → false.
        EXITRET.store(0, Ordering::SeqCst);
        assert!(!unsafe { fn_0040e538() });
        // Exit 2 (non-1) → false per CMP1/SBB/INC.
        EXITRET.store(2, Ordering::SeqCst);
        assert!(!unsafe { fn_0040e538() });
        assert_eq!(EXIT.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn error_after_adjust_is_false() {
        let _lock = LOCK.lock().unwrap();
        reset();
        OPEN.store(0, Ordering::SeqCst);
        EXIT.store(0, Ordering::SeqCst);
        unsafe { DAT_004127D8 = 2 };
        ERR.store(7, Ordering::SeqCst);
        assert!(!unsafe { fn_0040e538() });
        assert_eq!(EXIT.load(Ordering::SeqCst), 0);
        ERR.store(0, Ordering::SeqCst);
        EXITRET.store(1, Ordering::SeqCst);
        assert!(unsafe { fn_0040e538() });
        assert_eq!(EXIT.load(Ordering::SeqCst), 1);
        // Token-open fail → false, no exit.
        OPEN.store(98, Ordering::SeqCst);
        EXIT.store(0, Ordering::SeqCst);
        assert!(!unsafe { fn_0040e538() });
        assert_eq!(EXIT.load(Ordering::SeqCst), 0);
    }
}
