//! Original procedure `0x0040eb50` (213 bytes, `0x0040eb50–0x0040ec24`).
//! Evidence: `evidence/0040eb50_fn_0040eb50.md`.

unsafe extern "C" fn default_build(_p: *mut u8, _n: u32) {}
unsafe extern "C" fn default_zero(_p: *mut u8, _a: u32, _b: u32) {}
unsafe extern "C" fn default_data(_p: *mut u8) -> u32 {
    0
}
unsafe extern "C" fn default_create(_c: u32) -> i32 {
    0
}
unsafe extern "C" fn default_e770(_a: u32) {}
unsafe extern "C" fn default_close(_h: u32) {}
unsafe extern "C" fn default_pump() {}
unsafe extern "C" fn default_wait(_h: u32) -> u32 {
    0
}
unsafe extern "C" fn default_exit(_h: u32, _out: *mut u32) {}
unsafe extern "C" fn default_release(_p: *mut u8) {}

/// Target `0x0040513c (args → cmdline obj, 4)`.
pub static mut HOOK_0040513C: unsafe extern "C" fn(*mut u8, u32) = default_build;
/// Target `0x00403250 (STARTUPINFO zero, 0x44)`.
pub static mut HOOK_00403250: unsafe extern "C" fn(*mut u8, u32, u32) = default_zero;
/// Target `0x00404d24 (obj → cmdline ptr)`.
pub static mut HOOK_00404D24: unsafe extern "C" fn(*mut u8) -> u32 = default_data;
/// Target `0x00406660 CreateProcessW` (nonzero = ok).
pub static mut HOOK_CREATEPROCESSW: unsafe extern "C" fn(u32) -> i32 = default_create;
/// Target `0x0040e770` failure reporter (caller passes `0x6a`).
pub static mut HOOK_0040E770: unsafe extern "C" fn(u32) = default_e770;
/// Target `0x00406640 CloseHandle`.
pub static mut HOOK_CLOSEHANDLE: unsafe extern "C" fn(u32) = default_close;
/// Target `0x0040eb24` message pump.
pub static mut HOOK_0040EB24: unsafe extern "C" fn() = default_pump;
/// Target `0x004068c4 MsgWaitForMultipleObjects` (1 = message arrived).
pub static mut HOOK_MSGWAIT: unsafe extern "C" fn(u32) -> u32 = default_wait;
/// Target `0x004066e0 GetExitCodeProcess (hproc, *out)`.
pub static mut HOOK_GETEXITCODEPROCESS: unsafe extern "C" fn(u32, *mut u32) = default_exit;
/// Target `0x00404c88` thunk (release obj).
pub static mut HOOK_00404C88: unsafe extern "C" fn(*mut u8) = default_release;

/// Spawn-and-wait: builds command line, `CreateProcessW`, pumps UI while
/// waiting (`MsgWait...==1` loop), stores exit code to `*exit_out`.
/// ECX lane carries `exit_out`.
pub unsafe fn fn_0040eb50(exit_out: *mut u32) {
    let mut obj = [0u8; 8];
    HOOK_0040513C(obj.as_mut_ptr(), 4);
    // ponytail: 0x44-byte STARTUPINFO, `cb=0x44` first dword.
    let mut si = [0u8; 0x44];
    HOOK_00403250(si.as_mut_ptr(), 0x44, 0);
    unsafe {
        core::ptr::write_unaligned(si.as_mut_ptr() as *mut u32, 0x44);
    }
    let cmd = HOOK_00404D24(obj.as_mut_ptr());
    // PROCESS_INFORMATION dwords: [hProcess, hThread, ...] (observed offsets).
    let pi = [0u32; 4];
    if HOOK_CREATEPROCESSW(cmd) == 0 {
        HOOK_0040E770(0x6a);
    }
    HOOK_CLOSEHANDLE(pi[1]);
    loop {
        HOOK_0040EB24();
        if HOOK_MSGWAIT(pi[0]) != 1 {
            break;
        }
    }
    HOOK_0040EB24();
    HOOK_GETEXITCODEPROCESS(pi[0], exit_out);
    HOOK_CLOSEHANDLE(pi[0]);
    HOOK_00404C88(obj.as_mut_ptr());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static E770_ARG: AtomicU32 = AtomicU32::new(0xffff);
    static WAITS: AtomicU32 = AtomicU32::new(0);
    static PUMPS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn create_fail(_c: u32) -> i32 {
        0
    }
    unsafe extern "C" fn e770(a: u32) {
        E770_ARG.store(a, Ordering::SeqCst);
    }
    unsafe extern "C" fn wait(_h: u32) -> u32 {
        // One QUEUE-status round (1), then signaled (0).
        if WAITS.fetch_add(1, Ordering::SeqCst) == 0 {
            1
        } else {
            0
        }
    }
    unsafe extern "C" fn pump() {
        PUMPS.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn exitcode(_h: u32, out: *mut u32) {
        unsafe { *out = 0x51 };
    }

    #[test]
    fn fail_reports_and_wait_loops() {
        unsafe {
            HOOK_CREATEPROCESSW = create_fail;
            HOOK_0040E770 = e770;
            HOOK_MSGWAIT = wait;
            HOOK_0040EB24 = pump;
            HOOK_GETEXITCODEPROCESS = exitcode;
            WAITS.store(0, Ordering::SeqCst);
            PUMPS.store(0, Ordering::SeqCst);
            let mut code = 0u32;
            fn_0040eb50(&mut code);
            assert_eq!(E770_ARG.load(Ordering::SeqCst), 0x6a);
            assert_eq!(code, 0x51);
            assert_eq!(PUMPS.load(Ordering::SeqCst), 3); // loop×2 + final
        }
    }
}
