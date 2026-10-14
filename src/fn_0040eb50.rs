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
unsafe extern "C" fn default_close(_h: u32) {}
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
/// Target `0x0040e770` failure reporter (caller passes `0x6a`):
/// direct intra-reconstruction call (rewired; signatures verified
/// `fn(u32)`).
/// Target `0x00406640 CloseHandle`.
pub static mut HOOK_CLOSEHANDLE: unsafe extern "C" fn(u32) = default_close;
/// Target `0x0040eb24` message pump: direct intra-reconstruction
/// call (rewired; signatures verified `fn()`).
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
        crate::fn_0040e770::fn_0040e770(0x6a);
    }
    HOOK_CLOSEHANDLE(pi[1]);
    loop {
        crate::fn_0040eb24::fn_0040eb24();
        if HOOK_MSGWAIT(pi[0]) != 1 {
            break;
        }
    }
    crate::fn_0040eb24::fn_0040eb24();
    HOOK_GETEXITCODEPROCESS(pi[0], exit_out);
    HOOK_CLOSEHANDLE(pi[0]);
    HOOK_00404C88(obj.as_mut_ptr());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static WAITS: AtomicU32 = AtomicU32::new(0);
    static E770_HITS: AtomicU32 = AtomicU32::new(0);
    static PEEK_HITS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn create_fail(_c: u32) -> i32 {
        0
    }
    /// Real `fn_0040e770` lane hooks: error passthrough, message
    /// hooks no-op, nonzero show (keeps the real die off its alloc
    /// lane).
    unsafe extern "C" fn gle() -> u32 {
        5
    }
    unsafe extern "C" fn e88(_a: u32, _b: u32) {
        E770_HITS.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn b84(_a: u32, _b: *mut u32) {}
    unsafe extern "C" fn dd(_a: u32, _b: *const u8, _c: u32, _d: *mut u8) {}
    unsafe extern "C" fn n824(_a: *const u8, _b: u8, _c: *mut u8) -> u32 {
        7
    }
    /// Real `fn_0040eb24` peek hook: empty queue (immediate return).
    unsafe extern "C" fn peek(_m: *mut u8) -> i32 {
        PEEK_HITS.fetch_add(1, Ordering::SeqCst);
        0
    }
    unsafe extern "C" fn wait(_h: u32) -> u32 {
        // One QUEUE-status round (1), then signaled (0).
        if WAITS.fetch_add(1, Ordering::SeqCst) == 0 {
            1
        } else {
            0
        }
    }
    unsafe extern "C" fn exitcode(_h: u32, out: *mut u32) {
        unsafe { *out = 0x51 };
    }

    #[test]
    fn fail_reports_and_wait_loops() {
        // Real `fn_0040e770` behind the report (its hooks/DAT
        // shared; nonzero show skips the real die alloc lane, null
        // raise slot skips raise) and real `fn_0040eb24` behind the
        // pumps (empty queue returns at once): hold their locks plus
        // the real die lock set.
        let _e770 = crate::fn_0040e770::TEST_LOCK.lock().unwrap();
        let _eb24 = crate::fn_0040eb24::TEST_LOCK.lock().unwrap();
        let _b8 = crate::fn_004046b8::TEST_LOCK.lock().unwrap();
        let _ac = crate::fn_004046ac::TEST_LOCK.lock().unwrap();
        let _loop = crate::fn_00404580::TEST_LOCK.lock().unwrap();
        let _tls = crate::fn_00406588::TEST_LOCK.lock().unwrap();
        let (old_hook, old_tail);
        unsafe {
            old_hook = crate::fn_00403f88::HOOK_0041301C;
            old_tail = crate::fn_00403f88::TAIL_00413014;
            crate::fn_00403f88::HOOK_0041301C = None;
            crate::fn_0040e770::DAT_00412C08 = core::ptr::null();
            crate::fn_0040e770::HOOK_GETLASTERROR = gle;
            crate::fn_0040e770::HOOK_00407EE8 = e88;
            crate::fn_0040e770::HOOK_0040BF84 = b84;
            crate::fn_0040e770::HOOK_0040DEF0 = dd;
            crate::fn_0040e770::HOOK_00409824 = n824;
            crate::fn_0040eb24::HOOK_PEEKMESSAGEW = peek;
            HOOK_CREATEPROCESSW = create_fail;
            HOOK_MSGWAIT = wait;
            HOOK_GETEXITCODEPROCESS = exitcode;
            WAITS.store(0, Ordering::SeqCst);
            E770_HITS.store(0, Ordering::SeqCst);
            PEEK_HITS.store(0, Ordering::SeqCst);
            let mut code = 0u32;
            fn_0040eb50(&mut code);
            // Report ran once (report lane), pumps drained nothing
            // (3 EB24 calls × immediate return), wait loop as before.
            assert_eq!(E770_HITS.load(Ordering::SeqCst), 1);
            assert_eq!(PEEK_HITS.load(Ordering::SeqCst), 3);
            assert_eq!(code, 0x51);
            crate::fn_00403f88::HOOK_0041301C = old_hook;
            crate::fn_00403f88::TAIL_00413014 = old_tail;
        }
    }
}
