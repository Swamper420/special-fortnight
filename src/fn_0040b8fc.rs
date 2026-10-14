//! Original procedure `0x0040b8fc` (151 bytes, `0x40b8fc–0x40b992`).
//! Evidence: `evidence/0040b8fc_fn_0040b8fc.md`.

use crate::fn_004046c4::fn_004046c4;
use crate::fn_00404c98::fn_00404c98;
use crate::fn_00404cec::fn_00404cec;
use crate::fn_00404dd4::fn_00404dd4;
use crate::fn_0040b7bc::fn_0040b7bc;

unsafe extern "C" fn default_cmdline() -> *mut u16 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_modname(_h: u32, _buf: *mut u16, _len: u32) -> u32 {
    0
}

/// Import `KERNEL32.DLL::GetCommandLineW` (`CALL 0x4066c0`), no
/// args, wide-string data-pointer result.
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once the Win32 boundary is cut.
pub static mut HOOK_GetCommandLineW: unsafe extern "C" fn() -> *mut u16 = default_cmdline;

/// Import `KERNEL32.DLL::GetModuleFileNameW` (`CALL 0x406710`),
/// called as `(0, buf, 0x104)`; returns the char count forwarded
/// to the sized alloc.
///
/// ponytail: hook standing in for the stdcall import, rewire to
/// raw `extern "system"` once the Win32 boundary is cut.
pub static mut HOOK_GetModuleFileNameW: unsafe extern "C" fn(u32, *mut u16, u32) -> u32 =
    default_modname;

/// Test-only serialization for tests sharing this module's globals.
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Select one command-line token by 0-based index, or the module
/// file name when `param_1==0`: modname lane runs
/// `4dd4(out, buf, len)` and skips the store; else loop parses
/// (`*p==0` first → null-acquire lane), keeps the token when the
/// index hits zero *after* the parse, decs otherwise, then
/// stores via `4c98(out, tmp)` and releases the temp.
/// `param_1` (index) arrives in EAX, `param_2` (out slot) in EDX
/// per Ghidra `__register` observation. True-exit EAX is the
/// release result, ignored by both callers: modeled `void`.
pub unsafe fn fn_0040b8fc(param_1: u32, param_2: *mut u8) {
    let mut local_8: *mut u8 = core::ptr::null_mut();
    let slot = &mut local_8 as *mut *mut u8 as *mut u8;
    if param_1 == 0 {
        let mut buf = [0u16; 260];
        let len = HOOK_GetModuleFileNameW(0, buf.as_mut_ptr(), 0x104);
        fn_00404dd4(param_2, buf.as_mut_ptr() as *mut u8, len);
    } else {
        let mut idx = param_1;
        let mut p = HOOK_GetCommandLineW();
        loop {
            let c: u16 = core::ptr::read_unaligned(p);
            if c == 0 {
                fn_00404cec(slot, core::ptr::null_mut());
                break;
            }
            p = fn_0040b7bc(p, slot);
            if idx == 0 {
                break;
            }
            idx = idx.wrapping_sub(1);
        }
        fn_00404c98(param_2, local_8);
    }
    fn_004046c4(slot);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_GetCommandLineW, HOOK_GetModuleFileNameW, TEST_LOCK, fn_0040b8fc};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CMD_ADDR: AtomicUsize = AtomicUsize::new(0);
    static GMFN_HITS: AtomicUsize = AtomicUsize::new(0);
    static GMFN_H: AtomicUsize = AtomicUsize::new(0);
    static GMFN_LEN: AtomicUsize = AtomicUsize::new(0);
    static GMFN_RET: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL_C: AtomicUsize = AtomicUsize::new(0);
    static DTOR_HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn cmdline() -> *mut u16 {
        CMD_ADDR.load(Ordering::SeqCst) as *mut u16
    }

    unsafe extern "C" fn modname(h: u32, buf: *mut u16, len: u32) -> u32 {
        GMFN_HITS.fetch_add(1, Ordering::SeqCst);
        GMFN_H.store(h as usize, Ordering::SeqCst);
        GMFN_LEN.store(len as usize, Ordering::SeqCst);
        core::ptr::write_unaligned(buf, 0x5a);
        core::ptr::write_unaligned(buf.wrapping_add(1), 0);
        GMFN_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn alloc(n: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        0
    }

    unsafe extern "C" fn fill(_a: *mut u8, _b: u32, c: u32) {
        FILL_HITS.fetch_add(1, Ordering::SeqCst);
        FILL_C.store(c as usize, Ordering::SeqCst);
    }

    /// Probe for the done dtor's indirect slot: counts entries,
    /// returns 0 so its tail lane never fires.
    unsafe extern "C" fn indirect() -> u32 {
        DTOR_HITS.fetch_add(1, Ordering::SeqCst);
        0
    }

    /// Header arena: obj = base+12; tag at base+2 (`obj-10`),
    /// refcount at base+4 (`obj-8`), length at base+8 (`obj-4`).
    unsafe fn hdr(arena: &mut [u32; 4], tag: u16, rc: u32, len: u32) -> *mut u8 {
        let base = arena.as_mut_ptr() as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, tag);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, rc);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, len);
        base.wrapping_byte_add(12)
    }

    #[test]
    fn select_token_lanes() {
        // Foreign fn_00404dd4 hooks (no owner lock): hold the
        // common one first; dtor probe needs the fn_00402e20
        // lock; own last. Null-alloc lanes (u32-slot ceiling
        // shared with fn_0040b7bc).
        let _common = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let _callee = crate::fn_00402e20::TEST_LOCK.lock().unwrap();
        let _own = TEST_LOCK.lock().unwrap();
        let saved = unsafe { crate::fn_00402e20::PTR_00412740 };
        unsafe {
            crate::fn_00402e20::PTR_00412740 = indirect;
            HOOK_GetCommandLineW = cmdline;
            HOOK_GetModuleFileNameW = modname;
            crate::fn_00404dd4::HOOK_004054b4 = alloc;
            crate::fn_00404dd4::HOOK_00402fbc = fill;
        }
        let mut out: *mut u8 = core::ptr::null_mut();
        let out_ptr = &mut out as *mut *mut u8 as *mut u8;

        // Module-name lane: import(0, buf, 0x104), alloc(len),
        // fill(len<<1); store skipped; no dtor.
        GMFN_RET.store(1, Ordering::SeqCst);
        GMFN_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        DTOR_HITS.store(0, Ordering::SeqCst);
        out = core::ptr::null_mut();
        unsafe { fn_0040b8fc(0, out_ptr) };
        assert_eq!(GMFN_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GMFN_H.load(Ordering::SeqCst), 0);
        assert_eq!(GMFN_LEN.load(Ordering::SeqCst), 0x104);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 1);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FILL_C.load(Ordering::SeqCst), 2);
        assert!(out.is_null());
        assert_eq!(DTOR_HITS.load(Ordering::SeqCst), 0);

        // Token lanes on "aa bb": index 1 keeps the second
        // token (two parses, alloc 2 each); index 2 exhausts
        // the input and falls into the null-acquire lane.
        // (Index 0 always selects the module-name lane, so the
        // first token is only reachable as a kept second parse.)
        let mut cmd = [0x61u16, 0x61, 0x20, 0x62, 0x62, 0];
        CMD_ADDR.store(cmd.as_mut_ptr() as usize, Ordering::SeqCst);
        GMFN_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        DTOR_HITS.store(0, Ordering::SeqCst);
        out = core::ptr::null_mut();
        unsafe { fn_0040b8fc(1, out_ptr) };
        assert_eq!(GMFN_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 2);
        assert!(out.is_null());
        assert_eq!(DTOR_HITS.load(Ordering::SeqCst), 0);
        GMFN_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        out = core::ptr::null_mut();
        unsafe { fn_0040b8fc(2, out_ptr) };
        assert_eq!(GMFN_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 2);
        assert!(out.is_null());

        // Empty command with nonzero index: null-acquire lane.
        let mut empty = [0u16];
        CMD_ADDR.store(empty.as_mut_ptr() as usize, Ordering::SeqCst);
        GMFN_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        DTOR_HITS.store(0, Ordering::SeqCst);
        out = core::ptr::null_mut();
        unsafe { fn_0040b8fc(5, out_ptr) };
        assert_eq!(GMFN_HITS.load(Ordering::SeqCst), 0);
        assert!(out.is_null());
        assert_eq!(DTOR_HITS.load(Ordering::SeqCst), 0);

        // Old-release lane: seeded refcount-1 object fires the
        // dtor probe once and the slot is cleared.
        let mut arena = [0u32; 4];
        let obj = unsafe { hdr(&mut arena, 2, 1, 0) };
        CMD_ADDR.store(cmd.as_mut_ptr() as usize, Ordering::SeqCst);
        DTOR_HITS.store(0, Ordering::SeqCst);
        out = obj;
        unsafe { fn_0040b8fc(1, out_ptr) };
        assert!(out.is_null());
        assert_eq!(unsafe { *arena.as_mut_ptr().wrapping_add(1) }, 0);
        assert_eq!(DTOR_HITS.load(Ordering::SeqCst), 1);

        unsafe {
            crate::fn_00402e20::PTR_00412740 = saved;
        }
    }
}
