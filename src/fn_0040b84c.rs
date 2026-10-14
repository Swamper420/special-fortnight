//! Original procedure `0x0040b84c` (66 bytes, `0x0040b84c–0x0040b88d`).
//! Evidence: `evidence/0040b84c_fn_0040b84c.md`.

use crate::fn_004046c4::fn_004046c4;
use crate::fn_00404e14::fn_00404e14;
use crate::fn_0040b7bc::fn_0040b7bc;

unsafe extern "C" fn default_cmdline() -> *mut u16 {
    core::ptr::null_mut()
}

/// Import `KERNEL32.DLL::GetCommandLineW` (`CALL 0x004066c0`), no
/// args, wide-string data-pointer result.
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once the Win32 boundary is cut.
pub static mut HOOK_GetCommandLineW: unsafe extern "C" fn() -> *mut u16 = default_cmdline;

/// Test-only serialization for tests sharing this module's globals.
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `cmd=GetCommandLineW(); parsed=b7bc(cmd,&tmp);
/// 4e14(out,parsed); 46c4(&tmp)`. `param_1` (out slot) arrives
/// in EAX (saved in EBX across the calls) per Ghidra
/// `__register` observation. True-exit EAX is the release
/// result (dead stack address), ignored by the sole caller:
/// modeled `void` per the decompiler.
pub unsafe fn fn_0040b84c(param_1: *mut u8) {
    let mut local_8: *mut u8 = core::ptr::null_mut();
    let slot = &mut local_8 as *mut *mut u8 as *mut u8;
    let cmd = HOOK_GetCommandLineW();
    let parsed = fn_0040b7bc(cmd, slot);
    fn_00404e14(param_1, parsed);
    fn_004046c4(slot);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_GetCommandLineW, TEST_LOCK, fn_0040b84c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static GCL_HITS: AtomicUsize = AtomicUsize::new(0);
    static CMD_ADDR: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL_A: AtomicUsize = AtomicUsize::new(0);
    static FILL_C: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn cmdline() -> *mut u16 {
        GCL_HITS.fetch_add(1, Ordering::SeqCst);
        CMD_ADDR.load(Ordering::SeqCst) as *mut u16
    }

    unsafe extern "C" fn alloc(n: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        0
    }

    unsafe extern "C" fn fill(a: *mut u8, _b: u32, c: u32) {
        FILL_HITS.fetch_add(1, Ordering::SeqCst);
        FILL_A.store(a as usize, Ordering::SeqCst);
        FILL_C.store(c as usize, Ordering::SeqCst);
    }

    #[test]
    fn cmdline_parse_forward_lanes() {
        // Foreign fn_00404dd4 hooks (no owner lock): hold the
        // common one first, then own. Null-alloc lane (u32-slot
        // ceiling shared with fn_0040b7bc).
        let _common = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let _own = TEST_LOCK.lock().unwrap();
        let mut cmd = [0x61u16, 0x62, 0x20, 0x63, 0x64, 0];
        CMD_ADDR.store(cmd.as_mut_ptr() as usize, Ordering::SeqCst);
        unsafe {
            HOOK_GetCommandLineW = cmdline;
            crate::fn_00404dd4::HOOK_004054b4 = alloc;
            crate::fn_00404dd4::HOOK_00402fbc = fill;
        }
        GCL_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        let mut out: *mut u8 = core::ptr::null_mut();
        let out_ptr = &mut out as *mut *mut u8 as *mut u8;
        unsafe { fn_0040b84c(out_ptr) };
        // One import call; two allocs: token size 2 (parse)
        // then rest-len 2 (`"cd"`); one fill of the rest
        // (`len<<1 = 4` bytes at cmd+6); null release lane.
        assert_eq!(GCL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 2);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(
            FILL_A.load(Ordering::SeqCst),
            (cmd.as_mut_ptr() as usize).wrapping_add(6)
        );
        assert_eq!(FILL_C.load(Ordering::SeqCst), 4);
        assert!(out.is_null());
    }
}
