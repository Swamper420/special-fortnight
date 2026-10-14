//! Original procedure `0x0040b89c` (81 bytes, `0x40b89c–0x40b8ec`).
//! Evidence: `evidence/0040b89c_fn_0040b89c.md`.

use crate::fn_004046c4::fn_004046c4;
use crate::fn_0040b7bc::fn_0040b7bc;

unsafe extern "C" fn default_cmdline() -> *mut u16 {
    core::ptr::null_mut()
}

/// Import `KERNEL32.DLL::GetCommandLineW` (`CALL 0x4066c0`), no
/// args, wide-string data-pointer result.
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once the Win32 boundary is cut.
pub static mut HOOK_GetCommandLineW: unsafe extern "C" fn() -> *mut u16 = default_cmdline;

/// Test-only serialization for tests sharing this module's globals.
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Count extra command-line parses: `p=parse(cmd); n=0; while
/// *p { n++; p=parse(p) }`. The initial parse is uncounted
/// (`INC ESI` only runs in the loop body). Returns the count:
/// the true-exit epilogue at `0x40b8f4` is `MOV EAX,ESI`, and
/// the sole caller moves EAX to EBX. No params per Ghidra
/// `__register` observation.
pub unsafe fn fn_0040b89c() -> u32 {
    let mut local_8: *mut u8 = core::ptr::null_mut();
    let slot = &mut local_8 as *mut *mut u8 as *mut u8;
    let mut p = fn_0040b7bc(HOOK_GetCommandLineW(), slot);
    let mut n: u32 = 0;
    loop {
        let c: u16 = core::ptr::read_unaligned(p);
        if c == 0 {
            break;
        }
        n = n.wrapping_add(1);
        p = fn_0040b7bc(p, slot);
    }
    fn_004046c4(slot);
    n
}

#[cfg(test)]
mod tests {
    use super::{HOOK_GetCommandLineW, TEST_LOCK, fn_0040b89c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CMD_ADDR: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn cmdline() -> *mut u16 {
        CMD_ADDR.load(Ordering::SeqCst) as *mut u16
    }

    unsafe extern "C" fn alloc(_n: u32) -> u32 {
        0
    }

    unsafe extern "C" fn fill(_a: *mut u8, _b: u32, _c: u32) {}

    #[test]
    fn count_extra_parses() {
        // Foreign fn_00404dd4 hooks (no owner lock): hold the
        // common one first, then own. Null-alloc lane (u32-slot
        // ceiling shared with fn_0040b7bc).
        let _common = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let _own = TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_GetCommandLineW = cmdline;
            crate::fn_00404dd4::HOOK_004054b4 = alloc;
            crate::fn_00404dd4::HOOK_00402fbc = fill;
        }
        // Empty and single-token inputs: no extra parse.
        let mut s0 = [0u16];
        CMD_ADDR.store(s0.as_mut_ptr() as usize, Ordering::SeqCst);
        assert_eq!(unsafe { fn_0040b89c() }, 0);
        let mut s1 = [0x61u16, 0];
        CMD_ADDR.store(s1.as_mut_ptr() as usize, Ordering::SeqCst);
        assert_eq!(unsafe { fn_0040b89c() }, 0);
        // Two tokens: one extra parse; three: two.
        let mut s2 = [0x61u16, 0x20, 0x62, 0];
        CMD_ADDR.store(s2.as_mut_ptr() as usize, Ordering::SeqCst);
        assert_eq!(unsafe { fn_0040b89c() }, 1);
        let mut s3 = [0x61u16, 0x20, 0x62, 0x20, 0x63, 0];
        CMD_ADDR.store(s3.as_mut_ptr() as usize, Ordering::SeqCst);
        assert_eq!(unsafe { fn_0040b89c() }, 2);
    }
}
