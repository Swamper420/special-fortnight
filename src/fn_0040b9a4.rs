//! Original procedure `0x0040b9a4` (41 bytes, `0x0040b9a4–0x0040b9cc`).
//! Evidence: `evidence/0040b9a4_fn_0040b9a4.md`.

use crate::fn_00408218::fn_00408218;

unsafe extern "C" fn default_win_dir(_buf: *mut u16, _len: u32) -> u32 {
    0
}

/// Import `KERNEL32.DLL::GetWindowsDirectoryW` (`CALL 0x004067d4`),
/// called as `(buf, 0x104)`; the count result is ignored.
///
/// ponytail: hook standing in for the import, rewire to a real
/// `windows-sys` binding once a Windows target binding exists.
pub static mut HOOK_GetWindowsDirectoryW: unsafe extern "C" fn(*mut u16, u32) -> u32 =
    default_win_dir;

/// `GetWindowsDirectoryW(buf, 0x104); 8218(buf, slot)`.
/// `param_1` (slot) arrives in EAX and is saved across the import
/// call in callee-preserved EBX per assembly. Direct call to done
/// `fn_00408218` (no hook).
pub unsafe fn fn_0040b9a4(param_1: *mut u8) {
    let mut buf = [0u16; 260];
    HOOK_GetWindowsDirectoryW(buf.as_mut_ptr(), 0x104);
    fn_00408218(buf.as_mut_ptr(), param_1);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_GetWindowsDirectoryW, fn_0040b9a4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static WIN_HITS: AtomicUsize = AtomicUsize::new(0);
    static WIN_BUF: AtomicUsize = AtomicUsize::new(0);
    static WIN_LEN: AtomicUsize = AtomicUsize::new(0);
    static WIN_RET: AtomicUsize = AtomicUsize::new(0);
    static WIN_EMPTY: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL_A: AtomicUsize = AtomicUsize::new(0);
    static FILL_B: AtomicUsize = AtomicUsize::new(0);
    static FILL_C: AtomicUsize = AtomicUsize::new(0);

    const CANNED: u32 = 0x1122_3344;

    unsafe extern "C" fn win_dir(buf: *mut u16, len: u32) -> u32 {
        WIN_HITS.fetch_add(1, Ordering::SeqCst);
        WIN_BUF.store(buf as usize, Ordering::SeqCst);
        WIN_LEN.store(len as usize, Ordering::SeqCst);
        if WIN_EMPTY.load(Ordering::SeqCst) != 0 {
            core::ptr::write_unaligned(buf, 0);
        } else {
            // L"AB" + terminator.
            core::ptr::write_unaligned(buf, 0x41);
            core::ptr::write_unaligned(buf.wrapping_add(1), 0x42);
            core::ptr::write_unaligned(buf.wrapping_add(2), 0);
        }
        WIN_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn alloc(n: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        CANNED
    }

    unsafe extern "C" fn fill(a: *mut u8, b: u32, c: u32) {
        FILL_HITS.fetch_add(1, Ordering::SeqCst);
        FILL_A.store(a as usize, Ordering::SeqCst);
        FILL_B.store(b as usize, Ordering::SeqCst);
        FILL_C.store(c as usize, Ordering::SeqCst);
    }

    #[test]
    fn win_dir_forward() {
        // Foreign fn_00404dd4 hooks (no owner lock): hold the
        // common one first while writing them.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_GetWindowsDirectoryW = win_dir;
            crate::fn_00404dd4::HOOK_004054b4 = alloc;
            crate::fn_00404dd4::HOOK_00402fbc = fill;
        }
        let mut slot: *mut u8 = core::ptr::null_mut();
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;

        // Wide lane: L"AB" -> alloc(2), fill(buf, canned, 4).
        WIN_EMPTY.store(0, Ordering::SeqCst);
        WIN_RET.store(2, Ordering::SeqCst);
        WIN_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        slot = core::ptr::null_mut();
        unsafe { fn_0040b9a4(slot_ptr) };
        assert_eq!(WIN_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(WIN_LEN.load(Ordering::SeqCst), 0x104);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 2);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FILL_A.load(Ordering::SeqCst), WIN_BUF.load(Ordering::SeqCst));
        assert_eq!(FILL_B.load(Ordering::SeqCst), CANNED as usize);
        assert_eq!(FILL_C.load(Ordering::SeqCst), 4);
        assert_eq!(slot, CANNED as usize as *mut u8);

        // Empty lane: alloc(0), zero-count fill still fires (the
        // original gates fill on the pointer, not the length),
        // slot still stored.
        WIN_EMPTY.store(1, Ordering::SeqCst);
        WIN_RET.store(0, Ordering::SeqCst);
        WIN_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        slot = core::ptr::null_mut();
        unsafe { fn_0040b9a4(slot_ptr) };
        assert_eq!(WIN_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 0);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(slot, CANNED as usize as *mut u8);
    }
}
