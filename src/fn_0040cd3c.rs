//! Original procedure `0x0040cd3c` (73 bytes, `0x0040cd3c–0x0040cd84`).
//! Evidence: `evidence/0040cd3c_fn_0040cd3c.md`.

unsafe extern "C" fn default_convert(_a: *mut u16, _b: u32, _c: u32, _d: *mut u32) {}
unsafe extern "C" fn default_release(_s: *mut u8) {}

/// Target `0x004082d4` (`FUN_004082d4`), `(p1,p2,p3,&local)`.
///
/// ponytail: hook standing in for done `fn_004082d4`, rewire to the real
/// call once cross-module linkage proven.
pub static mut HOOK_004082D4: unsafe extern "C" fn(*mut u16, u32, u32, *mut u32) =
    default_convert;

/// Thunk `0x00404c88` (`thunk_FUN_004046c4`), `(&local_8)`, unconditional.
///
/// ponytail: hook standing in for the thunk target, rewire to done
/// `fn_004046c4` once cross-module linkage proven.
pub static mut HOOK_004046C4: unsafe extern "C" fn(*mut u8) = default_release;

/// `local=0; convert(p1,p2,p3,&local); report(local); release(&local)`.
/// SEH push/`FS:[0]` swap omitted (no host equivalent).
/// `report` is a direct intra-cluster call to `crate::fn_0040ccdc::fn_0040ccdc`.
pub unsafe fn fn_0040cd3c(param_1: *mut u16, param_2: u32, param_3: u32) {
    let mut local_8: u32 = 0;
    HOOK_004082D4(param_1, param_2, param_3, &mut local_8);
    crate::fn_0040ccdc::fn_0040ccdc(local_8);
    HOOK_004046C4(&mut local_8 as *mut u32 as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004046C4, HOOK_004082D4, fn_0040cd3c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEEN: AtomicUsize = AtomicUsize::new(0);
    static REL: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn convert(_a: *mut u16, _b: u32, _c: u32, d: *mut u32) {
        *d = 0x5a;
    }
    // Observed through the real `fn_0040ccdc`: it forwards a block
    // `[local, 0x11]` to its format hook and the format result to the
    // real die (pinned to its null-raise lane here), so record at the
    // format hook — same value, same call count.
    unsafe extern "C" fn fmt(
        _a: usize,
        _b: u8,
        _c: *const u16,
        _d: u32,
        blk: *mut u8,
    ) -> u32 {
        assert_eq!(core::ptr::read_unaligned(blk as *const u32), 0x5a);
        assert_eq!(core::ptr::read_unaligned((blk as usize).wrapping_add(4) as *const u8), 0x11);
        SEEN.store(0x5a, Ordering::SeqCst);
        0x5a
    }
    unsafe extern "C" fn release(s: *mut u8) {
        REL.store(core::ptr::read_unaligned(s as *const u32) as usize, Ordering::SeqCst);
    }

    #[test]
    fn convert_report_release_chain() {
        // Real `fn_00403f88` behind the report (nonzero result skips
        // its alloc lane): hold its lock set, pin the null raise slot.
        let _b8 = crate::fn_004046b8::TEST_LOCK.lock().unwrap();
        let _ac = crate::fn_004046ac::TEST_LOCK.lock().unwrap();
        let _loop = crate::fn_00404580::TEST_LOCK.lock().unwrap();
        let _tls = crate::fn_00406588::TEST_LOCK.lock().unwrap();
        let (old_hook, old_tail);
        unsafe {
            old_hook = crate::fn_00403f88::HOOK_0041301C;
            old_tail = crate::fn_00403f88::TAIL_00413014;
            crate::fn_00403f88::HOOK_0041301C = None;
            HOOK_004082D4 = convert;
            HOOK_004046C4 = release;
            crate::fn_0040ccdc::HOOK_00409860 = fmt;
        }
        let mut buf = [0u16; 2];
        unsafe { fn_0040cd3c(buf.as_mut_ptr(), 7, 8) };
        assert_eq!(SEEN.load(Ordering::SeqCst), 0x5a);
        assert_eq!(REL.load(Ordering::SeqCst), 0x5a);
        unsafe {
            crate::fn_00403f88::HOOK_0041301C = old_hook;
            crate::fn_00403f88::TAIL_00413014 = old_tail;
        }
    }
}
