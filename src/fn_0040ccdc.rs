//! Original procedure `0x0040ccdc` (43 bytes, `0x0040ccdc–0x0040cd06`).
//! Evidence: `evidence/0040ccdc_fn_0040ccdc.md`.

unsafe extern "C" fn default_fmt(
    _p1: usize,
    _p2: u8,
    _p3: *const u16,
    _p4: u32,
    _p5: *mut u8,
) -> u32 {
    0
}
/// Target `0x00409860` (`FUN_00409860`), 5 lanes `(EAX,DL,ECX,0,&block)`.
///
/// ponytail: hook standing in for done `fn_00409860`, rewire to the real
/// call once cross-module linkage proven.
pub static mut HOOK_00409860: unsafe extern "C" fn(usize, u8, *const u16, u32, *mut u8) -> u32 =
    default_fmt;

/// Target `0x00403f88` (`FUN_00403f88`): direct
/// intra-reconstruction call (rewired; signatures verified
/// `fn(u32)`).

/// Cells `0x0040c550` (first lane) and `0x0040cd14` (`lzmadecompsmall: %s`).
///
/// ponytail: absolute-address cells as own-module statics, unify in
/// `data.rs` once data layout proven.
pub static mut DAT_0040C550: usize = 0;
pub static mut DAT_0040CD14: usize = 0;

/// `local_c=param_1, local_8=0x11; r=fmt([DAT],1,str,0,&block); die(r)`.
pub unsafe fn fn_0040ccdc(param_1: u32) {
    let mut block = [0u8; 8];
    core::ptr::write_unaligned(block.as_mut_ptr() as *mut u32, param_1);
    block[4] = 0x11;
    let r = HOOK_00409860(
        DAT_0040C550,
        1,
        DAT_0040CD14 as *const u16,
        0,
        block.as_mut_ptr(),
    );
    crate::fn_00403f88::fn_00403f88(r);
}

#[cfg(test)]
mod tests {
    use super::{DAT_0040C550, DAT_0040CD14, HOOK_00409860, fn_0040ccdc};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TAG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn fmt(_a: usize, _b: u8, _c: *const u16, _d: u32, blk: *mut u8) -> u32 {
        assert_eq!(core::ptr::read_unaligned((blk as usize).wrapping_add(4) as *const u8), 0x11);
        TAG.fetch_add(1, Ordering::SeqCst);
        9
    }
    #[test]
    fn tag_byte_is_0x11() {
        // Real `fn_00403f88` behind the die lane (nonzero result skips
        // the alloc lane; null raise slot skips raise; tail default
        // no-op): hold its lock set, pin the raise slot.
        let _b8 = crate::fn_004046b8::TEST_LOCK.lock().unwrap();
        let _ac = crate::fn_004046ac::TEST_LOCK.lock().unwrap();
        let _loop = crate::fn_00404580::TEST_LOCK.lock().unwrap();
        let _tls = crate::fn_00406588::TEST_LOCK.lock().unwrap();
        let (old_hook, old_tail);
        unsafe {
            old_hook = crate::fn_00403f88::HOOK_0041301C;
            old_tail = crate::fn_00403f88::TAIL_00413014;
            HOOK_00409860 = fmt;
            DAT_0040C550 = 1;
            DAT_0040CD14 = 2;
            crate::fn_00403f88::HOOK_0041301C = None;
        }
        unsafe { fn_0040ccdc(0x55) };
        unsafe {
            crate::fn_00403f88::HOOK_0041301C = old_hook;
            crate::fn_00403f88::TAIL_00413014 = old_tail;
        }
        assert_eq!(TAG.load(Ordering::SeqCst), 1);
    }
}
