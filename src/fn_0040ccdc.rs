//! Original procedure `0x0040ccdc` (43 bytes, `0x40ccdc–0x40cd06`).
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
unsafe extern "C" fn default_die(_c: u32) {}

/// Target `0x409860` (`FUN_00409860`), 5 lanes `(EAX,DL,ECX,0,&block)`.
///
/// ponytail: hook standing in for done `fn_00409860`, rewire to the real
/// call once cross-module linkage proven.
pub static mut HOOK_00409860: unsafe extern "C" fn(usize, u8, *const u16, u32, *mut u8) -> u32 =
    default_fmt;

/// Target `0x403f88` (`FUN_00403f88`).
///
/// ponytail: hook standing in for done `fn_00403f88`, rewire to the real
/// call once cross-module linkage proven.
pub static mut HOOK_00403F88: unsafe extern "C" fn(u32) = default_die;

/// Cells `0x40c550` (first lane) and `0x40cd14` (`lzmadecompsmall: %s`).
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
    HOOK_00403F88(r);
}

#[cfg(test)]
mod tests {
    use super::{DAT_0040C550, DAT_0040CD14, HOOK_00403F88, HOOK_00409860, fn_0040ccdc};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TAG: AtomicUsize = AtomicUsize::new(0);
    static DIE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn fmt(_a: usize, _b: u8, _c: *const u16, _d: u32, blk: *mut u8) -> u32 {
        assert_eq!(core::ptr::read_unaligned((blk as usize).wrapping_add(4) as *const u8), 0x11);
        TAG.fetch_add(1, Ordering::SeqCst);
        9
    }
    unsafe extern "C" fn die(c: u32) {
        DIE.store(c as usize, Ordering::SeqCst);
    }

    #[test]
    fn tag_byte_is_0x11() {
        unsafe {
            HOOK_00409860 = fmt;
            HOOK_00403F88 = die;
            DAT_0040C550 = 1;
            DAT_0040CD14 = 2;
        }
        unsafe { fn_0040ccdc(0x55) };
        assert_eq!(TAG.load(Ordering::SeqCst), 1);
        assert_eq!(DIE.load(Ordering::SeqCst), 9);
    }
}
