//! Original procedure `0x0040cc3c` (43 bytes, `0x40cc3c–0x40cc66`).
//! Evidence: `evidence/0040cc3c_fn_0040cc3c.md`.

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

/// Target `0x403f88` (`FUN_00403f88`), called with the format result.
///
/// ponytail: hook standing in for done `fn_00403f88`, rewire to the real
/// call once cross-module linkage proven.
pub static mut HOOK_00403F88: unsafe extern "C" fn(u32) = default_die;

/// Cells `0x40c4dc` (dword-loaded first lane) and `0x40cc74` (format string).
///
/// ponytail: absolute-address cells as own-module statics, unify in
/// `data.rs` once data layout proven.
pub static mut DAT_0040C4DC: usize = 0;
pub static mut DAT_0040CC74: usize = 0;

/// `local_c=param_1, local_8=0; r=fmt([DAT],1,str,0,&block); die(r)`.
/// `param_1` EAX per `__register` observation.
pub unsafe fn fn_0040cc3c(param_1: u32) {
    // ponytail: 8-byte stack block `[u32 local_c, u8 local_8]`; one array
    // keeps the `+4` byte adjacent on host (separate locals would not).
    let mut block = [0u8; 8];
    core::ptr::write_unaligned(block.as_mut_ptr() as *mut u32, param_1);
    block[4] = 0;
    let r = HOOK_00409860(
        DAT_0040C4DC,
        1,
        DAT_0040CC74 as *const u16,
        0,
        block.as_mut_ptr(),
    );
    HOOK_00403F88(r);
}

#[cfg(test)]
mod tests {
    use super::{DAT_0040C4DC, DAT_0040CC74, HOOK_00403F88, HOOK_00409860, fn_0040cc3c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static P1: AtomicUsize = AtomicUsize::new(0);
    static P2: AtomicUsize = AtomicUsize::new(0);
    static P3: AtomicUsize = AtomicUsize::new(0);
    static P4: AtomicUsize = AtomicUsize::new(0);
    static BLK: AtomicUsize = AtomicUsize::new(0);
    static DIE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn fmt(p1: usize, p2: u8, p3: *const u16, p4: u32, p5: *mut u8) -> u32 {
        P1.store(p1, Ordering::SeqCst);
        P2.store(p2 as usize, Ordering::SeqCst);
        P3.store(p3 as usize, Ordering::SeqCst);
        P4.store(p4 as usize, Ordering::SeqCst);
        BLK.store(p5 as usize, Ordering::SeqCst);
        // Block must read back [param_1, 0x00] at its base.
        assert_eq!(core::ptr::read_unaligned(p5 as *const u32), 0x1234);
        assert_eq!(core::ptr::read_unaligned((p5 as usize).wrapping_add(4) as *const u8), 0);
        0x77
    }
    unsafe extern "C" fn die(c: u32) {
        DIE.store(c as usize, Ordering::SeqCst);
    }

    #[test]
    fn forwards_block_and_result() {
        unsafe {
            HOOK_00409860 = fmt;
            HOOK_00403F88 = die;
            DAT_0040C4DC = 0xaaa;
            DAT_0040CC74 = 0xbbb;
        }
        unsafe { fn_0040cc3c(0x1234) };
        assert_eq!(P1.load(Ordering::SeqCst), 0xaaa);
        assert_eq!(P2.load(Ordering::SeqCst), 1);
        assert_eq!(P3.load(Ordering::SeqCst), 0xbbb);
        assert_eq!(P4.load(Ordering::SeqCst), 0);
        assert_ne!(BLK.load(Ordering::SeqCst), 0);
        assert_eq!(DIE.load(Ordering::SeqCst), 0x77);
    }
}
