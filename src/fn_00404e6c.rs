//! Original procedure `0x00404e6c` (39 bytes, `0x404e6c–0x404e92`).
//! Evidence: `evidence/00404e6c_fn_00404e6c.md`.

use crate::fn_00404c98::fn_00404c98;
use crate::fn_00404d30::fn_00404d30;
use crate::fn_00404dc4::fn_00404dc4;

/// `p2==0 → 4dc4(slot,0,0)`; tag `[p2-10]==2 → 4c98(slot,p2)`;
/// else `4d30(slot,p2,[p2-4],[p2-12])`. Params arrive in EAX/EDX
/// per Ghidra `__register` observation. The `XCHG [ESP],ECX /
/// PUSH ECX` shuffle only parks the tag word below the return
/// address for the terminal `JMP 4d30` (4th stack arg); all three
/// exits are terminal jumps, modeled as call+return per
/// decompiler. Header words stay `u16`/`u32` per observed widths.
/// Direct calls to done callees (no hooks).
pub unsafe fn fn_00404e6c(param_1: *mut u8, param_2: *mut u8) {
    if param_2.is_null() {
        fn_00404dc4(param_1, core::ptr::null(), 0);
        return;
    }
    if core::ptr::read_unaligned(param_2.wrapping_byte_offset(-10) as *const u16) == 2 {
        fn_00404c98(param_1, param_2);
        return;
    }
    let tag = core::ptr::read_unaligned(param_2.wrapping_byte_offset(-12) as *const u16);
    let len = core::ptr::read_unaligned(param_2.wrapping_byte_offset(-4) as *const u32);
    fn_00404d30(param_1, param_2, len, tag as u32);
}

#[cfg(test)]
mod tests {
    use super::fn_00404e6c;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CONV_HITS: AtomicUsize = AtomicUsize::new(0);
    static CONV_CAP: AtomicUsize = AtomicUsize::new(0);
    static CONV_SRC: AtomicUsize = AtomicUsize::new(0);
    static CONV_P4: AtomicUsize = AtomicUsize::new(0);
    static CONV_N: AtomicUsize = AtomicUsize::new(0);
    static CONV_RET: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL_C: AtomicUsize = AtomicUsize::new(0);
    static SIZE_HITS: AtomicUsize = AtomicUsize::new(0);

    const CANNED: u32 = 0x1122_3344;

    unsafe extern "C" fn convert(
        _dst: *mut u16,
        cap: u32,
        src: *const u8,
        p4: u32,
        n: u32,
    ) -> i32 {
        CONV_HITS.fetch_add(1, Ordering::SeqCst);
        CONV_CAP.store(cap as usize, Ordering::SeqCst);
        CONV_SRC.store(src as usize, Ordering::SeqCst);
        CONV_P4.store(p4 as usize, Ordering::SeqCst);
        CONV_N.store(n as usize, Ordering::SeqCst);
        CONV_RET.load(Ordering::SeqCst) as i32
    }

    unsafe extern "C" fn size(_slot: *mut u8, _n: u32) {
        SIZE_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn alloc(n: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        CANNED
    }

    unsafe extern "C" fn fill(_a: *mut u8, _b: u32, c: u32) {
        FILL_HITS.fetch_add(1, Ordering::SeqCst);
        FILL_C.store(c as usize, Ordering::SeqCst);
    }

    /// Header arena: obj = base+12; tag u16 @+2 (`obj-10`),
    /// tag2 u16 @+0 (`obj-12`), len u32 @+8 (`obj-4`),
    /// refcount u32 @+4 (`obj-8`).
    unsafe fn hdr(buf: &mut [u8; 32], tag: u16, tag2: u16, len: u32, rc: u32) -> *mut u8 {
        let base = buf.as_mut_ptr();
        core::ptr::write_unaligned(base.wrapping_add(0) as *mut u16, tag2);
        core::ptr::write_unaligned(base.wrapping_add(2) as *mut u16, tag);
        core::ptr::write_unaligned(base.wrapping_add(4) as *mut u32, rc);
        core::ptr::write_unaligned(base.wrapping_add(8) as *mut u32, len);
        base.wrapping_add(12)
    }

    #[test]
    fn dispatch_lanes() {
        // Downstream hooks owned elsewhere (no owner locks exist):
        // set + restore everything this test's lanes can reach.
        let old_conv = unsafe { crate::fn_00404d30::HOOK_004047ec };
        let old_size = unsafe { crate::fn_00404d30::HOOK_00404f00 };
        let old_alloc = unsafe { crate::fn_00404dd4::HOOK_004054b4 };
        let old_fill = unsafe { crate::fn_00404dd4::HOOK_00402fbc };
        unsafe {
            crate::fn_00404d30::HOOK_004047ec = convert;
            crate::fn_00404d30::HOOK_00404f00 = size;
            crate::fn_00404dd4::HOOK_004054b4 = alloc;
            crate::fn_00404dd4::HOOK_00402fbc = fill;
        }

        // Null lane: 4dc4(slot,null,0) → 4d30 p3=0 → release old.
        // Old rc=2 → dec to 1, no dtor hook involved.
        let mut abuf = [0u8; 32];
        let mut slot: *mut u8 = unsafe { hdr(&mut abuf, 2, 0, 0, 2) };
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;
        CONV_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404e6c(slot_ptr, core::ptr::null_mut()) };
        assert!(slot.is_null());
        assert_eq!(unsafe { core::ptr::read_unaligned(abuf.as_ptr().wrapping_add(4) as *const u32) }, 1);
        assert_eq!(CONV_HITS.load(Ordering::SeqCst), 0);

        // Tag==2 lane: 4c98 acquire (rc 5→6), old null, no hooks.
        let mut bbuf = [0u8; 32];
        let p2 = unsafe { hdr(&mut bbuf, 2, 0, 8, 5) };
        slot = core::ptr::null_mut();
        unsafe { fn_00404e6c(slot_ptr, p2) };
        assert_eq!(slot, p2);
        assert_eq!(unsafe { core::ptr::read_unaligned(p2.wrapping_byte_offset(-8) as *const u32) }, 6);

        // Foreign-tag lane: 4d30(slot,src,len=5,tag2=0x51).
        // Stack convert path (ret 3): alloc(3), fill 3<<1=6.
        let mut cbuf = [0u8; 32];
        let p3 = unsafe { hdr(&mut cbuf, 7, 0x51, 5, 0) };
        slot = core::ptr::null_mut();
        CONV_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        SIZE_HITS.store(0, Ordering::SeqCst);
        CONV_RET.store(3, Ordering::SeqCst);
        unsafe { fn_00404e6c(slot_ptr, p3) };
        assert_eq!(CONV_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CONV_CAP.load(Ordering::SeqCst), 0x7ff);
        assert_eq!(CONV_SRC.load(Ordering::SeqCst), p3 as usize);
        assert_eq!(CONV_P4.load(Ordering::SeqCst), 0x51);
        assert_eq!(CONV_N.load(Ordering::SeqCst), 5);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 3);
        assert_eq!(FILL_C.load(Ordering::SeqCst), 6);
        assert_eq!(SIZE_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(slot as u32, CANNED);

        unsafe {
            crate::fn_00404d30::HOOK_004047ec = old_conv;
            crate::fn_00404d30::HOOK_00404f00 = old_size;
            crate::fn_00404dd4::HOOK_004054b4 = old_alloc;
            crate::fn_00404dd4::HOOK_00402fbc = old_fill;
        }
    }
}
