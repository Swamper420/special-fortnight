//! Original procedure `0x00404e94` (34 bytes, `0x404e94–0x404eb5`).
//! Evidence: `evidence/00404e94_fn_00404e94.md`.

use crate::fn_00404718::fn_00404718;
use crate::fn_00404850::fn_00404850;

/// `p2==0 → 4850(slot,0,0,p3)`; tag `[p2-10]==1 → 4718(slot,p2)`;
/// else `4850(slot,p2,[p2-4],p3)`. `param_1` arrives in EAX,
/// `param_2` in EDX, `param_3` in CX per Ghidra `__register`
/// observation. The entry `XCHG [ESP],ECX / PUSH ECX` parks the
/// full ECX below the return address for the terminal `JMP 4850`
/// (4th stack arg); the tag-1 lane pops it back before the
/// terminal `JMP 4718`. All exits terminal, modeled as
/// call+return per decompiler. Header words stay `u16`/`u32`
/// per observed widths. Direct calls to done callees (no hooks).
pub unsafe fn fn_00404e94(param_1: *mut u8, param_2: *mut u8, param_3: u16) {
    if param_2.is_null() {
        fn_00404850(
            param_1 as *mut u32,
            core::ptr::null_mut(),
            0,
            param_3,
        );
        return;
    }
    if core::ptr::read_unaligned(param_2.wrapping_byte_offset(-10) as *const u16) == 1 {
        fn_00404718(param_1 as *mut usize, param_2);
        return;
    }
    let len = core::ptr::read_unaligned(param_2.wrapping_byte_offset(-4) as *const u32);
    fn_00404850(param_1 as *mut u32, param_2 as *mut u16, len as i32, param_3);
}

#[cfg(test)]
mod tests {
    use super::fn_00404e94;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static REL_HITS: AtomicUsize = AtomicUsize::new(0);
    static CVT_HITS: AtomicUsize = AtomicUsize::new(0);
    static CVT_TAG: AtomicUsize = AtomicUsize::new(0);
    static CVT_COUNT: AtomicUsize = AtomicUsize::new(0);
    static CVT_SIZE: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_SIZE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn release(_a: *mut u32) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn convert(_a: *mut u8, _b: u32, _c: *mut u16, d: u32, e: i32) -> u32 {
        CVT_HITS.fetch_add(1, Ordering::SeqCst);
        CVT_TAG.store(d as usize, Ordering::SeqCst);
        CVT_COUNT.store(e as usize, Ordering::SeqCst);
        CVT_SIZE.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn alloc(_a: *mut u32, b: u32, _c: u32) {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_SIZE.store(b as usize, Ordering::SeqCst);
    }

    /// Header arena: obj = base+12; tag u16 @+2 (`obj-10`),
    /// len u32 @+8 (`obj-4`), refcount u32 @+4 (`obj-8`).
    unsafe fn hdr(buf: &mut [u8; 32], tag: u16, len: u32, rc: u32) -> *mut u8 {
        let base = buf.as_mut_ptr();
        core::ptr::write_unaligned(base.wrapping_add(2) as *mut u16, tag);
        core::ptr::write_unaligned(base.wrapping_add(4) as *mut u32, rc);
        core::ptr::write_unaligned(base.wrapping_add(8) as *mut u32, len);
        base.wrapping_add(12)
    }

    #[test]
    fn dispatch_lanes() {
        // Downstream hooks owned by done fn_00404850 (no owner
        // lock): set + restore everything this test can reach.
        let old_rel = unsafe { crate::fn_00404850::HOOK_004046C4 };
        let old_cvt = unsafe { crate::fn_00404850::HOOK_004047C0 };
        let old_alloc = unsafe { crate::fn_00404850::HOOK_004049C4 };
        unsafe {
            crate::fn_00404850::HOOK_004046C4 = release;
            crate::fn_00404850::HOOK_004047C0 = convert;
            crate::fn_00404850::HOOK_004049C4 = alloc;
        }

        let mut slot: *mut u8 = core::ptr::null_mut();
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;

        // Null lane: 4850(slot,null,0,p3) → count<1 → release only.
        REL_HITS.store(0, Ordering::SeqCst);
        CVT_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404e94(slot_ptr, core::ptr::null_mut(), 7) };
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CVT_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);

        // Tag==1 lane: 4718 acquire (rc 5→6), old null, no hooks.
        let mut abuf = [0u8; 32];
        let p2 = unsafe { hdr(&mut abuf, 1, 4, 5) };
        slot = core::ptr::null_mut();
        unsafe { fn_00404e94(slot_ptr, p2, 7) };
        assert_eq!(slot, p2);
        assert_eq!(unsafe { core::ptr::read_unaligned(p2.wrapping_byte_offset(-8) as *const u32) }, 6);

        // Foreign-tag lane: 4850(slot,src,len=9,p3=4) → probe
        // (NULL,0,src,tag=4,count=9), alloc(size 0), release.
        let mut bbuf = [0u8; 32];
        let p3 = unsafe { hdr(&mut bbuf, 7, 9, 0) };
        slot = core::ptr::null_mut();
        REL_HITS.store(0, Ordering::SeqCst);
        CVT_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        CVT_SIZE.store(0, Ordering::SeqCst);
        unsafe { fn_00404e94(slot_ptr, p3, 4) };
        assert_eq!(CVT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CVT_TAG.load(Ordering::SeqCst), 4);
        assert_eq!(CVT_COUNT.load(Ordering::SeqCst), 9);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_SIZE.load(Ordering::SeqCst), 0);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);

        unsafe {
            crate::fn_00404850::HOOK_004046C4 = old_rel;
            crate::fn_00404850::HOOK_004047C0 = old_cvt;
            crate::fn_00404850::HOOK_004049C4 = old_alloc;
        }
    }
}
