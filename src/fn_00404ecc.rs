//! Original procedure `0x00404ecc` (38 bytes, `0x00404ecc–0x00404ef1`).
//! Evidence: `evidence/00404ecc_fn_00404ecc.md`.

use crate::fn_00404af0::fn_00404af0;
use crate::fn_00404b9c::fn_00404b9c;

/// `len=0; if p2!=0 { len=[p2-4]; if [p2-10]!=2 {
/// 4af0(slot,p2,len,[p2-12]); return } }; 4b9c(slot,p2,len)`.
/// Short-circuit order isomorphic: null skips both the length
/// load and the tag test. Params arrive in EAX/EDX per Ghidra
/// `__register` observation. The `XCHG [ESP],ECX / PUSH ECX /
/// MOVZX / XCHG [ESP+4],ECX` shuffle only parks `len` and the
/// tag word below the return address for the terminal `JMP 4af0`
/// (3rd/4th stack args); both exits terminal, modeled as
/// call+return per decompiler. Header words stay `u16`/`u32`
/// per observed widths. Direct calls to done callees (no hooks).
pub unsafe fn fn_00404ecc(param_1: *mut u32, param_2: *mut u8) {
    let mut len: u32 = 0;
    if !param_2.is_null() {
        len = core::ptr::read_unaligned(param_2.wrapping_byte_offset(-4) as *const u32);
        if core::ptr::read_unaligned(param_2.wrapping_byte_offset(-10) as *const u16) != 2 {
            let tag = core::ptr::read_unaligned(param_2.wrapping_byte_offset(-12) as *const u16);
            fn_00404af0(param_1, param_2, len as i32, tag as u32);
            return;
        }
    }
    fn_00404b9c(param_1, param_2 as *const u16, len);
}

#[cfg(test)]
mod tests {
    use super::fn_00404ecc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CLEAR_HITS: AtomicUsize = AtomicUsize::new(0);
    static CONV_CALLS: AtomicUsize = AtomicUsize::new(0);
    static CONV_CAP: AtomicUsize = AtomicUsize::new(0);
    static CONV_SRC: AtomicUsize = AtomicUsize::new(0);
    static CONV_P4: AtomicUsize = AtomicUsize::new(0);
    static CONV_N: AtomicUsize = AtomicUsize::new(0);
    static STORE_HITS: AtomicUsize = AtomicUsize::new(0);
    static STORE_N: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static FREE_HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_FREE: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn clear(_slot: *mut u32) {
        CLEAR_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn convert(
        _buf: *mut u16,
        cap: u32,
        src: *const u8,
        p4: u32,
        count: i32,
    ) -> i32 {
        CONV_CALLS.fetch_add(1, Ordering::SeqCst);
        CONV_CAP.store(cap as usize, Ordering::SeqCst);
        CONV_SRC.store(src as usize, Ordering::SeqCst);
        CONV_P4.store(p4 as usize, Ordering::SeqCst);
        CONV_N.store(count as usize, Ordering::SeqCst);
        3
    }

    unsafe extern "C" fn store(_slot: *mut u32, _buf: *const u16, n: u32) {
        STORE_HITS.fetch_add(1, Ordering::SeqCst);
        STORE_N.store(n as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn alloc(_psz: u32, _cch: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn free_hook(bstr: u32) {
        FREE_HITS.fetch_add(1, Ordering::SeqCst);
        GOT_FREE.store(bstr as usize, Ordering::SeqCst);
    }

    /// Header arena: obj = base+12; tag u16 @+2 (`obj-10`),
    /// tag2 u16 @+0 (`obj-12`), len u32 @+8 (`obj-4`).
    unsafe fn hdr(buf: &mut [u8; 32], tag: u16, tag2: u16, len: u32) -> *mut u8 {
        let base = buf.as_mut_ptr();
        core::ptr::write_unaligned(base.wrapping_add(0) as *mut u16, tag2);
        core::ptr::write_unaligned(base.wrapping_add(2) as *mut u16, tag);
        core::ptr::write_unaligned(base.wrapping_add(8) as *mut u32, len);
        base.wrapping_add(12)
    }

    #[test]
    fn dispatch_lanes() {
        // 4af0's hooks have no owner lock: set + restore. 4b9c's
        // import hooks are owner-locked: hold both guards.
        let _guard_a = crate::fn_00404a64::TEST_LOCK.lock().unwrap();
        let _guard_b = crate::fn_00404a7c::TEST_LOCK.lock().unwrap();
        let old_clear = unsafe { crate::fn_00404af0::HOOK_00404A8C };
        let old_conv = unsafe { crate::fn_00404af0::HOOK_004047EC };
        let old_store = unsafe { crate::fn_00404af0::HOOK_00404B9C };
        let old_alloc = unsafe { crate::fn_00404a64::SYS_ALLOC_STRING_LEN_00401180 };
        let old_free = unsafe { crate::fn_00404a7c::SYS_FREE_STRING_00401190 };
        unsafe {
            crate::fn_00404af0::HOOK_00404A8C = clear;
            crate::fn_00404af0::HOOK_004047EC = convert;
            crate::fn_00404af0::HOOK_00404B9C = store;
            crate::fn_00404a64::SYS_ALLOC_STRING_LEN_00401180 = alloc;
            crate::fn_00404a7c::SYS_FREE_STRING_00401190 = free_hook;
        }

        // Null lane: real 4b9c(slot,null,0) → 4a8c clear path; slot is
        // already 0 so 4a8c skips the free (null old → no hook fire).
        // (ecc itself returns void per observed signature; only slot
        // state is asserted.)
        let mut slot = 0u32;
        let p = &mut slot as *mut u32;
        FREE_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404ecc(p, core::ptr::null_mut()) };
        assert_eq!(slot, 0);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 0);

        // Tag==2 lane: real 4b9c(slot,src,len=3) → alloc hit,
        // old freed, slot+ret take the new string.
        let mut abuf = [0u8; 32];
        let pa = unsafe { hdr(&mut abuf, 2, 0, 3) };
        ALLOC_RET.store(0x99, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FREE_HITS.store(0, Ordering::SeqCst);
        slot = 0x22;
        unsafe { fn_00404ecc(p, pa) };
        assert_eq!(slot, 0x99);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_FREE.load(Ordering::SeqCst), 0x22);

        // Foreign-tag lane: 4af0(slot,src,3,tag2=0x33) →
        // stack convert (cap 0x7ff) hit → store n=3.
        let mut bbuf = [0u8; 32];
        let pb = unsafe { hdr(&mut bbuf, 7, 0x33, 3) };
        CLEAR_HITS.store(0, Ordering::SeqCst);
        CONV_CALLS.store(0, Ordering::SeqCst);
        STORE_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404ecc(p, pb) };
        assert_eq!(CONV_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(CONV_CAP.load(Ordering::SeqCst), 0x7ff);
        assert_eq!(CONV_SRC.load(Ordering::SeqCst), pb as usize);
        assert_eq!(CONV_P4.load(Ordering::SeqCst), 0x33);
        assert_eq!(CONV_N.load(Ordering::SeqCst), 3);
        assert_eq!(STORE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(STORE_N.load(Ordering::SeqCst), 3);
        assert_eq!(CLEAR_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);

        unsafe {
            crate::fn_00404af0::HOOK_00404A8C = old_clear;
            crate::fn_00404af0::HOOK_004047EC = old_conv;
            crate::fn_00404af0::HOOK_00404B9C = old_store;
            crate::fn_00404a64::SYS_ALLOC_STRING_LEN_00401180 = old_alloc;
            crate::fn_00404a7c::SYS_FREE_STRING_00401190 = old_free;
        }
    }
}
