//! Original procedure `0x00404c2c` (81 bytes, `0x00404c2c–0x00404c7c`).
//! Evidence: `evidence/00404c2c_fn_00404c2c.md`.

use crate::fn_00404a64::fn_00404a64;
use crate::fn_00404a7c::fn_00404a7c;
use crate::fn_00404dd4::HOOK_00402fbc;

/// `new=0; if p2>0 { new=4a64(p2); cur=*p1; n=cur?[cur-4]>>1:0;
/// if n>0 { n=min(p2,n); 02fbc(cur,new,n+n) } }; 4a7c(p1,new)`.
/// `param_1` arrives in EAX (slot cell), `param_2` in EDX per Ghidra
/// `__register` observation. Guards isomorphic: signed `JLE` on
/// `param_2`, signed `JLE` on the header count, signed `JGE` for the
/// min. Slot cell is opaque (`*mut u8`); the stored link reads
/// pointer-sized (one MOV on the i686 target); header/count stay
/// `u32` per observed widths. `ADD ECX,ECX` is `wrapping_add`.
/// Direct calls to done `fn_00404a64`/`fn_00404a7c` (no hooks); fill
/// reuses `HOOK_00402fbc` from done `fn_00404dd4`.
///
/// ponytail: non-atomic host model of the implicitly-locked `XCHG`
/// inside `fn_00404a7c` (same ceiling as LOCK atomics elsewhere).
pub unsafe fn fn_00404c2c(param_1: *mut u8, param_2: u32) {
    let mut new: u32 = 0;
    if (param_2 as i32) > 0 {
        new = fn_00404a64(param_2);
        let cur: *mut u8 = core::ptr::read_unaligned(param_1 as *const *mut u8);
        let mut n: u32 = 0;
        if !cur.is_null() {
            n = core::ptr::read_unaligned(cur.wrapping_byte_offset(-4) as *const u32) >> 1;
        }
        if (n as i32) > 0 {
            if (param_2 as i32) < (n as i32) {
                n = param_2;
            }
            HOOK_00402fbc(cur, new, n.wrapping_add(n));
        }
    }
    fn_00404a7c(param_1 as *mut u32, new);
}

#[cfg(test)]
mod tests {
    use super::fn_00404c2c;
    use crate::fn_00404dd4::HOOK_00402fbc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FREE_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL_A: AtomicUsize = AtomicUsize::new(0);
    static FILL_B: AtomicUsize = AtomicUsize::new(0);
    static FILL_C: AtomicUsize = AtomicUsize::new(0);

    const CANNED_NEW: u32 = 0x0A11CE;

    unsafe extern "C" fn alloc(_psz: u32, cch: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(cch as usize, Ordering::SeqCst);
        CANNED_NEW
    }

    unsafe extern "C" fn tail(_arg: u32) {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn free_hook(_bstr: u32) {
        FREE_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn fill(a: *mut u8, b: u32, c: u32) {
        FILL_HITS.fetch_add(1, Ordering::SeqCst);
        FILL_A.store(a as usize, Ordering::SeqCst);
        FILL_B.store(b as usize, Ordering::SeqCst);
        FILL_C.store(c as usize, Ordering::SeqCst);
    }

    /// BSTR-like cell: byte length at `buf+4`, chars at `buf+8`.
    unsafe fn bstr(buf: *mut u8, byte_len: u32) -> *mut u8 {
        core::ptr::write_unaligned(buf.wrapping_byte_add(4) as *mut u32, byte_len);
        buf.wrapping_byte_add(8)
    }

    unsafe fn slot_lo(slot_ptr: *mut u8) -> u32 {
        core::ptr::read_unaligned(slot_ptr as *const u32)
    }

    #[test]
    fn alloc_copy_exchange_lanes() {
        // Shared fn_00404dd4 hooks: hold the common owner lock first.
        let _shared = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        // Done callees read their hook globals: hold both owner
        // locks so their writer tests can't race us.
        let _a = crate::fn_00404a64::TEST_LOCK.lock().unwrap();
        let _f = crate::fn_00404a7c::TEST_LOCK.lock().unwrap();
        unsafe {
            crate::fn_00404a64::SYS_ALLOC_STRING_LEN_00401180 = alloc;
            crate::fn_00404a64::TAIL_00402F60 = tail;
            crate::fn_00404a7c::SYS_FREE_STRING_00401190 = free_hook;
            HOOK_00402fbc = fill;
        }

        // Release arena: obj = base+12, count cell = base+4.
        let mut arena = [0u32; 4];
        let base = arena.as_mut_ptr() as *mut u8;
        let obj = unsafe { base.wrapping_byte_add(12) };

        // Zero-count lane: no alloc/fill, old freed, slot cleared.
        let mut slot: *mut u8 = obj;
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        FREE_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404c2c(slot_ptr, 0) };
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { slot_lo(slot_ptr) }, 0);

        // Negative-count lane: same skip (`JLE` is signed).
        slot = obj;
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        FREE_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404c2c(slot_ptr, 0xffffffff) };
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { slot_lo(slot_ptr) }, 0);

        // Null-slot lane: alloc fires, no fill, no free.
        slot = core::ptr::null_mut();
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        FREE_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404c2c(slot_ptr, 5) };
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 5);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { slot_lo(slot_ptr) }, CANNED_NEW);

        // Min lane: header 8 → n=4, p2=2 → fill bytes 2+2=4.
        let mut cell = [0u8; 16];
        let cur = unsafe { bstr(cell.as_mut_ptr(), 8) };
        slot = cur;
        FILL_HITS.store(0, Ordering::SeqCst);
        FREE_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404c2c(slot_ptr, 2) };
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FILL_A.load(Ordering::SeqCst), cur as usize);
        assert_eq!(FILL_B.load(Ordering::SeqCst), CANNED_NEW as usize);
        assert_eq!(FILL_C.load(Ordering::SeqCst), 4);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { slot_lo(slot_ptr) }, CANNED_NEW);

        // Clamp lane: header 8 → n=4, p2=10 → fill bytes 4+4=8.
        slot = cur;
        FILL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404c2c(slot_ptr, 10) };
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FILL_C.load(Ordering::SeqCst), 8);
        assert_eq!(unsafe { slot_lo(slot_ptr) }, CANNED_NEW);

        // Zero-header lane: n=0 → no fill, exchange still runs.
        let mut cell0 = [0u8; 16];
        let cur0 = unsafe { bstr(cell0.as_mut_ptr(), 0) };
        slot = cur0;
        FILL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404c2c(slot_ptr, 3) };
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { slot_lo(slot_ptr) }, CANNED_NEW);
    }
}
