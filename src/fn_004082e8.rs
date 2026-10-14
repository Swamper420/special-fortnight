//! Original procedure `0x004082e8` (390 bytes, `0x4082e8–0x40846d`).
//! Evidence: `evidence/004082e8_fn_004082e8.md`.

use crate::fn_004046c4::fn_004046c4;
use crate::fn_00404820::fn_00404820;
use crate::fn_0040493c::fn_0040493c;
use crate::fn_00404c98::fn_00404c98;
use crate::fn_00404d24::fn_00404d24;
use crate::fn_00404dd4::fn_00404dd4;
use crate::fn_00404f00::fn_00404f00;
use crate::fn_00408274::fn_00408274;

/// Test-only serialization for tests sharing this module's locals
/// (also held by cross-module tests that drive `fn_004082e8`).
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

unsafe fn tag_at(p: *mut u16) -> u16 {
    core::ptr::read_unaligned(p.wrapping_byte_offset(-10) as *const u16)
}

unsafe fn len_at(p: *mut u16) -> u32 {
    core::ptr::read_unaligned(p.wrapping_byte_offset(-4) as *const u32)
}

/// One normalize site: `null → skip; tag==2 → keep; else
/// 00404820(&slot, cur)`. Returns the `EAX` value. `fn_00404820`
/// returns the re-read slot truncated to `u32`, so the full pointer
/// is re-read instead (identical value on target).
unsafe fn normalize(slot: *mut *mut u16) -> *mut u16 {
    let cur: *mut u16 = core::ptr::read_unaligned(slot);
    if cur.is_null() || tag_at(cur) == 2 {
        return cur;
    }
    fn_00404820(slot as *mut u32, cur as *mut u8);
    core::ptr::read_unaligned(slot)
}

/// Format-into-slot with doubling growth. `param_1` is the slot
/// address (reloaded, never cached), `param_2` the string object,
/// `param_3/param_4` opaque format args forwarded as `(p4, p3)`.
/// Stack probe loop and SEH install/teardown have no host effect
/// (see evidence). Both thunks are transparent jumps; the done
/// targets are called directly.
pub unsafe fn fn_004082e8(param_1: *mut u8, param_2: *mut u16, param_3: u32, param_4: u32) {
    let mut local_8: *mut u16 = param_2;
    fn_0040493c(local_8 as *mut u8);
    // ~8 KB scratch (`[EBP-0x2010]`, `0x1000`-unit capacity).
    let mut buf = [0u16; 0x1000];
    let mut ebx: u32 = 0x1000;

    let p = normalize(&mut local_8 as *mut *mut u16);
    let mut i4: u32 = 0;
    if !p.is_null() {
        i4 = len_at(p);
    }
    let mut local_14: u32;
    if (i4 as i32) < 0xc00 {
        let q = normalize(&mut local_8 as *mut *mut u16);
        let mut n: u32 = 0;
        if !q.is_null() {
            n = len_at(q);
        }
        local_14 = fn_00408274(buf.as_mut_ptr(), 0xfff as *mut u16, local_8, param_4, param_3, n as i32);
    } else {
        let q = normalize(&mut local_8 as *mut *mut u16);
        ebx = 0;
        local_14 = 0;
        if !q.is_null() {
            ebx = len_at(q);
            local_14 = ebx;
        }
    }
    if (ebx.wrapping_sub(1) as i32) > (local_14 as i32) {
        fn_00404dd4(param_1, buf.as_mut_ptr() as *mut u8, local_14);
    } else {
        loop {
            ebx = ebx.wrapping_add(ebx);
            fn_00404c98(param_1, core::ptr::null_mut());
            fn_00404f00(param_1 as *mut *mut u8, ebx);
            let s = normalize(&mut local_8 as *mut *mut u16);
            let mut edi: u32 = 0;
            if !s.is_null() {
                edi = len_at(s);
            }
            let slot_ptr: *const u8 = core::ptr::read_unaligned(param_1 as *const *const u8);
            let e = fn_00404d24(slot_ptr);
            local_14 = fn_00408274(
                e as *mut u16,
                (ebx.wrapping_sub(1)) as usize as *mut u16,
                local_8,
                param_4,
                param_3,
                edi as i32,
            );
            if (ebx.wrapping_sub(1) as i32) > (local_14 as i32) {
                break;
            }
        }
        fn_00404f00(param_1 as *mut *mut u8, local_14);
    }
    fn_004046c4(&mut local_8 as *mut *mut u16 as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{TEST_LOCK, fn_004082e8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static FMT_CALLS: AtomicUsize = AtomicUsize::new(0);
    static FMT_MODE: AtomicUsize = AtomicUsize::new(0);
    static FMT_A1: AtomicUsize = AtomicUsize::new(0);
    static FMT_A2: AtomicUsize = AtomicUsize::new(0);
    static FMT_A3: AtomicUsize = AtomicUsize::new(0);
    static FMT_A4: AtomicUsize = AtomicUsize::new(0);
    static FMT_A5: AtomicUsize = AtomicUsize::new(0);
    static FMT_A6: AtomicUsize = AtomicUsize::new(0);
    static FMT_B2: AtomicUsize = AtomicUsize::new(0);
    static FMT_B3: AtomicUsize = AtomicUsize::new(0);
    static FMT_B4: AtomicUsize = AtomicUsize::new(0);
    static FMT_B5: AtomicUsize = AtomicUsize::new(0);
    static FMT_B6: AtomicUsize = AtomicUsize::new(0);
    static NORM_HITS: AtomicUsize = AtomicUsize::new(0);
    static FWD_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL_A: AtomicUsize = AtomicUsize::new(0);
    static FILL_B: AtomicUsize = AtomicUsize::new(0);
    static FILL_C: AtomicUsize = AtomicUsize::new(0);
    static P00_ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static P00_ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static P00_ALLOC_RET: AtomicUsize = AtomicUsize::new(0);
    static P00_REALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static P00_REALLOC_TOTAL: AtomicUsize = AtomicUsize::new(0);
    static P00_COPY_HITS: AtomicUsize = AtomicUsize::new(0);
    static P00_NORM_HITS: AtomicUsize = AtomicUsize::new(0);
    static P00_FAIL_HITS: AtomicUsize = AtomicUsize::new(0);

    const CANNED: u32 = 0x1122_3344;

    unsafe extern "C" fn format_hook(
        p1: *mut u16,
        p2: *mut u16,
        p3: *mut u16,
        p4: u32,
        p5: u32,
        p6: i32,
    ) -> u32 {
        let n = FMT_CALLS.fetch_add(1, Ordering::SeqCst);
        FMT_A1.store(p1 as usize, Ordering::SeqCst);
        FMT_A2.store(p2 as usize, Ordering::SeqCst);
        FMT_A3.store(p3 as usize, Ordering::SeqCst);
        FMT_A4.store(p4 as usize, Ordering::SeqCst);
        FMT_A5.store(p5 as usize, Ordering::SeqCst);
        FMT_A6.store(p6 as usize, Ordering::SeqCst);
        if n == 0 {
            FMT_B2.store(p2 as usize, Ordering::SeqCst);
            FMT_B3.store(p3 as usize, Ordering::SeqCst);
            FMT_B4.store(p4 as usize, Ordering::SeqCst);
            FMT_B5.store(p5 as usize, Ordering::SeqCst);
            FMT_B6.store(p6 as usize, Ordering::SeqCst);
        }
        if FMT_MODE.load(Ordering::SeqCst) == 1 {
            [0x1000u32, 5][if n == 0 { 0 } else { 1 }]
        } else {
            5
        }
    }

    unsafe extern "C" fn norm_callee(_a: *mut u32, _b: *mut u8) {
        NORM_HITS.fetch_add(1, Ordering::SeqCst);
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

    unsafe extern "C" fn fwd(_slot: *mut u8, _src: *mut u8) {
        FWD_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn p00_alloc(n: u32) -> *mut u8 {
        P00_ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        P00_ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        P00_ALLOC_RET.load(Ordering::SeqCst) as *mut u8
    }

    unsafe extern "C" fn p00_realloc(_slot: *mut *mut u8, total: u32) {
        P00_REALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        P00_REALLOC_TOTAL.store(total as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn p00_copy(_s: *mut u8, _d: *mut u8, _n: u32) {
        P00_COPY_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn p00_norm(_o: *mut u8, _s: *mut u8) {
        P00_NORM_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn p00_fail(_b: *mut u8) {
        P00_FAIL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    /// Header arena: obj = base+12; tag u16 @+2 (`obj-10`),
    /// refcount u32 @+4 (`obj-8`), len u32 @+8 (`obj-4`).
    unsafe fn arena(a: &mut [u8; 32], tag: u16, rc: u32, len: u32) -> (*mut u8, *mut u16) {
        let base = a.as_mut_ptr();
        core::ptr::write_unaligned(base.wrapping_add(2) as *mut u16, tag);
        core::ptr::write_unaligned(base.wrapping_add(4) as *mut u32, rc);
        core::ptr::write_unaligned(base.wrapping_add(8) as *mut u32, len);
        (base.wrapping_add(12), base.wrapping_add(12) as *mut u16)
    }

    unsafe fn rc_of(base: *mut u8) -> u32 {
        core::ptr::read_unaligned(base.wrapping_add(4) as *const u32)
    }

    fn reset() {
        FMT_CALLS.store(0, Ordering::SeqCst);
        NORM_HITS.store(0, Ordering::SeqCst);
        FWD_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        P00_ALLOC_HITS.store(0, Ordering::SeqCst);
        P00_REALLOC_HITS.store(0, Ordering::SeqCst);
        P00_COPY_HITS.store(0, Ordering::SeqCst);
        P00_NORM_HITS.store(0, Ordering::SeqCst);
        P00_FAIL_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn small_and_growth_lanes() {
        // Foreign hooks/cells live in other modules: hold the common
        // owner lock first, then the sibling format lock, then own.
        let _common = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let _f74 = crate::fn_00408274::TEST_LOCK.lock().unwrap();
        let _own = TEST_LOCK.lock().unwrap();
        let s74 = unsafe { crate::fn_00408274::HOOK_00408540 };
        let s4820 = unsafe { crate::fn_00404820::CALLEE_00404E6C };
        let sdd_a = unsafe { crate::fn_00404dd4::HOOK_004054b4 };
        let sdd_f = unsafe { crate::fn_00404dd4::HOOK_00402fbc };
        let sc98 = unsafe { crate::fn_00404c98::HOOK_00404e6c };
        let s00_a = unsafe { crate::fn_00404f00::HOOK_004054b4 };
        let s00_c = unsafe { crate::fn_00404f00::HOOK_00402fbc };
        let s00_r = unsafe { crate::fn_00404f00::HOOK_00402e38 };
        let s00_n = unsafe { crate::fn_00404f00::HOOK_00404e6c };
        let s00_f = unsafe { crate::fn_00404f00::FAIL_00402F60 };
        unsafe {
            crate::fn_00408274::HOOK_00408540 = format_hook;
            crate::fn_00404820::CALLEE_00404E6C = norm_callee;
            crate::fn_00404dd4::HOOK_004054b4 = alloc;
            crate::fn_00404dd4::HOOK_00402fbc = fill;
            crate::fn_00404c98::HOOK_00404e6c = fwd;
            crate::fn_00404f00::HOOK_004054b4 = p00_alloc;
            crate::fn_00404f00::HOOK_00402fbc = p00_copy;
            crate::fn_00404f00::HOOK_00402e38 = p00_realloc;
            crate::fn_00404f00::HOOK_00404e6c = p00_norm;
            crate::fn_00404f00::FAIL_00402F60 = p00_fail;
        }

        // Lane A: null object, null slot. AddRef no-op, normalize
        // skipped, format(buf, 0xfff, 0, p4, p3, 0) -> 5 < 0xfff,
        // alloc/fill lane, release no-op.
        reset();
        FMT_MODE.store(0, Ordering::SeqCst);
        let mut slot_a: *mut u8 = core::ptr::null_mut();
        let pa = &mut slot_a as *mut *mut u8 as *mut u8;
        unsafe { fn_004082e8(pa, core::ptr::null_mut(), 0x4444_4444, 0x5555_5555) };
        assert_eq!(FMT_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(FMT_A2.load(Ordering::SeqCst), 0xfff);
        assert_eq!(FMT_A3.load(Ordering::SeqCst), 0);
        assert_eq!(FMT_A4.load(Ordering::SeqCst), 0x5555_5555);
        assert_eq!(FMT_A5.load(Ordering::SeqCst), 0x4444_4444);
        assert_eq!(FMT_A6.load(Ordering::SeqCst), 0);
        assert_eq!(NORM_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 5);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FILL_A.load(Ordering::SeqCst), FMT_A1.load(Ordering::SeqCst));
        assert_eq!(FILL_B.load(Ordering::SeqCst), CANNED as usize);
        assert_eq!(FILL_C.load(Ordering::SeqCst), 10);
        assert_eq!(slot_a, CANNED as usize as *mut u8);

        // Lane B: tag-2 object (rc 5, len 0x20), null slot. AddRef
        // 5->6, normalize skipped by tag, format sees obj and len,
        // teardown 6->5 with no dtor call.
        reset();
        FMT_MODE.store(0, Ordering::SeqCst);
        let mut ab = [0u8; 32];
        let (ob, ob16) = unsafe { arena(&mut ab, 2, 5, 0x20) };
        let base_b = ob.wrapping_byte_offset(-12);
        let mut slot_b: *mut u8 = core::ptr::null_mut();
        let pb = &mut slot_b as *mut *mut u8 as *mut u8;
        unsafe { fn_004082e8(pb, ob16, 0x4444_4444, 0x5555_5555) };
        assert_eq!(FMT_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(FMT_A2.load(Ordering::SeqCst), 0xfff);
        assert_eq!(FMT_A3.load(Ordering::SeqCst), ob as usize);
        assert_eq!(FMT_A6.load(Ordering::SeqCst), 0x20);
        assert_eq!(NORM_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { rc_of(base_b) }, 5);

        // Lane C: len 0xc00 takes the big lane (no pre-loop format);
        // iter1 doubles EBX 0xc00->0x1800, 00404c98 null exchange,
        // 00404f00 alloc of 0x1800 into the canned arena; the in-loop
        // format (budget 0x17ff) returns 5 < 0x17ff so the loop exits;
        // final 00404f00 grows in place (realloc total 5*2+14=24).
        reset();
        FMT_MODE.store(0, Ordering::SeqCst);
        let mut ac = [0u8; 32];
        let (oc, oc16) = unsafe { arena(&mut ac, 2, 5, 0xc00) };
        let base_c = oc.wrapping_byte_offset(-12);
        let mut anb = [0u8; 32];
        let (nb, _nb16) = unsafe { arena(&mut anb, 2, 1, 0) };
        P00_ALLOC_RET.store(nb as usize, Ordering::SeqCst);
        let mut slot_c: *mut u8 = core::ptr::null_mut();
        let pc = &mut slot_c as *mut *mut u8 as *mut u8;
        unsafe { fn_004082e8(pc, oc16, 0x4444_4444, 0x5555_5555) };
        assert_eq!(FMT_CALLS.load(Ordering::SeqCst), 1);
        // Only call: in-loop format against the grown buffer.
        assert_eq!(FMT_A2.load(Ordering::SeqCst), 0x17ff);
        assert_eq!(FMT_A1.load(Ordering::SeqCst), nb as usize);
        assert_eq!(FMT_A3.load(Ordering::SeqCst), oc as usize);
        assert_eq!(FMT_A4.load(Ordering::SeqCst), 0x5555_5555);
        assert_eq!(FMT_A5.load(Ordering::SeqCst), 0x4444_4444);
        assert_eq!(FMT_A6.load(Ordering::SeqCst), 0xc00);
        assert_eq!(P00_ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(P00_ALLOC_ARG.load(Ordering::SeqCst), 0x1800);
        assert_eq!(NORM_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FWD_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(P00_COPY_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(P00_NORM_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(P00_FAIL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(P00_REALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(P00_REALLOC_TOTAL.load(Ordering::SeqCst), 24);
        assert_eq!(slot_c, nb);
        assert_eq!(unsafe { rc_of(base_c) }, 5);

        unsafe {
            crate::fn_00408274::HOOK_00408540 = s74;
            crate::fn_00404820::CALLEE_00404E6C = s4820;
            crate::fn_00404dd4::HOOK_004054b4 = sdd_a;
            crate::fn_00404dd4::HOOK_00402fbc = sdd_f;
            crate::fn_00404c98::HOOK_00404e6c = sc98;
            crate::fn_00404f00::HOOK_004054b4 = s00_a;
            crate::fn_00404f00::HOOK_00402fbc = s00_c;
            crate::fn_00404f00::HOOK_00402e38 = s00_r;
            crate::fn_00404f00::HOOK_00404e6c = s00_n;
            crate::fn_00404f00::FAIL_00402F60 = s00_f;
        }
    }
}
