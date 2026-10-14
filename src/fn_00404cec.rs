//! Original procedure `0x00404cec` (53 bytes, `0x00404cec–0x00404d20`).
//! Evidence: `evidence/00404cec_fn_00404cec.md`.

use crate::fn_00402e20::fn_00402e20;

/// Target `0x00404e6c` (`FUN_00404e6c`), reached by a terminal `JMP`
/// on the non-`2` tag lane (decompiler shows call+return): direct
/// intra-reconstruction call (rewired; signatures verified
/// `fn(*mut u8, *mut u8)`).

/// Acquire `param_2` (null → skip; tag `[p2-10]!=2` → forward lane
/// and return; refcount `[p2-8]>=0` → locked inc, else store
/// as-is with no copy), `XCHG` into `*param_1`, release old
/// (`[old-8]>0` → locked dec → zero calls `02e20(old-12)`).
/// Params arrive in EAX/EDX per Ghidra `__register` observation.
/// Same shape as `fn_00404c98` minus the realloc lane.
/// `INC; JLE`-not-taken is `(rc as i32) >= 0`, exact including
/// `rc=0x7fffffff` (INC sets both SF and OF). Release guards match
/// `fn_004046c4`/`fn_004046e8`. Header/count stay `u32`/`u16` per
/// observed widths; links read pointer-sized. Direct call to done
/// `fn_00402e20` (no hook).
///
/// ponytail: non-atomic host model of `LOCK INC`/`LOCK DEC`/`XCHG`
/// (AtomicU32 once threading proven).
pub unsafe fn fn_00404cec(param_1: *mut u8, param_2: *mut u8) {
    if !param_2.is_null() {
        if core::ptr::read_unaligned(param_2.wrapping_byte_offset(-10) as *const u16) != 2 {
            crate::fn_00404e6c::fn_00404e6c(param_1, param_2);
            return;
        }
        let rc = core::ptr::read_unaligned(param_2.wrapping_byte_offset(-8) as *const u32);
        if (rc as i32) >= 0 {
            core::ptr::write_unaligned(param_2.wrapping_byte_offset(-8) as *mut u32, rc.wrapping_add(1));
        }
    }
    let old: *mut u8 = core::ptr::read_unaligned(param_1 as *const *mut u8);
    core::ptr::write_unaligned(param_1 as *mut *mut u8, param_2);
    if !old.is_null() {
        let seen = core::ptr::read_unaligned(old.wrapping_byte_offset(-8) as *const u32);
        if (seen.wrapping_sub(1) as i32) >= 0 {
            let next = seen.wrapping_sub(1);
            core::ptr::write_unaligned(old.wrapping_byte_offset(-8) as *mut u32, next);
            if next == 0 {
                fn_00402e20(old.wrapping_byte_offset(-12) as u32);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fn_00404cec;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DTOR_HITS: AtomicUsize = AtomicUsize::new(0);
    static CONV_HITS: AtomicUsize = AtomicUsize::new(0);
    static CONV_SRC: AtomicUsize = AtomicUsize::new(0);
    static CONV_P4: AtomicUsize = AtomicUsize::new(0);
    static CONV_N: AtomicUsize = AtomicUsize::new(0);
    static CONV_RET: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static FILL_C: AtomicUsize = AtomicUsize::new(0);

    /// Probe for the done dtor's indirect slot: counts entries,
    /// returns 0 so its tail lane never fires.
    unsafe extern "C" fn indirect() -> u32 {
        DTOR_HITS.fetch_add(1, Ordering::SeqCst);
        0
    }

    /// Downstream `fn_00404d30` convert/size pair (mirrors its own
    /// test): stack path, canned return.
    unsafe extern "C" fn convert(
        _dst: *mut u16,
        _cap: u32,
        src: *const u8,
        p4: u32,
        n: u32,
    ) -> i32 {
        CONV_HITS.fetch_add(1, Ordering::SeqCst);
        CONV_SRC.store(src as usize, Ordering::SeqCst);
        CONV_P4.store(p4 as usize, Ordering::SeqCst);
        CONV_N.store(n as usize, Ordering::SeqCst);
        CONV_RET.load(Ordering::SeqCst) as i32
    }

    unsafe extern "C" fn size(_slot: *mut u8, _n: u32) {}

    /// Downstream `fn_00404dd4` alloc/fill pair: canned DATA pointer.
    unsafe extern "C" fn alloc(n: u32) -> u32 {
        ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        0x1122_3344
    }

    unsafe extern "C" fn fill(_a: *mut u8, _b: u32, c: u32) {
        FILL_C.store(c as usize, Ordering::SeqCst);
    }

    /// Header arena: obj = base+12; tag at base+2 (`obj-10`),
    /// refcount at base+4 (`obj-8`).
    unsafe fn hdr(arena: &mut [u32; 4], tag: u16, rc: u32) -> *mut u8 {
        let base = arena.as_mut_ptr() as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, tag);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, rc);
        base.wrapping_byte_add(12)
    }

    unsafe fn rc_of(p: *mut u8) -> u32 {
        core::ptr::read_unaligned(p.wrapping_byte_offset(-8) as *const u32)
    }

    #[test]
    fn acquire_store_release_lanes() {
        // Forward lane reaches done `fn_00404e6c` → `fn_00404d30` →
        // `fn_00404dd4`: hold the common owner lock; the dtor lane
        // reaches done fn_00402e20: hold its lock too.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let _callee = crate::fn_00402e20::TEST_LOCK.lock().unwrap();
        let saved = unsafe { crate::fn_00402e20::PTR_00412740 };
        let old_conv = unsafe { crate::fn_00404d30::HOOK_004047ec };
        let old_size = unsafe { crate::fn_00404d30::HOOK_00404f00 };
        let old_alloc = unsafe { crate::fn_00404dd4::HOOK_004054b4 };
        let old_fill = unsafe { crate::fn_00404dd4::HOOK_00402fbc };
        unsafe {
            crate::fn_00402e20::PTR_00412740 = indirect;
            crate::fn_00404d30::HOOK_004047ec = convert;
            crate::fn_00404d30::HOOK_00404f00 = size;
            crate::fn_00404dd4::HOOK_004054b4 = alloc;
            crate::fn_00404dd4::HOOK_00402fbc = fill;
        }

        let mut arena = [0u32; 4];
        let mut slot: *mut u8 = core::ptr::null_mut();
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;

        // Null/null lane: no-op.
        DTOR_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404cec(slot_ptr, core::ptr::null_mut()) };
        assert!(slot.is_null());
        assert_eq!(DTOR_HITS.load(Ordering::SeqCst), 0);

        // Null + old(1) lane: exchange, release calls dtor once.
        slot = unsafe { hdr(&mut arena, 2, 1) };
        DTOR_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404cec(slot_ptr, core::ptr::null_mut()) };
        assert!(slot.is_null());
        assert_eq!(unsafe { *arena.as_mut_ptr().wrapping_add(1) }, 0);
        assert_eq!(DTOR_HITS.load(Ordering::SeqCst), 1);

        // Foreign-tag lane: real forward → convert(src, tag2, len),
        // stack path (ret 3): alloc(3), fill 3<<1=6; the converted
        // object is stored into the slot (`fn_00404dd4` tail).
        let mut fwd_arena = [0u8; 32];
        let fbase = fwd_arena.as_mut_ptr();
        unsafe {
            core::ptr::write_unaligned(fbase.wrapping_add(2) as *mut u16, 7);
            core::ptr::write_unaligned(fbase.wrapping_add(0) as *mut u16, 0x51);
            core::ptr::write_unaligned(fbase.wrapping_add(4) as *mut u32, 5);
            core::ptr::write_unaligned(fbase.wrapping_add(8) as *mut u32, 5);
        }
        let p2 = fbase.wrapping_add(12);
        slot = core::ptr::null_mut();
        CONV_HITS.store(0, Ordering::SeqCst);
        CONV_RET.store(3, Ordering::SeqCst);
        unsafe { fn_00404cec(slot_ptr, p2) };
        assert_eq!(CONV_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CONV_SRC.load(Ordering::SeqCst), p2 as usize);
        assert_eq!(CONV_P4.load(Ordering::SeqCst), 0x51);
        assert_eq!(CONV_N.load(Ordering::SeqCst), 5);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 3);
        assert_eq!(FILL_C.load(Ordering::SeqCst), 6);
        assert_eq!(slot as usize, 0x1122_3344);
        assert_eq!(unsafe { rc_of(p2) }, 5);

        // Inc lane: rc 5→6, stored as-is.
        let mut inc_arena = [0u32; 4];
        let p2 = unsafe { hdr(&mut inc_arena, 2, 5) };
        slot = core::ptr::null_mut();
        unsafe { fn_00404cec(slot_ptr, p2) };
        assert_eq!(slot, p2);
        assert_eq!(unsafe { rc_of(p2) }, 6);

        // Skip-inc lane: negative rc stored as-is, no hook.
        // (No realloc lane here, unlike `fn_00404c98`.)
        let mut neg_arena = [0u32; 4];
        let p2 = unsafe { hdr(&mut neg_arena, 2, 0xffff_ffff) };
        slot = core::ptr::null_mut();
        unsafe { fn_00404cec(slot_ptr, p2) };
        assert_eq!(slot, p2);
        assert_eq!(unsafe { rc_of(p2) }, 0xffff_ffff);

        // Old-zero lane: exchange runs, no dec, no call.
        let mut z_arena = [0u32; 4];
        slot = unsafe { hdr(&mut z_arena, 2, 0) };
        DTOR_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404cec(slot_ptr, core::ptr::null_mut()) };
        assert!(slot.is_null());
        assert_eq!(unsafe { *z_arena.as_mut_ptr().wrapping_add(1) }, 0);
        assert_eq!(DTOR_HITS.load(Ordering::SeqCst), 0);

        // Old-2 lane: dec to 1, no call.
        let mut d_arena = [0u32; 4];
        slot = unsafe { hdr(&mut d_arena, 2, 2) };
        DTOR_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404cec(slot_ptr, core::ptr::null_mut()) };
        assert!(slot.is_null());
        assert_eq!(unsafe { *d_arena.as_mut_ptr().wrapping_add(1) }, 1);
        assert_eq!(DTOR_HITS.load(Ordering::SeqCst), 0);

        unsafe {
            crate::fn_00402e20::PTR_00412740 = saved;
            crate::fn_00404d30::HOOK_004047ec = old_conv;
            crate::fn_00404d30::HOOK_00404f00 = old_size;
            crate::fn_00404dd4::HOOK_004054b4 = old_alloc;
            crate::fn_00404dd4::HOOK_00402fbc = old_fill;
        }
    }
}
