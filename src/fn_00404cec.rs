//! Original procedure `0x00404cec` (53 bytes, `0x404cec–0x404d20`).
//! Evidence: `evidence/00404cec_fn_00404cec.md`.

use crate::fn_00402e20::fn_00402e20;

unsafe extern "C" fn default_forward(_slot: *mut u8, _src: *mut u8) {}

/// Target `0x404e6c` (`FUN_00404e6c`), reached by a terminal `JMP`
/// on the non-`2` tag lane (decompiler shows call+return).
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_00404e6c` once it exists.
pub static mut HOOK_00404e6c: unsafe extern "C" fn(*mut u8, *mut u8) = default_forward;

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
            HOOK_00404e6c(param_1, param_2);
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
    use super::{HOOK_00404e6c, fn_00404cec};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static FWD_HITS: AtomicUsize = AtomicUsize::new(0);
    static FWD_A: AtomicUsize = AtomicUsize::new(0);
    static FWD_B: AtomicUsize = AtomicUsize::new(0);
    static DTOR_HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn forward(slot: *mut u8, src: *mut u8) {
        FWD_HITS.fetch_add(1, Ordering::SeqCst);
        FWD_A.store(slot as usize, Ordering::SeqCst);
        FWD_B.store(src as usize, Ordering::SeqCst);
    }

    /// Probe for the done dtor's indirect slot: counts entries,
    /// returns 0 so its tail lane never fires.
    unsafe extern "C" fn indirect() -> u32 {
        DTOR_HITS.fetch_add(1, Ordering::SeqCst);
        0
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
        // Direct call reaches done fn_00402e20, which reads its PTR
        // global: hold the owner lock so its writer test can't race us.
        let _callee = crate::fn_00402e20::TEST_LOCK.lock().unwrap();
        let saved = unsafe { crate::fn_00402e20::PTR_00412740 };
        unsafe {
            crate::fn_00402e20::PTR_00412740 = indirect;
            HOOK_00404e6c = forward;
        }

        let mut arena = [0u32; 4];
        let mut slot: *mut u8 = core::ptr::null_mut();
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;

        // Null/null lane: no-op.
        FWD_HITS.store(0, Ordering::SeqCst);
        DTOR_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404cec(slot_ptr, core::ptr::null_mut()) };
        assert!(slot.is_null());
        assert_eq!(FWD_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(DTOR_HITS.load(Ordering::SeqCst), 0);

        // Null + old(1) lane: exchange, release calls dtor once.
        slot = unsafe { hdr(&mut arena, 2, 1) };
        DTOR_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404cec(slot_ptr, core::ptr::null_mut()) };
        assert!(slot.is_null());
        assert_eq!(unsafe { *arena.as_mut_ptr().wrapping_add(1) }, 0);
        assert_eq!(DTOR_HITS.load(Ordering::SeqCst), 1);

        // Foreign-tag lane: forward only, slot untouched.
        let mut fwd_arena = [0u32; 4];
        let p2 = unsafe { hdr(&mut fwd_arena, 7, 5) };
        slot = core::ptr::null_mut();
        FWD_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404cec(slot_ptr, p2) };
        assert_eq!(FWD_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FWD_A.load(Ordering::SeqCst), slot_ptr as usize);
        assert_eq!(FWD_B.load(Ordering::SeqCst), p2 as usize);
        assert!(slot.is_null());
        assert_eq!(unsafe { rc_of(p2) }, 5);

        // Inc lane: rc 5→6, stored as-is.
        let mut inc_arena = [0u32; 4];
        let p2 = unsafe { hdr(&mut inc_arena, 2, 5) };
        slot = core::ptr::null_mut();
        FWD_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404cec(slot_ptr, p2) };
        assert_eq!(slot, p2);
        assert_eq!(unsafe { rc_of(p2) }, 6);
        assert_eq!(FWD_HITS.load(Ordering::SeqCst), 0);

        // Skip-inc lane: negative rc stored as-is, no hook.
        // (No realloc lane here, unlike `fn_00404c98`.)
        let mut neg_arena = [0u32; 4];
        let p2 = unsafe { hdr(&mut neg_arena, 2, 0xffff_ffff) };
        slot = core::ptr::null_mut();
        FWD_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404cec(slot_ptr, p2) };
        assert_eq!(slot, p2);
        assert_eq!(unsafe { rc_of(p2) }, 0xffff_ffff);
        assert_eq!(FWD_HITS.load(Ordering::SeqCst), 0);

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
        }
    }
}
