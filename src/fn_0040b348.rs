//! Original procedure `0x0040b348` (116 bytes, `0x0040b348–0x0040b3bb`).
//! Evidence: `evidence/0040b348_fn_0040b348.md`.

unsafe extern "C" fn default_count(_p: *mut u8) -> i32 {
    0
}

unsafe extern "C" fn default_release(_slot: *mut u8) {}

/// Counter `0x0040b58c` (`FUN_0040b58c`), called with `param_1`;
/// zero selects the direct lane.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_0040b58c` once it exists.
pub static mut HOOK_0040B58C: unsafe extern "C" fn(*mut u8) -> i32 = default_count;

/// Target `0x00405058` (`FUN_00405058`), called as
/// `(param_3, param_1|local_c, param_2)`: direct
/// intra-reconstruction call (rewired; signatures verified
/// `fn(*mut u8, *mut u8, *mut u8)`).

/// Builder `0x0040525c` (`FUN_0040525c`), called as
/// `(param_1, 1, count-1, &local_c)`: direct intra-reconstruction
/// call (rewired; signatures verified `fn(*mut u8, i32, i32,
/// *mut u8)`).

/// Release `0x00404c88` (`thunk_FUN_004046c4`), always run on
/// `&local_c` (SEH finally on target).
///
/// ponytail: hook mirroring done `fn_004046c4`'s shape, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_004046C4: unsafe extern "C" fn(*mut u8) = default_release;

/// `count=b58c(p1); count==0 ? take(p3,p1,p2) :
/// { build(p1,1,count-1,&local); take(p3,local,p2) };
/// release(&local)`. Params arrive in EAX/EDX/ECX per Ghidra
/// `__register` observation. The `FS:[0]` SEH install/restore
/// has no host equivalent and is omitted; the always-run
/// release is kept.
pub unsafe fn fn_0040b348(param_1: *mut u8, param_2: *mut u8, param_3: *mut u8) {
    let mut local_c: *mut u8 = core::ptr::null_mut();
    let count = HOOK_0040B58C(param_1);
    if count == 0 {
        crate::fn_00405058::fn_00405058(param_3, param_1, param_2);
    } else {
        crate::fn_0040525c::fn_0040525c(
            param_1,
            1,
            count.wrapping_sub(1),
            core::ptr::addr_of_mut!(local_c) as *mut u8,
        );
        let local = core::ptr::read_unaligned(core::ptr::addr_of!(local_c));
        crate::fn_00405058::fn_00405058(param_3, local, param_2);
    }
    HOOK_004046C4(core::ptr::addr_of_mut!(local_c) as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004046C4, HOOK_0040B58C, fn_0040b348};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static C58C_HITS: AtomicUsize = AtomicUsize::new(0);
    static C58C_RET: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);

    /// Headed take/build source: tag 2, refcount reset per lane,
    /// length 0 (the build clamps to a zero copy, so its wide lane
    /// never writes).
    static mut HEAD_ARENA: [u8; 64] = [0; 64];

    unsafe extern "C" fn count(_p: *mut u8) -> i32 {
        C58C_HITS.fetch_add(1, Ordering::SeqCst);
        C58C_RET.load(Ordering::SeqCst) as i32
    }

    unsafe fn headed() -> *mut u8 {
        let base = core::ptr::addr_of_mut!(HEAD_ARENA) as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, 2);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, 5);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, 0);
        base.wrapping_byte_add(12)
    }

    unsafe fn rc_of(p: *mut u8) -> u32 {
        core::ptr::read_unaligned(p.wrapping_byte_offset(-8) as *const u32)
    }

    unsafe fn slot_of(p: *mut u8) -> *mut u8 {
        core::ptr::read_unaligned(p as *const *mut u8)
    }

    unsafe extern "C" fn release(_slot: *mut u8) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    fn clear() {
        C58C_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn zero_and_nonzero_lanes() {
        // Real `fn_00405058` behind the take (its tails shared) and
        // real `fn_0040525c` behind the build (its hooks shared):
        // hold the common owner lock and its lock.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let _slice = crate::fn_0040525c::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_0040B58C = count;
            HOOK_004046C4 = release;
        }
        let mut s3 = [0u8; 8];
        let p3 = s3.as_mut_ptr();
        // Zero lane: real take(p3, p1, null) stores the headed
        // source (rc 5→6); release always fires.
        let p1 = unsafe { headed() };
        C58C_RET.store(0, Ordering::SeqCst);
        clear();
        unsafe { fn_0040b348(p1, core::ptr::null_mut(), p3) };
        assert_eq!(C58C_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { slot_of(p3) }, p1);
        assert_eq!(unsafe { rc_of(p1) }, 6);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
        // Nonzero lane: real build(p1, 1, 3, &local) clamps to a
        // zero copy (len 0), local stays null; real take(p3, null,
        // p2) takes its null-`param_2` tail (default no-op): the
        // slot keeps its reset null.
        let p1b = unsafe { headed() };
        unsafe { core::ptr::write_unaligned(p3 as *mut *mut u8, core::ptr::null_mut()) };
        C58C_RET.store(4, Ordering::SeqCst);
        clear();
        unsafe { fn_0040b348(p1b, core::ptr::null_mut(), p3) };
        assert_eq!(C58C_HITS.load(Ordering::SeqCst), 1);
        assert!(unsafe { slot_of(p3) }.is_null());
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
    }
}
