//! Original procedure `0x0040b348` (116 bytes, `0x0040b348–0x0040b3bb`).
//! Evidence: `evidence/0040b348_fn_0040b348.md`.

unsafe extern "C" fn default_count(_p: *mut u8) -> i32 {
    0
}

unsafe extern "C" fn default_take(_a: *mut u8, _b: *mut u8, _c: *mut u8) {}

unsafe extern "C" fn default_build(_a: *mut u8, _n: i32, _m: i32, _d: *mut u8) {}

unsafe extern "C" fn default_release(_slot: *mut u8) {}

/// Counter `0x0040b58c` (`FUN_0040b58c`), called with `param_1`;
/// zero selects the direct lane.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_0040b58c` once it exists.
pub static mut HOOK_0040B58C: unsafe extern "C" fn(*mut u8) -> i32 = default_count;

/// Target `0x00405058` (`FUN_00405058`), called as
/// `(param_3, param_1|local_c, param_2)`.
///
/// ponytail: hook mirroring done `fn_00405058`'s shape, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_00405058: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8) =
    default_take;

/// Builder `0x0040525c` (`FUN_0040525c`), called as
/// `(param_1, 1, count-1, &local_c)`.
///
/// ponytail: hook mirroring done `fn_0040525c`'s shape, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_0040525C: unsafe extern "C" fn(*mut u8, i32, i32, *mut u8) =
    default_build;

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
        HOOK_00405058(param_3, param_1, param_2);
    } else {
        HOOK_0040525C(
            param_1,
            1,
            count.wrapping_sub(1),
            core::ptr::addr_of_mut!(local_c) as *mut u8,
        );
        let local = core::ptr::read_unaligned(core::ptr::addr_of!(local_c));
        HOOK_00405058(param_3, local, param_2);
    }
    HOOK_004046C4(core::ptr::addr_of_mut!(local_c) as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004046C4, HOOK_00405058, HOOK_0040525C, HOOK_0040B58C, fn_0040b348};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static C58C_HITS: AtomicUsize = AtomicUsize::new(0);
    static C58C_RET: AtomicUsize = AtomicUsize::new(0);
    static TAKE_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAKE_A: AtomicUsize = AtomicUsize::new(0);
    static TAKE_B: AtomicUsize = AtomicUsize::new(0);
    static TAKE_C: AtomicUsize = AtomicUsize::new(0);
    static BUILD_HITS: AtomicUsize = AtomicUsize::new(0);
    static BUILD_A: AtomicUsize = AtomicUsize::new(0);
    static BUILD_B: AtomicUsize = AtomicUsize::new(0);
    static BUILD_C: AtomicUsize = AtomicUsize::new(0);
    static BUILD_D: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL_ARG: AtomicUsize = AtomicUsize::new(0);

    static mut MARK: u8 = 0;

    unsafe extern "C" fn count(_p: *mut u8) -> i32 {
        C58C_HITS.fetch_add(1, Ordering::SeqCst);
        C58C_RET.load(Ordering::SeqCst) as i32
    }

    unsafe extern "C" fn take(a: *mut u8, b: *mut u8, c: *mut u8) {
        TAKE_HITS.fetch_add(1, Ordering::SeqCst);
        TAKE_A.store(a as usize, Ordering::SeqCst);
        TAKE_B.store(b as usize, Ordering::SeqCst);
        TAKE_C.store(c as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn build(a: *mut u8, n: i32, m: i32, d: *mut u8) {
        BUILD_HITS.fetch_add(1, Ordering::SeqCst);
        BUILD_A.store(a as usize, Ordering::SeqCst);
        BUILD_B.store(n as usize, Ordering::SeqCst);
        BUILD_C.store(m as usize, Ordering::SeqCst);
        BUILD_D.store(d as usize, Ordering::SeqCst);
        core::ptr::write_unaligned(d as *mut *mut u8, core::ptr::addr_of_mut!(MARK));
    }

    unsafe extern "C" fn release(slot: *mut u8) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
        REL_ARG.store(slot as usize, Ordering::SeqCst);
    }

    fn clear() {
        C58C_HITS.store(0, Ordering::SeqCst);
        TAKE_HITS.store(0, Ordering::SeqCst);
        BUILD_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn zero_and_nonzero_lanes() {
        // Own hooks only: no foreign globals, no TEST_LOCK.
        unsafe {
            HOOK_0040B58C = count;
            HOOK_00405058 = take;
            HOOK_0040525C = build;
            HOOK_004046C4 = release;
        }
        let mut o1 = 0u8;
        let mut o2 = 0u8;
        let mut o3 = 0u8;
        let p1 = &mut o1 as *mut u8;
        let p2 = &mut o2 as *mut u8;
        let p3 = &mut o3 as *mut u8;
        // Zero lane: take(p3, p1, p2), no build, always release.
        C58C_RET.store(0, Ordering::SeqCst);
        clear();
        unsafe { fn_0040b348(p1, p2, p3) };
        assert_eq!(C58C_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAKE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAKE_A.load(Ordering::SeqCst), p3 as usize);
        assert_eq!(TAKE_B.load(Ordering::SeqCst), p1 as usize);
        assert_eq!(TAKE_C.load(Ordering::SeqCst), p2 as usize);
        assert_eq!(BUILD_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
        // Nonzero lane: build(p1, 1, count-1, &local), then
        // take(p3, built, p2); release sees the same &local.
        C58C_RET.store(4, Ordering::SeqCst);
        clear();
        unsafe { fn_0040b348(p1, p2, p3) };
        assert_eq!(BUILD_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(BUILD_A.load(Ordering::SeqCst), p1 as usize);
        assert_eq!(BUILD_B.load(Ordering::SeqCst), 1);
        assert_eq!(BUILD_C.load(Ordering::SeqCst), 3);
        assert_eq!(TAKE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAKE_A.load(Ordering::SeqCst), p3 as usize);
        assert_eq!(
            TAKE_B.load(Ordering::SeqCst),
            core::ptr::addr_of!(MARK) as usize
        );
        assert_eq!(TAKE_C.load(Ordering::SeqCst), p2 as usize);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(
            REL_ARG.load(Ordering::SeqCst),
            BUILD_D.load(Ordering::SeqCst)
        );
    }
}
