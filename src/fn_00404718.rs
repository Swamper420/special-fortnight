//! Original procedure `0x00404718` (89 bytes, `0x404718–0x404770`).
//! Evidence: `evidence/00404718_fn_00404718.md`.

unsafe extern "C" fn default_convert(_d: *mut usize, _s: *mut u8, _c: u32) {}

unsafe extern "C" fn default_alloc(_len: u32, _cp: u32) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_copy(_old: *mut u8, _new: *mut u8, _len: u32) {}

unsafe extern "C" fn default_free(_base: *mut u8) {}

/// Convert tail `0x404e94` (`FUN_00404e94`), reached by `JMP` when the tag
/// word at `src−10` is not 1 (args: dest slot, src, `DAT_004138c8`).
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00404e94` once it exists.
pub static mut CONVERT_00404E94: unsafe extern "C" fn(*mut usize, *mut u8, u32) =
    default_convert;

/// Alloc `0x404774` (`FUN_00404774`), copy-on-write arm.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00404774` (same work package) once cross-module wiring exists.
pub static mut ALLOC_00404774: unsafe extern "C" fn(u32, u32) -> *mut u8 = default_alloc;

/// Copy `0x402fbc` (`FUN_00402fbc`), args `(old, new, old_len)`.
///
/// ponytail: hook standing in for done `fn_00402fbc`, rewire to real call
/// once cross-module test serialization exists.
pub static mut COPY_00402FBC: unsafe extern "C" fn(*mut u8, *mut u8, u32) = default_copy;

/// Free `0x402e20` (`FUN_00402e20`), arg is header base (`old−12`).
///
/// ponytail: hook standing in for done `fn_00402e20` (which takes the base
/// as `u32`); rewire once address-width unification is decided.
pub static mut FREE_00402E20: unsafe extern "C" fn(*mut u8) = default_free;

/// Default codeword observed as `dword ptr [0x004138c8]`.
///
/// ponytail: absolute-address cell as hermetic own-module static, unify
/// with writer modules in `data.rs` once data layout proven.
pub static mut DAT_004138C8: u32 = 0;

/// String-assign: share (lock-inc) or duplicate (alloc+copy) `src`, swap
/// into `*dest`, release old with lock-dec/free at zero.
/// `param_1` (dest slot) arrives in EAX, `param_2` (src) in EDX.
/// Header (12 B before data): `u16 codeword @−12`, `u16 tag @−10`,
/// `u32 refcount @−8`, `u32 length @−4`.
pub unsafe fn fn_00404718(param_1: *mut usize, param_2: *mut u8) {
    let mut src = param_2;
    if !src.is_null() {
        if *((src as usize).wrapping_sub(10) as *const u16) != 1 {
            CONVERT_00404E94(param_1, src, DAT_004138C8);
            return;
        }
        let rc = *((src as usize).wrapping_sub(8) as *const u32);
        if rc < 0x80000000 {
            *((src as usize).wrapping_sub(8) as *mut u32) = rc.wrapping_add(1);
        } else {
            let len = *((src as usize).wrapping_sub(4) as *const u32);
            let cp = *((src as usize).wrapping_sub(12) as *const u16);
            let fresh = ALLOC_00404774(len, cp as u32);
            COPY_00402FBC(src, fresh, len);
            src = fresh;
        }
    }
    let old = *param_1;
    *param_1 = src as usize;
    if old == 0 {
        return;
    }
    let oldp = old as *mut u8;
    let orc = *((oldp as usize).wrapping_sub(8) as *const u32);
    if (orc.wrapping_sub(1) as i32) < 0 {
        return;
    }
    let dec = orc.wrapping_sub(1);
    *((oldp as usize).wrapping_sub(8) as *mut u32) = dec;
    if dec != 0 {
        return;
    }
    FREE_00402E20(oldp.wrapping_sub(12));
}

#[cfg(test)]
mod tests {
    use super::{
        ALLOC_00404774, CONVERT_00404E94, COPY_00402FBC, DAT_004138C8, FREE_00402E20,
        fn_00404718,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CONVERT_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_LEN: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_CP: AtomicUsize = AtomicUsize::new(0);
    static COPY_HITS: AtomicUsize = AtomicUsize::new(0);
    static COPY_LEN: AtomicUsize = AtomicUsize::new(0);
    static FREE_HITS: AtomicUsize = AtomicUsize::new(0);
    static FREE_ARG: AtomicUsize = AtomicUsize::new(0);

    static mut FRESH_BACKING: [u8; 32] = [0; 32];

    unsafe extern "C" fn convert(_d: *mut usize, _s: *mut u8, _c: u32) {
        CONVERT_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn alloc(len: u32, cp: u32) -> *mut u8 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_LEN.store(len as usize, Ordering::SeqCst);
        ALLOC_CP.store(cp as usize, Ordering::SeqCst);
        FRESH_BACKING.as_mut_ptr().wrapping_add(12)
    }

    unsafe extern "C" fn copy(_o: *mut u8, _n: *mut u8, len: u32) {
        COPY_HITS.fetch_add(1, Ordering::SeqCst);
        COPY_LEN.store(len as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn free(base: *mut u8) {
        FREE_HITS.fetch_add(1, Ordering::SeqCst);
        FREE_ARG.store(base as usize, Ordering::SeqCst);
    }

    /// 12-byte header + data; buffer must outlive the call.
    unsafe fn make(backing: *mut u8, rc: u32, len: u32, tag: u16) -> *mut u8 {
        *((backing as usize).wrapping_sub(12) as *mut u16) = 0;
        *((backing as usize).wrapping_sub(10) as *mut u16) = tag;
        *((backing as usize).wrapping_sub(8) as *mut u32) = rc;
        *((backing as usize).wrapping_sub(4) as *mut u32) = len;
        backing
    }

    #[test]
    fn assign_share_release_convert_cow() {
        unsafe {
            CONVERT_00404E94 = convert;
            ALLOC_00404774 = alloc;
            COPY_00402FBC = copy;
            FREE_00402E20 = free;
            DAT_004138C8 = 0x41;
        }
        // Share: dest null, src rc=1 → slot takes src, rc=2, no free.
        let mut b1 = [0u8; 32];
        let mut slot: usize = 0;
        let s1 = unsafe { make(b1.as_mut_ptr().wrapping_add(12), 1, 4, 1) };
        FREE_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404718(&mut slot, s1) };
        assert_eq!(slot, s1 as usize);
        assert_eq!(unsafe { *((s1 as usize).wrapping_sub(8) as *const u32) }, 2);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 0);

        // Release: dest holds rc=1 string, src null → slot null, freed at base.
        let mut b2 = [0u8; 32];
        let base2 = b2.as_mut_ptr() as usize;
        let s2 = unsafe { make(b2.as_mut_ptr().wrapping_add(12), 1, 4, 1) };
        slot = s2 as usize;
        FREE_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404718(&mut slot, core::ptr::null_mut()) };
        assert_eq!(slot, 0);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FREE_ARG.load(Ordering::SeqCst), base2);

        // Convert tail: tag != 1 → hook fires, slot untouched.
        let mut b3 = [0u8; 32];
        let s3 = unsafe { make(b3.as_mut_ptr().wrapping_add(12), 1, 4, 7) };
        slot = 0x1234;
        CONVERT_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404718(&mut slot, s3) };
        assert_eq!(CONVERT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(slot, 0x1234);

        // Copy-on-write: rc=0x80000000 → alloc(len, cp)+copy, slot takes fresh.
        let mut b4 = [0u8; 64];
        let s4 = unsafe { make(b4.as_mut_ptr().wrapping_add(12), 0x80000000, 9, 1) };
        unsafe { *((s4 as usize).wrapping_sub(12) as *mut u16) = 5 };
        slot = 0;
        ALLOC_HITS.store(0, Ordering::SeqCst);
        COPY_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404718(&mut slot, s4) };
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_LEN.load(Ordering::SeqCst), 9);
        assert_eq!(ALLOC_CP.load(Ordering::SeqCst), 5);
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(COPY_LEN.load(Ordering::SeqCst), 9);
        assert_eq!(
            slot,
            unsafe { FRESH_BACKING.as_mut_ptr().wrapping_add(12) } as usize
        );
        // Old (null) needs no release.
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 1);
    }
}
