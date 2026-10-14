//! Original procedure `0x004018f8` (882 bytes, `0x004018f8–0x00401c7b`).
//! Evidence: `evidence/004018f8_fn_004018f8.md`.

use core::ptr::null_mut;

unsafe extern "C" fn default_null(_a: u32, _b: u32) -> *mut u32 {
    null_mut()
}

/// Small lane (`param ≤ 0xa2c`): class index `(param+3)>>3` into
/// `DAT_004138dc`, descriptor `DAT_0041205c+8*class`, freelist pop or
/// bitmap carve under descriptor/`DAT_00413a34` locks.
///
/// ponytail: heap tables unmodeled on host; hook owns region state,
/// rewire to real body once data layout proven.
pub static mut HOOK_SMALL_ALLOC: unsafe extern "C" fn(u32, u32) -> *mut u32 =
    default_null;

/// Bucket lane (`0xa2c < param ≤ 0x40a2c`): rounded `(p+0xd3)&~0xff`,
/// total `+0x30`, bitmap search + split under `DAT_00413a34`.
///
/// ponytail: hook owns bitmap/freelist state, rewire once proven.
pub static mut HOOK_BUCKET_ALLOC: unsafe extern "C" fn(u32, u32) -> *mut u32 =
    default_null;

/// Huge lane (`param > 0x40a2c`, non-negative): tail continuation into
/// `FUN_004016a4` (`JNS 0x004016a4`); dossier shows `VirtualAlloc`
/// paragraph with no in-body import call (cross-function artifact).
///
/// ponytail: hook covers continuation, rewire to real `fn_004016a4`
/// once it exists.
pub static mut HOOK_LARGE_ALLOC: unsafe extern "C" fn(u32, u32) -> *mut u32 =
    default_null;

/// `param_1` arrives in EAX. Size dispatch only; region bodies behind
/// hooks. All adds wrap like x86.
pub unsafe fn fn_004018f8(param_1: u32) -> *mut u32 {
    if param_1 > 0xa2c {
        if param_1 <= 0x40a2c {
            let rounded = param_1.wrapping_add(0xd3) & 0xffffff00;
            let total = rounded.wrapping_add(0x30);
            return HOOK_BUCKET_ALLOC(rounded, total);
        }
        if (param_1 as i32) < 0 {
            return null_mut();
        }
        let reserve = param_1.wrapping_add(0x10013) & 0xffff0000;
        return HOOK_LARGE_ALLOC(param_1, reserve);
    }
    HOOK_SMALL_ALLOC(param_1.wrapping_add(3) >> 3, param_1)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_BUCKET_ALLOC, HOOK_LARGE_ALLOC, HOOK_SMALL_ALLOC, fn_004018f8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS_S: AtomicUsize = AtomicUsize::new(0);
    static HITS_B: AtomicUsize = AtomicUsize::new(0);
    static HITS_L: AtomicUsize = AtomicUsize::new(0);
    static ARG0: AtomicUsize = AtomicUsize::new(0);
    static ARG1: AtomicUsize = AtomicUsize::new(0);
    static RETP: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn small(a: u32, b: u32) -> *mut u32 {
        HITS_S.fetch_add(1, Ordering::SeqCst);
        ARG0.store(a as usize, Ordering::SeqCst);
        ARG1.store(b as usize, Ordering::SeqCst);
        RETP.load(Ordering::SeqCst) as *mut u32
    }

    unsafe extern "C" fn bucket(a: u32, b: u32) -> *mut u32 {
        HITS_B.fetch_add(1, Ordering::SeqCst);
        ARG0.store(a as usize, Ordering::SeqCst);
        ARG1.store(b as usize, Ordering::SeqCst);
        RETP.load(Ordering::SeqCst) as *mut u32
    }

    unsafe extern "C" fn large(a: u32, b: u32) -> *mut u32 {
        HITS_L.fetch_add(1, Ordering::SeqCst);
        ARG0.store(a as usize, Ordering::SeqCst);
        ARG1.store(b as usize, Ordering::SeqCst);
        RETP.load(Ordering::SeqCst) as *mut u32
    }

    #[test]
    fn dispatch_and_size_math() {
        unsafe {
            HOOK_SMALL_ALLOC = small;
            HOOK_BUCKET_ALLOC = bucket;
            HOOK_LARGE_ALLOC = large;
        }
        let mut buf = [0u8; 8];
        let p = buf.as_mut_ptr() as usize;
        RETP.store(p, Ordering::SeqCst);

        // Small lane: idx (p+3)>>3.
        HITS_S.store(0, Ordering::SeqCst);
        let r = unsafe { fn_004018f8(1) };
        assert_eq!(r as usize, p);
        assert_eq!(HITS_S.load(Ordering::SeqCst), 1);
        assert_eq!(ARG0.load(Ordering::SeqCst), 0);
        assert_eq!(ARG1.load(Ordering::SeqCst), 1);
        unsafe { fn_004018f8(0xa2c) };
        assert_eq!(ARG0.load(Ordering::SeqCst), 0xa2f >> 3);

        // Bucket lane: (0xa2d+0xd3)&~0xff=0xb00, total 0xb30.
        HITS_B.store(0, Ordering::SeqCst);
        unsafe { fn_004018f8(0xa2d) };
        assert_eq!(HITS_B.load(Ordering::SeqCst), 1);
        assert_eq!(ARG0.load(Ordering::SeqCst), 0xb00);
        assert_eq!(ARG1.load(Ordering::SeqCst), 0xb30);
        unsafe { fn_004018f8(0x40a2c) };
        assert_eq!(HITS_B.load(Ordering::SeqCst), 2);

        // Huge lane: reserve (p+0x10013)&0xffff0000.
        HITS_L.store(0, Ordering::SeqCst);
        unsafe { fn_004018f8(0x40a2d) };
        assert_eq!(HITS_L.load(Ordering::SeqCst), 1);
        assert_eq!(ARG0.load(Ordering::SeqCst), 0x40a2d);
        assert_eq!(ARG1.load(Ordering::SeqCst), 0x50000);

        // Negative → null, no hook.
        HITS_L.store(0, Ordering::SeqCst);
        let r = unsafe { fn_004018f8(0x80000000) };
        assert!(r.is_null());
        assert_eq!(HITS_L.load(Ordering::SeqCst), 0);
    }
}
