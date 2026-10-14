//! Original procedure `0x00405ae4` (58 bytes, `0x405ae4–0x405b1d`).
//! Evidence: `evidence/00405ae4_fn_00405ae4.md`.

use core::ptr::{null_mut, read_unaligned, write_unaligned};

unsafe extern "C" fn default_convert(p: *mut u8, _d: *mut u8, _n: u32) -> *mut u8 {
    p
}

unsafe extern "C" fn default_free(_p: *mut u8) {}

/// Target `0x405548` (`FUN_00405548`), called as `(obj, *entry, extra)`
/// when both the table entry and `u32 [obj-4]` are nonzero.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00405548` once it exists.
pub static mut HOOK_00405548: unsafe extern "C" fn(*mut u8, *mut u8, u32) -> *mut u8 =
    default_convert;

/// Target `0x402e20` (`FUN_00402e20`), called with `obj-8` (header base).
/// Image param is `u32`; hook widens to host pointer.
///
/// ponytail: hook standing in for done `fn_00402e20`, rewire to real
/// call once cross-module test serialization exists.
pub static mut HOOK_00402e20: unsafe extern "C" fn(*mut u8) = default_free;

/// Release `*param_1`: zero holder, `LOCK DEC [obj-8]`; on zero maybe
/// convert via table at `desc + u8[desc+1] + 6`, then free `obj-8`.
/// Returns holder (`param_1` in EAX per `__register` observation).
pub unsafe fn fn_00405ae4(
    param_1: *mut *mut u8,
    param_2: *mut u8,
) -> *mut *mut u8 {
    let obj: *mut u8 = read_unaligned(param_1 as *const *mut u8);
    if obj.is_null() {
        return param_1;
    }
    write_unaligned(param_1, null_mut());
    let rc_ptr = obj.wrapping_byte_offset(-8) as *mut u32;
    let rc: u32 = read_unaligned(rc_ptr as *const u32).wrapping_sub(1);
    write_unaligned(rc_ptr, rc);
    if rc != 0 {
        return param_1;
    }
    let idx = read_unaligned(param_2.wrapping_byte_offset(1)) as usize;
    let entry: *mut u8 = read_unaligned(
        ((param_2 as usize).wrapping_add(idx).wrapping_add(6)) as *const *mut u8,
    );
    let mut cur = obj;
    if !entry.is_null() {
        let extra: u32 =
            read_unaligned(obj.wrapping_byte_offset(-4) as *const u32);
        if extra != 0 {
            let desc: *mut u8 = read_unaligned(entry as *const *mut u8);
            cur = HOOK_00405548(obj, desc, extra);
        }
    }
    HOOK_00402e20(cur.wrapping_byte_offset(-8));
    param_1
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00402e20, HOOK_00405548, fn_00405ae4};
    use core::ptr::{read_unaligned, write_unaligned};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CONVERT_HITS: AtomicUsize = AtomicUsize::new(0);
    static FREE_HITS: AtomicUsize = AtomicUsize::new(0);
    static FREE_ARG: AtomicUsize = AtomicUsize::new(0);
    static ARG0: AtomicUsize = AtomicUsize::new(0);
    static ARG1: AtomicUsize = AtomicUsize::new(0);
    static ARG2: AtomicUsize = AtomicUsize::new(0);
    static CONVERT_RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn convert(p: *mut u8, d: *mut u8, n: u32) -> *mut u8 {
        CONVERT_HITS.fetch_add(1, Ordering::SeqCst);
        ARG0.store(p as usize, Ordering::SeqCst);
        ARG1.store(d as usize, Ordering::SeqCst);
        ARG2.store(n as usize, Ordering::SeqCst);
        CONVERT_RET.load(Ordering::SeqCst) as *mut u8
    }

    unsafe extern "C" fn free_it(p: *mut u8) {
        FREE_HITS.fetch_add(1, Ordering::SeqCst);
        FREE_ARG.store(p as usize, Ordering::SeqCst);
    }

    fn rc_of(obj: *mut u8) -> u32 {
        unsafe { read_unaligned(obj.wrapping_byte_offset(-8) as *const u32) }
    }

    #[test]
    fn release_lanes() {
        unsafe {
            HOOK_00405548 = convert;
            HOOK_00402e20 = free_it;
        }
        // Header arena: obj = base+8; rc @ obj-8, extra @ obj-4.
        let mut hdr = [0u8; 16];
        let base = hdr.as_mut_ptr();
        let obj = unsafe { base.wrapping_add(8) };
        let mut holder: *mut u8 = core::ptr::null_mut();
        // Desc table: idx=4 → slot @ dbuf+10 holds &link; link holds desc.
        let mut desc = [0x77u8; 8];
        let desc_ptr = desc.as_mut_ptr();
        let mut link: *mut u8 = desc_ptr;
        let mut dbuf = [0u8; 32];
        unsafe {
            write_unaligned(dbuf.as_mut_ptr().wrapping_add(1), 4u8);
            write_unaligned(
                dbuf.as_mut_ptr().wrapping_add(10) as *mut *mut u8,
                &mut link as *mut *mut u8 as *mut u8,
            );
        }
        let dbase = dbuf.as_mut_ptr();
        let haddr = &mut holder as *mut *mut u8;

        // Null holder: nothing fires, holder returned.
        CONVERT_HITS.store(0, Ordering::SeqCst);
        FREE_HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405ae4(&mut holder, dbase) }, haddr);
        assert_eq!(CONVERT_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 0);

        // rc 2→1: holder zeroed, no convert, no free.
        unsafe {
            write_unaligned(base as *mut u32, 2u32);
            holder = obj;
            assert_eq!(fn_00405ae4(&mut holder, dbase), haddr);
            assert!(holder.is_null());
            assert_eq!(rc_of(obj), 1);
        }
        assert_eq!(CONVERT_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 0);

        // rc 1→0, null entry: free(obj-8), no convert.
        unsafe {
            write_unaligned(base as *mut u32, 1u32);
            write_unaligned(base.wrapping_add(4) as *mut u32, 9u32);
            write_unaligned(dbuf.as_mut_ptr().wrapping_add(10) as *mut *mut u8, core::ptr::null_mut());
            holder = obj;
            fn_00405ae4(&mut holder, dbase);
            assert_eq!(FREE_HITS.load(Ordering::SeqCst), 1);
            assert_eq!(FREE_ARG.load(Ordering::SeqCst), base as usize);
        }
        assert_eq!(CONVERT_HITS.load(Ordering::SeqCst), 0);

        // rc 1→0, entry set but extra 0: free, no convert.
        unsafe {
            write_unaligned(base as *mut u32, 1u32);
            write_unaligned(base.wrapping_add(4) as *mut u32, 0u32);
            write_unaligned(
                dbuf.as_mut_ptr().wrapping_add(10) as *mut *mut u8,
                &mut link as *mut *mut u8 as *mut u8,
            );
            holder = obj;
            fn_00405ae4(&mut holder, dbase);
        }
        assert_eq!(CONVERT_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(FREE_ARG.load(Ordering::SeqCst), base as usize);

        // rc 1→0, entry + extra nonzero: convert fires, free takes its return.
        let mut hdr2 = [0u8; 16];
        let base2 = hdr2.as_mut_ptr();
        let obj2 = unsafe { base2.wrapping_add(8) };
        CONVERT_RET.store(obj2 as usize, Ordering::SeqCst);
        unsafe {
            write_unaligned(base as *mut u32, 1u32);
            write_unaligned(base.wrapping_add(4) as *mut u32, 7u32);
            holder = obj;
            fn_00405ae4(&mut holder, dbase);
        }
        assert_eq!(CONVERT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG0.load(Ordering::SeqCst), obj as usize);
        assert_eq!(ARG1.load(Ordering::SeqCst), desc_ptr as usize);
        assert_eq!(ARG2.load(Ordering::SeqCst), 7);
        assert_eq!(FREE_HITS.load(Ordering::SeqCst), 3);
        assert_eq!(FREE_ARG.load(Ordering::SeqCst), base2 as usize);
    }
}
