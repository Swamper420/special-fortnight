//! Original procedure `0x00405458` (83 bytes, `0x405458–0x4054aa`).
//! Evidence: `evidence/00405458_fn_00405458.md`.

use crate::fn_00402e20::fn_00402e20;
use crate::fn_00402fbc::fn_00402fbc;
use core::ptr::{null_mut, read_unaligned, write_unaligned};

unsafe extern "C" fn default_convert(_slot: *mut u8) {}

unsafe extern "C" fn default_alloc(_len: u32) -> *mut u8 {
    null_mut()
}

/// Target `0x404818` (`FUN_00404818`), called with the slot on the
/// non-`2` tag lane; result reloaded from `*slot`.
///
/// ponytail: hook standing in for done `fn_00404818`, rewire to real
/// call once cross-module test serialization exists (its hook global
/// has no owner lock, so a direct call would race its writer test).
pub static mut HOOK_00404818: unsafe extern "C" fn(*mut u8) = default_convert;

/// Target `0x4054b4` (`FUN_004054b4`), called with `[obj-4]` length;
/// result is the new data pointer, stored to `*slot`.
///
/// ponytail: hook standing in for same-batch `fn_004054b4`, rewire to
/// the real call once both modules are linked.
pub static mut HOOK_004054b4: unsafe extern "C" fn(u32) -> *mut u8 =
    default_alloc;

/// Detach the string in `*slot` (copy-on-write): null → null; tag
/// `[p-10]!=2` → convert lane and reload; refcount `[p-8]==1` →
/// return as-is; else alloc `[p-4]`, copy `len<<1` bytes, release
/// old (`[old-8]>0` → locked dec → zero calls `02e20(old-12)`).
/// `param_1` arrives in EAX per Ghidra `__register` observation.
/// Header/count stay `u32`/`u16` per observed widths; links read
/// pointer-sized. Direct calls to done `fn_00402fbc` (pure) and
/// `fn_00402e20` (under its `TEST_LOCK` in tests).
///
/// ponytail: non-atomic host model of `LOCK DEC` (AtomicU32 once
/// threading proven).
pub unsafe fn fn_00405458(param_1: *mut u8) -> *mut u8 {
    let mut cur: *mut u8 = read_unaligned(param_1 as *const *mut u8);
    if cur.is_null() {
        return null_mut();
    }
    if read_unaligned(cur.wrapping_byte_offset(-10) as *const u16) != 2 {
        HOOK_00404818(param_1);
        cur = read_unaligned(param_1 as *const *mut u8);
    }
    if read_unaligned(cur.wrapping_byte_offset(-8) as *const u32) == 1 {
        return cur;
    }
    let len: u32 = read_unaligned(cur.wrapping_byte_offset(-4) as *const u32);
    let new = HOOK_004054b4(len);
    fn_00402fbc(cur, new, len.wrapping_shl(1));
    write_unaligned(param_1 as *mut *mut u8, new);
    let seen: u32 = read_unaligned(cur.wrapping_byte_offset(-8) as *const u32);
    if (seen.wrapping_sub(1) as i32) >= 0 {
        let next = seen.wrapping_sub(1);
        write_unaligned(cur.wrapping_byte_offset(-8) as *mut u32, next);
        if next == 0 {
            fn_00402e20(cur.wrapping_byte_offset(-12) as u32);
        }
    }
    new
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00404818, HOOK_004054b4, fn_00405458};
    use core::ptr::{null_mut, read_unaligned, write_unaligned};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CONVERT_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_RET: AtomicUsize = AtomicUsize::new(0);
    static DTOR_HITS: AtomicUsize = AtomicUsize::new(0);

    static mut FIXUP_OBJ: usize = 0;

    unsafe extern "C" fn convert(slot: *mut u8) {
        CONVERT_HITS.fetch_add(1, Ordering::SeqCst);
        assert_eq!(slot as usize, SLOT_SAVED.load(Ordering::SeqCst));
        write_unaligned(slot as *mut *mut u8, FIXUP_OBJ as *mut u8);
    }

    static SLOT_SAVED: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn alloc(n: u32) -> *mut u8 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        ALLOC_RET.load(Ordering::SeqCst) as *mut u8
    }

    /// Probe for the done dtor's indirect slot: counts entries,
    /// returns 0 so its tail lane never fires.
    unsafe extern "C" fn indirect() -> u32 {
        DTOR_HITS.fetch_add(1, Ordering::SeqCst);
        0
    }

    /// Header arena: obj = base+12; tag at base+2 (`obj-10`),
    /// refcount at base+4 (`obj-8`), length at base+8 (`obj-4`).
    unsafe fn hdr(arena: &mut [u32; 4], tag: u16, rc: u32, len: u32) -> *mut u8 {
        let base = arena.as_mut_ptr() as *mut u8;
        write_unaligned(base.wrapping_byte_add(2) as *mut u16, tag);
        write_unaligned(base.wrapping_byte_add(4) as *mut u32, rc);
        write_unaligned(base.wrapping_byte_add(8) as *mut u32, len);
        base.wrapping_byte_add(12)
    }

    #[test]
    fn detach_lanes() {
        // Shared fn_00404dd4 hooks: hold the common owner lock first.
        let _shared = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        // Direct call reaches done fn_00402e20, which reads its PTR
        // global: hold the owner lock so its writer test can't race us.
        let _callee = crate::fn_00402e20::TEST_LOCK.lock().unwrap();
        let saved = unsafe { crate::fn_00402e20::PTR_00412740 };
        unsafe {
            crate::fn_00402e20::PTR_00412740 = indirect;
            HOOK_00404818 = convert;
            HOOK_004054b4 = alloc;
        }

        let mut slot: *mut u8 = null_mut();
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;
        SLOT_SAVED.store(slot_ptr as usize, Ordering::SeqCst);

        // Null lane: returns null, no hooks.
        CONVERT_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        assert!(unsafe { fn_00405458(slot_ptr) }.is_null());
        assert!(slot.is_null());
        assert_eq!(CONVERT_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);

        // Unique lane: rc==1 returns as-is, no alloc.
        let mut u_arena = [0u32; 4];
        let u = unsafe { hdr(&mut u_arena, 2, 1, 5) };
        slot = u;
        ALLOC_HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405458(slot_ptr) }, u);
        assert_eq!(slot, u);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);

        // Convert lane: foreign tag fires hook; hook installs a
        // valid rc==1 object, which is returned with no alloc.
        let mut f_arena = [0u32; 4];
        let f = unsafe { hdr(&mut f_arena, 3, 9, 5) };
        let mut t_arena = [0u32; 4];
        let t = unsafe { hdr(&mut t_arena, 2, 1, 5) };
        unsafe { FIXUP_OBJ = t as usize };
        slot = f;
        CONVERT_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405458(slot_ptr) }, t);
        assert_eq!(slot, t);
        assert_eq!(CONVERT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);

        // Shared lane: rc==2 len==3; alloc new, real 02fbc copies
        // 6 bytes old->new, old 2->1, slot=new, no dtor.
        // Header (16 bytes) + 6 payload bytes in one arena.
        let mut o_arena = [0u8; 24];
        let obase = o_arena.as_mut_ptr();
        unsafe {
            write_unaligned(obase.wrapping_byte_add(2) as *mut u16, 2);
            write_unaligned(obase.wrapping_byte_add(4) as *mut u32, 2);
            write_unaligned(obase.wrapping_byte_add(8) as *mut u32, 3);
            let op = obase.wrapping_byte_add(12);
            for (i, b) in [9u8, 8, 7, 6, 5, 4].iter().enumerate() {
                write_unaligned(op.wrapping_add(i), *b);
            }
            slot = op;
        }
        let mut n_arena = [0u8; 20];
        let nbase = n_arena.as_mut_ptr();
        let ndata = nbase.wrapping_add(12);
        ALLOC_RET.store(ndata as usize, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        DTOR_HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405458(slot_ptr) }, ndata);
        assert_eq!(slot, ndata);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 3);
        unsafe {
            assert_eq!(
                core::slice::from_raw_parts(ndata as *const u8, 6),
                &[9u8, 8, 7, 6, 5, 4]
            );
        }
        let obase_rc = unsafe {
            read_unaligned(obase.wrapping_byte_add(4) as *const u32)
        };
        assert_eq!(obase_rc, 1);
        assert_eq!(DTOR_HITS.load(Ordering::SeqCst), 0);

        // Zero-count lane: rc==0 → alloc+copy, no dec-write, no dtor.
        let mut z_arena = [0u8; 20];
        let zbase = z_arena.as_mut_ptr();
        unsafe {
            write_unaligned(zbase.wrapping_byte_add(2) as *mut u16, 2);
            write_unaligned(zbase.wrapping_byte_add(4) as *mut u32, 0);
            write_unaligned(zbase.wrapping_byte_add(8) as *mut u32, 2);
            let zp = zbase.wrapping_byte_add(12);
            write_unaligned(zp.wrapping_add(0), 0xAAu8);
            write_unaligned(zp.wrapping_add(1), 0xBBu8);
            write_unaligned(zp.wrapping_add(2), 0xCCu8);
            write_unaligned(zp.wrapping_add(3), 0xDDu8);
            slot = zp;
        }
        ALLOC_RET.store(ndata as usize, Ordering::SeqCst);
        DTOR_HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405458(slot_ptr) }, ndata);
        let zrc = unsafe { read_unaligned(zbase.wrapping_byte_add(4) as *const u32) };
        assert_eq!(zrc, 0);
        assert_eq!(DTOR_HITS.load(Ordering::SeqCst), 0);
        unsafe {
            assert_eq!(
                core::slice::from_raw_parts(ndata as *const u8, 4),
                &[0xAAu8, 0xBB, 0xCC, 0xDD]
            );
        }

        unsafe {
            crate::fn_00402e20::PTR_00412740 = saved;
        }
    }
}
