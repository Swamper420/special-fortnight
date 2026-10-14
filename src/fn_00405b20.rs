//! Original procedure `0x00405b20` (39 bytes, `0x405b20–0x405b46`).
//! Evidence: `evidence/00405b20_fn_00405b20.md`.

use core::ptr::{read_unaligned, write_unaligned};

unsafe extern "C" fn default_release(_holder: *mut *mut u8, _desc: *mut u8) {}

/// Target `0x405ae4` (`FUN_00405ae4`), called as `(holder, param_3)`
/// only when the old object's `LOCK DEC [old-8]` reaches zero (after a
/// plain `INC` restore).
///
/// ponytail: hook standing in for same-batch `fn_00405ae4`, rewire to
/// the real call once both modules are linked.
pub static mut HOOK_00405ae4: unsafe extern "C" fn(*mut *mut u8, *mut u8) =
    default_release;

/// Assign `*param_1 = param_2` with refcount handoff: `LOCK INC [new-8]`
/// if new nonzero; `LOCK DEC [old-8]` if old nonzero, releasing via
/// hook on dec-to-zero. Returns `void` per observed signature.
pub unsafe fn fn_00405b20(
    param_1: *mut *mut u8,
    param_2: *mut u8,
    param_3: *mut u8,
) {
    let old: *mut u8 = read_unaligned(param_1 as *const *mut u8);
    if !param_2.is_null() {
        let rc_ptr = param_2.wrapping_byte_offset(-8) as *mut u32;
        write_unaligned(
            rc_ptr,
            read_unaligned(rc_ptr as *const u32).wrapping_add(1),
        );
    }
    if !old.is_null() {
        let rc_ptr = old.wrapping_byte_offset(-8) as *mut u32;
        let rc: u32 = read_unaligned(rc_ptr as *const u32).wrapping_sub(1);
        write_unaligned(rc_ptr, rc);
        if rc == 0 {
            write_unaligned(
                rc_ptr,
                read_unaligned(rc_ptr as *const u32).wrapping_add(1),
            );
            HOOK_00405ae4(param_1, param_3);
        }
    }
    write_unaligned(param_1, param_2);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00405ae4, fn_00405b20};
    use core::ptr::{read_unaligned, write_unaligned};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HOOK_HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG0: AtomicUsize = AtomicUsize::new(0);
    static ARG1: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn release(holder: *mut *mut u8, desc: *mut u8) {
        HOOK_HITS.fetch_add(1, Ordering::SeqCst);
        ARG0.store(holder as usize, Ordering::SeqCst);
        ARG1.store(desc as usize, Ordering::SeqCst);
    }

    fn rc_of(obj: *mut u8) -> u32 {
        unsafe { read_unaligned(obj.wrapping_byte_offset(-8) as *const u32) }
    }

    #[test]
    fn assign_handoff() {
        unsafe {
            HOOK_00405ae4 = release;
        }
        // Header arenas: obj = base+8; rc @ obj-8.
        let mut old_hdr = [0u8; 16];
        let old_base = old_hdr.as_mut_ptr();
        let old_obj = unsafe { old_base.wrapping_add(8) };
        let mut new_hdr = [0u8; 16];
        let new_base = new_hdr.as_mut_ptr();
        let new_obj = unsafe { new_base.wrapping_add(8) };
        let mut desc = [0u8; 4];
        let desc_ptr = desc.as_mut_ptr();
        let mut holder: *mut u8 = core::ptr::null_mut();

        // Null/null: store only, no hook.
        HOOK_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00405b20(&mut holder, core::ptr::null_mut(), desc_ptr) };
        assert!(unsafe { holder.is_null() });
        assert_eq!(HOOK_HITS.load(Ordering::SeqCst), 0);

        // New inc: rc 5→6, old null, no hook.
        unsafe {
            write_unaligned(new_base as *mut u32, 5u32);
            fn_00405b20(&mut holder, new_obj, desc_ptr);
            assert_eq!(holder, new_obj);
            assert_eq!(rc_of(new_obj), 6);
        }
        assert_eq!(HOOK_HITS.load(Ordering::SeqCst), 0);

        // Old dec-to-nonzero: rc 2→1, hook silent, store replaces.
        unsafe {
            write_unaligned(old_base as *mut u32, 2u32);
            holder = old_obj;
            write_unaligned(new_base as *mut u32, 10u32);
            fn_00405b20(&mut holder, new_obj, desc_ptr);
            assert_eq!(holder, new_obj);
            assert_eq!(rc_of(old_obj), 1);
            assert_eq!(rc_of(new_obj), 11);
        }
        assert_eq!(HOOK_HITS.load(Ordering::SeqCst), 0);

        // Old dec-to-zero: rc restored 0→1, hook(holder, desc), store new.
        unsafe {
            write_unaligned(old_base as *mut u32, 1u32);
            holder = old_obj;
            write_unaligned(new_base as *mut u32, 20u32);
            fn_00405b20(&mut holder, new_obj, desc_ptr);
            assert_eq!(rc_of(old_obj), 1);
            assert_eq!(holder, new_obj);
            assert_eq!(rc_of(new_obj), 21);
        }
        assert_eq!(HOOK_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG0.load(Ordering::SeqCst), &mut holder as *mut *mut u8 as usize);
        assert_eq!(ARG1.load(Ordering::SeqCst), desc_ptr as usize);
    }
}
