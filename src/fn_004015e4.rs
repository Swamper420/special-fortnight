//! Original procedure `0x004015e4` (119 bytes, `0x4015e4–0x40165a`).
//! Evidence: `evidence/004015e4_fn_004015e4.md`.

unsafe extern "C" fn default_preseal() {}

unsafe extern "C" fn default_virtual_alloc(
    _addr: *const u8,
    _size: u32,
    _kind: u32,
    _prot: u32,
) -> *mut u8 {
    core::ptr::null_mut()
}

/// Pre-call `0x401578` (`FUN_00401578`).
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00401578` once linkage decided.
pub static mut CALL_00401578: unsafe extern "C" fn() = default_preseal;

/// Import thunk `0x4011ec` (`KERNEL32.DLL::VirtualAlloc`).
///
/// ponytail: hook standing in for OS import (also keeps host tests
/// linkable), rewire to raw `extern "system" VirtualAlloc` once
/// Windows-target linkage proven.
pub static mut VIRTUAL_ALLOC_004011ec: unsafe extern "C" fn(
    *const u8,
    u32,
    u32,
    u32,
) -> *mut u8 = default_virtual_alloc;

/// Sentinel link `DAT_00413a24` (address-taken by new region).
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade to real
/// image-relative data once layout proven.
pub static mut DAT_00413a24: u32 = 0;

/// Region-list head `DAT_00413a28`.
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade to real
/// image-relative data once layout proven.
pub static mut DAT_00413a28: *mut u32 = core::ptr::null_mut();

/// Cursor cell `DAT_00413a38`.
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade to real
/// image-relative data once layout proven.
pub static mut DAT_00413a38: *mut u8 = core::ptr::null_mut();

/// Remaining-size cell `DAT_00413a3c`.
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade to real
/// image-relative data once layout proven.
pub static mut DAT_00413a3c: u32 = 0;

/// Reserve a `0x13fff0` region, link it, carve `param_1` bytes off the top.
/// `param_1` arrives in EAX per Ghidra `__register` observation.
pub unsafe fn fn_004015e4(param_1: u32) -> *mut u8 {
    CALL_00401578();
    let base = VIRTUAL_ALLOC_004011ec(
        core::ptr::null(),
        0x13fff0,
        0x1000,
        4,
    );
    if base.is_null() {
        DAT_00413a3c = 0;
        return core::ptr::null_mut();
    }
    let old = DAT_00413a28;
    core::ptr::write_unaligned(
        base as *mut *mut u32,
        core::ptr::addr_of_mut!(DAT_00413a24),
    );
    DAT_00413a28 = base as *mut u32;
    core::ptr::write_unaligned((base as *mut *mut u32).add(1), old);
    core::ptr::write_unaligned(old as *mut *mut u8, base);
    core::ptr::write_unaligned(
        (base as *mut u32).add(0x4fffb),
        2u32,
    );
    DAT_00413a3c = 0x13ffe0u32.wrapping_sub(param_1);
    let cursor =
        base.wrapping_byte_add(0x13fff0u32.wrapping_sub(param_1) as usize);
    DAT_00413a38 = cursor;
    core::ptr::write_unaligned(
        cursor.wrapping_byte_sub(4) as *mut u32,
        param_1 | 2,
    );
    cursor
}

#[cfg(test)]
mod tests {
    use super::{
        CALL_00401578, DAT_00413a24, DAT_00413a28, DAT_00413a38,
        DAT_00413a3c, VIRTUAL_ALLOC_004011ec, fn_004015e4,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static PRESEAL_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_SIZE: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn preseal() {
        PRESEAL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn alloc(
        _addr: *const u8,
        size: u32,
        _kind: u32,
        _prot: u32,
    ) -> *mut u8 {
        ALLOC_SIZE.store(size as usize, Ordering::SeqCst);
        ALLOC_RET.load(Ordering::SeqCst) as *mut u8
    }

    #[test]
    fn reserve_link_and_fail_lanes() {
        unsafe {
            CALL_00401578 = preseal;
            VIRTUAL_ALLOC_004011ec = alloc;
        }
        // Fail lane: null base zeroes remaining, returns null.
        ALLOC_RET.store(0, Ordering::SeqCst);
        unsafe { DAT_00413a3c = 0xdead };
        let r = unsafe { fn_004015e4(0x10) };
        assert!(r.is_null());
        assert_eq!(PRESEAL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_SIZE.load(Ordering::SeqCst), 0x13fff0);
        assert_eq!(unsafe { DAT_00413a3c }, 0);

        // Success lane over a real 0x13fff0 region.
        let mut region = vec![0u8; 0x13fff0];
        let base = region.as_mut_ptr();
        core::mem::forget(region);
        ALLOC_RET.store(base as usize, Ordering::SeqCst);
        let mut old_head: *mut u8 = core::ptr::null_mut();
        unsafe {
            DAT_00413a28 = &mut old_head as *mut *mut u8 as *mut u32;
            DAT_00413a3c = 0xdead;
        }
        let cursor = unsafe { fn_004015e4(0x10) };
        assert_eq!(PRESEAL_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(cursor, unsafe { base.wrapping_byte_add(0x13ffe0) });
        assert_eq!(unsafe { DAT_00413a38 }, cursor);
        assert_eq!(unsafe { DAT_00413a3c }, 0x13ffd0);
        unsafe {
            assert_eq!(
                core::ptr::read_unaligned(base as *const *const u32),
                core::ptr::addr_of_mut!(DAT_00413a24) as *const u32
            );
            assert_eq!(
                core::ptr::read_unaligned(
                    (base as *const *mut u32).add(1)
                ),
                &mut old_head as *mut *mut u8 as *mut u32
            );
            assert_eq!(DAT_00413a28, base as *mut u32);
            assert_eq!(old_head, base);
            assert_eq!(
                core::ptr::read_unaligned(
                    (base as *const u32).add(0x4fffb)
                ),
                2
            );
            assert_eq!(
                core::ptr::read_unaligned(
                    cursor.wrapping_byte_sub(4) as *const u32
                ),
                0x12
            );
        }
    }
}
