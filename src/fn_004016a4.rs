//! Original procedure `0x004016a4` (98 bytes, `0x004016a4–0x00401705`).
//! Evidence: `evidence/004016a4_fn_004016a4.md`.

unsafe extern "C" fn default_virtual_alloc(
    _addr: *const u8,
    _size: u32,
    _kind: u32,
    _prot: u32,
) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_postalloc() {}

/// Import thunk `0x004011ec` (`KERNEL32.DLL::VirtualAlloc`).
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

/// Post-alloc call `0x0040165c` (`FUN_0040165c`).
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_0040165c` once linkage decided.
pub static mut CALL_0040165c: unsafe extern "C" fn() = default_postalloc;

/// Region-list head `DAT_00415acc`.
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade to real
/// image-relative data once layout proven.
pub static mut DAT_00415acc: *mut u32 = core::ptr::null_mut();

/// List sentinel `DAT_00415ac8` (address-taken by new region).
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade to real
/// image-relative data once layout proven.
pub static mut DAT_00415ac8: u32 = 0;

/// Ready flag `DAT_00415ac4` (cleared after insert).
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade to real
/// image-relative data once layout proven.
pub static mut DAT_00415ac4: u8 = 0;

/// Commit a 64KB-rounded region for `param_1`, link it, return `base+16`.
/// `param_1` arrives in EAX per Ghidra `__register` observation.
///
/// ponytail: image link slots are 4-byte `u32` address cells (target-exact);
/// host pointers are truncated to `u32` for those cells, so the header at
/// +8/+12 never overlaps the links on a 64-bit host. Full-pointer
/// fidelity returns with image-relative data layout.
pub unsafe fn fn_004016a4(param_1: i32) -> *mut u8 {
    let size =
        (param_1 as u32).wrapping_add(0x10013) & 0xffff0000;
    let base =
        VIRTUAL_ALLOC_004011ec(core::ptr::null(), size, 0x101000, 4);
    if base.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut i32, param_1);
    core::ptr::write_unaligned(
        base.wrapping_byte_add(12) as *mut u32,
        size | 4,
    );
    CALL_0040165c();
    let old = DAT_00415acc;
    core::ptr::write_unaligned(
        base as *mut u32,
        core::ptr::addr_of_mut!(DAT_00415ac8) as u32,
    );
    core::ptr::write_unaligned((base as *mut u32).add(1), old as u32);
    DAT_00415acc = base as *mut u32;
    core::ptr::write_unaligned(old as *mut u32, base as u32);
    DAT_00415ac4 = 0;
    base.wrapping_byte_add(16)
}

#[cfg(test)]
mod tests {
    use super::{
        CALL_0040165c, DAT_00415ac4, DAT_00415ac8, DAT_00415acc,
        VIRTUAL_ALLOC_004011ec, fn_004016a4,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ALLOC_SIZE: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_RET: AtomicUsize = AtomicUsize::new(0);
    static POST_HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn alloc(
        _addr: *const u8,
        size: u32,
        _kind: u32,
        _prot: u32,
    ) -> *mut u8 {
        ALLOC_SIZE.store(size as usize, Ordering::SeqCst);
        ALLOC_RET.load(Ordering::SeqCst) as *mut u8
    }

    unsafe extern "C" fn post() {
        POST_HITS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn round_commit_link_and_fail() {
        unsafe {
            VIRTUAL_ALLOC_004011ec = alloc;
            CALL_0040165c = post;
        }
        // Fail lane: null base returns null, post-call silent.
        ALLOC_RET.store(0, Ordering::SeqCst);
        assert!(unsafe { fn_004016a4(0x20) }.is_null());
        assert_eq!(ALLOC_SIZE.load(Ordering::SeqCst), 0x10000);
        assert_eq!(POST_HITS.load(Ordering::SeqCst), 0);

        // Success lane: param 0 → 0x10000 region, header + links.
        let mut region = vec![0u8; 0x10000 + 16];
        let base = region.as_mut_ptr();
        core::mem::forget(region);
        ALLOC_RET.store(base as usize, Ordering::SeqCst);
        let mut prev: *mut u8 = core::ptr::null_mut();
        unsafe {
            DAT_00415acc = &mut prev as *mut *mut u8 as *mut u32;
            DAT_00415ac4 = 0xff;
        }
        let r = unsafe { fn_004016a4(0) };
        assert_eq!(r, unsafe { base.wrapping_byte_add(16) });
        assert_eq!(POST_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { DAT_00415ac4 }, 0);
        assert_eq!(unsafe { DAT_00415acc }, base as *mut u32);
        assert_eq!(prev as u32, base as u32);
        unsafe {
            assert_eq!(
                core::ptr::read_unaligned(
                    base.wrapping_byte_add(8) as *const i32
                ),
                0
            );
            assert_eq!(
                core::ptr::read_unaligned(
                    base.wrapping_byte_add(12) as *const u32
                ),
                0x10004
            );
            assert_eq!(
                core::ptr::read_unaligned(base as *const u32),
                core::ptr::addr_of_mut!(DAT_00415ac8) as u32
            );
            assert_eq!(
                core::ptr::read_unaligned((base as *const u32).add(1)),
                &mut prev as *mut *mut u8 as u32
            );
        }
    }
}
