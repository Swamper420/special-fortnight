//! Original procedure `0x004011ec` (6 bytes, `0x004011ec–0x004011f1`).
//! Evidence: `evidence/004011ec_fn_004011ec.md`.

unsafe extern "C" fn default_target(_addr: *const u8, _size: u32, _alloc_type: u32, _protect: u32) -> *mut u8 {
    core::ptr::null_mut()
}

/// Import slot `dword ptr [0x00419344]` (`KERNEL32.DLL::VirtualAlloc`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_004011EC: unsafe extern "C" fn(*const u8, u32, u32, u32) -> *mut u8 = default_target;

/// `JMP dword ptr [0x00419344]` — tail-forward with identical args.
pub unsafe fn fn_004011ec(addr: *const u8, size: u32, alloc_type: u32, protect: u32) -> *mut u8 {
    HOOK_004011EC(addr, size, alloc_type, protect)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004011EC, fn_004011ec};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static SIZE: AtomicUsize = AtomicUsize::new(0);
    static PROT: AtomicUsize = AtomicUsize::new(0);
    static CELL: [u8; 4] = [0; 4];

    unsafe extern "C" fn target(
        _a: *const u8,
        n: u32,
        _t: u32,
        p: u32,
    ) -> *mut u8 {
        HITS.fetch_add(1, Ordering::SeqCst);
        SIZE.store(n as usize, Ordering::SeqCst);
        PROT.store(p as usize, Ordering::SeqCst);
        core::ptr::addr_of!(CELL) as *const u8 as *mut u8
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_004011EC = target };
        let r = unsafe {
            fn_004011ec(core::ptr::null(), 0x1000, 0x3000, 4)
        };
        assert_eq!(r, core::ptr::addr_of!(CELL) as *const u8 as *mut u8);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(SIZE.load(Ordering::SeqCst), 0x1000);
        assert_eq!(PROT.load(Ordering::SeqCst), 4);
    }
}
