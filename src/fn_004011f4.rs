//! Original procedure `0x004011f4` (6 bytes, `0x004011f4–0x004011f9`).
//! Evidence: `evidence/004011f4_fn_004011f4.md`.

unsafe extern "C" fn default_target(_addr: *mut u8, _size: u32, _free_type: u32) -> i32 {
    0
}

/// Import slot `dword ptr [0x00419340]` (`KERNEL32.DLL::VirtualFree`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_004011F4: unsafe extern "C" fn(*mut u8, u32, u32) -> i32 = default_target;

/// `JMP dword ptr [0x00419340]` — tail-forward with identical args.
pub unsafe fn fn_004011f4(addr: *mut u8, size: u32, free_type: u32) -> i32 {
    HOOK_004011F4(addr, size, free_type)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004011F4, fn_004011f4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static FREE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(_a: *mut u8, _n: u32, f: u32) -> i32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        FREE.store(f as usize, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_004011F4 = target };
        let r = unsafe { fn_004011f4(core::ptr::null_mut(), 0, 0x8000) };
        assert_eq!(r, 1);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FREE.load(Ordering::SeqCst), 0x8000);
    }
}
