//! Original procedure `0x00401180` (6 bytes, `0x00401180–0x00401185`).
//! Evidence: `evidence/00401180_fn_00401180.md`.

unsafe extern "C" fn default_target(_src: *const u16, _len: u32) -> *mut u16 {
    core::ptr::null_mut()
}

/// Import slot `dword ptr [0x0041930c]` (`OLEAUT32.DLL::SysAllocStringLen`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00401180: unsafe extern "C" fn(*const u16, u32) -> *mut u16 = default_target;

/// `JMP dword ptr [0x0041930c]` — tail-forward with identical args.
pub unsafe fn fn_00401180(src: *const u16, len: u32) -> *mut u16 {
    HOOK_00401180(src, len)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00401180, fn_00401180};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static LEN: AtomicUsize = AtomicUsize::new(0);
    static CELL: [u16; 2] = [0x41, 0];

    unsafe extern "C" fn target(_s: *const u16, n: u32) -> *mut u16 {
        HITS.fetch_add(1, Ordering::SeqCst);
        LEN.store(n as usize, Ordering::SeqCst);
        core::ptr::addr_of!(CELL) as *const u16 as *mut u16
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_00401180 = target };
        let r = unsafe { fn_00401180(core::ptr::null(), 6) };
        assert_eq!(r, core::ptr::addr_of!(CELL) as *const u16 as *mut u16);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(LEN.load(Ordering::SeqCst), 6);
    }
}
