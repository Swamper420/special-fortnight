//! Original procedure `0x004066c0` (6 bytes, `0x004066c0–0x004066c5`).
//! Evidence: `evidence/004066c0_fn_004066c0.md`.

unsafe extern "C" fn default_target() -> *mut u16 {
    core::ptr::null_mut()
}

/// Import slot `dword ptr [0x004194ac]` (`KERNEL32.DLL::GetCommandLineW`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_004066C0: unsafe extern "C" fn() -> *mut u16 = default_target;

/// `JMP dword ptr [0x004194ac]` — tail-forward with identical args.
pub unsafe fn fn_004066c0() -> *mut u16 {
    HOOK_004066C0()
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004066C0, fn_004066c0};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static mut RET: [u16; 2] = [0x41, 0];

    unsafe extern "C" fn target() -> *mut u16 {
        HITS.fetch_add(1, Ordering::SeqCst);
        core::ptr::addr_of_mut!(RET).cast()
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_004066C0 = target };
        let r = unsafe { fn_004066c0() };
        assert!(!r.is_null());
        assert_eq!(unsafe { *r }, 0x41);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
