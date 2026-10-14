//! Original procedure `0x00401190` (6 bytes, `0x00401190–0x00401195`).
//! Evidence: `evidence/00401190_fn_00401190.md`.

unsafe extern "C" fn default_target(_bstr: *mut u16) {}

/// Import slot `dword ptr [0x00419304]` (`OLEAUT32.DLL::SysFreeString`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00401190: unsafe extern "C" fn(*mut u16) = default_target;

/// `JMP dword ptr [0x00419304]` — tail-forward with identical args.
pub unsafe fn fn_00401190(bstr: *mut u16) {
    HOOK_00401190(bstr);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00401190, fn_00401190};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);
    static CELL: [u16; 2] = [0x42, 0];

    unsafe extern "C" fn target(b: *mut u16) {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(b as usize, Ordering::SeqCst);
    }

    #[test]
    fn forwards() {
        unsafe { HOOK_00401190 = target };
        let p = core::ptr::addr_of!(CELL) as *const u16 as *mut u16;
        unsafe { fn_00401190(p) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), p as usize);
    }
}
