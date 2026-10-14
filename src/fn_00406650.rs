//! Original procedure `0x00406650` (6 bytes, `0x00406650–0x00406655`).
//! Evidence: `evidence/00406650_fn_00406650.md`.

unsafe extern "C" fn default_target(
    _attrs: *mut u8,
    _manual: u32,
    _initial: u32,
    _name: *const u16,
) -> usize {
    0
}

/// Import slot `dword ptr [0x004194d8]` (`KERNEL32.DLL::CreateEventW`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00406650: unsafe extern "C" fn(*mut u8, u32, u32, *const u16) -> usize =
    default_target;

/// `JMP dword ptr [0x004194d8]` — tail-forward with identical args.
pub unsafe fn fn_00406650(
    attrs: *mut u8,
    manual: u32,
    initial: u32,
    name: *const u16,
) -> usize {
    HOOK_00406650(attrs, manual, initial, name)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406650, fn_00406650};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(_a: *mut u8, m: u32, _i: u32, _n: *const u16) -> usize {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(m as usize, Ordering::SeqCst);
        0x50
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_00406650 = target };
        let r = unsafe { fn_00406650(core::ptr::null_mut(), 1, 0, core::ptr::null()) };
        assert_eq!(r, 0x50);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 1);
    }
}
