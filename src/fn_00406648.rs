//! Original procedure `0x00406648` (6 bytes, `0x00406648–0x0040664d`).
//! Evidence: `evidence/00406648_fn_00406648.md`.

unsafe extern "C" fn default_target(_path: *const u16, _attrs: *mut u8) -> u32 {
    0
}

/// Import slot `dword ptr [0x004194dc]` (`KERNEL32.DLL::CreateDirectoryW`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00406648: unsafe extern "C" fn(*const u16, *mut u8) -> u32 = default_target;

/// `JMP dword ptr [0x004194dc]` — tail-forward with identical args.
pub unsafe fn fn_00406648(path: *const u16, attrs: *mut u8) -> u32 {
    HOOK_00406648(path, attrs)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406648, fn_00406648};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(p: *const u16, _a: *mut u8) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(p as usize, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_00406648 = target };
        let name = [0x41u16, 0];
        assert_eq!(unsafe { fn_00406648(name.as_ptr(), core::ptr::null_mut()) }, 1);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), name.as_ptr() as usize);
    }
}
