//! Original procedure `0x00406678` (6 bytes, `0x00406678–0x0040667d`).
//! Evidence: `evidence/00406678_fn_00406678.md`.

unsafe extern "C" fn default_target(
    _module: usize,
    _name: *const u16,
    _kind: *const u16,
) -> usize {
    0
}

/// Import slot `dword ptr [0x004194c4]` (`KERNEL32.DLL::FindResourceW`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00406678: unsafe extern "C" fn(usize, *const u16, *const u16) -> usize =
    default_target;

/// `JMP dword ptr [0x004194c4]` — tail-forward with identical args.
pub unsafe fn fn_00406678(module: usize, name: *const u16, kind: *const u16) -> usize {
    HOOK_00406678(module, name, kind)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406678, fn_00406678};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(m: usize, _n: *const u16, _k: *const u16) -> usize {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(m, Ordering::SeqCst);
        0x78
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_00406678 = target };
        let r = unsafe { fn_00406678(0x400000, core::ptr::null(), core::ptr::null()) };
        assert_eq!(r, 0x78);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 0x400000);
    }
}
