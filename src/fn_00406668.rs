//! Original procedure `0x00406668` (6 bytes, `0x00406668–0x0040666d`).
//! Evidence: `evidence/00406668_fn_00406668.md`.

unsafe extern "C" fn default_target(_name: *const u16) -> u32 {
    0
}

/// Import slot `dword ptr [0x004194cc]` (`KERNEL32.DLL::DeleteFileW`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00406668: unsafe extern "C" fn(*const u16) -> u32 = default_target;

/// `JMP dword ptr [0x004194cc]` — tail-forward with identical args.
pub unsafe fn fn_00406668(name: *const u16) -> u32 {
    HOOK_00406668(name)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406668, fn_00406668};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(n: *const u16) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(n as usize, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_00406668 = target };
        let name = [0x41u16, 0];
        assert_eq!(unsafe { fn_00406668(name.as_ptr()) }, 1);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), name.as_ptr() as usize);
    }
}
