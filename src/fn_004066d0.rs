//! Original procedure `0x004066d0` (6 bytes, `0x004066d0–0x004066d5`).
//! Evidence: `evidence/004066d0_fn_004066d0.md`.

unsafe extern "C" fn default_target(
    _root: *const u16,
    _per_cluster: *mut u32,
    _per_sector: *mut u32,
    _free: *mut u32,
    _total: *mut u32,
) -> u32 {
    0
}

/// Import slot `dword ptr [0x004194a4]` (`KERNEL32.DLL::GetDiskFreeSpaceW`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_004066D0: unsafe extern "C" fn(*const u16, *mut u32, *mut u32, *mut u32, *mut u32) -> u32 =
    default_target;

/// `JMP dword ptr [0x004194a4]` — tail-forward with identical args.
pub unsafe fn fn_004066d0(
    root: *const u16,
    per_cluster: *mut u32,
    per_sector: *mut u32,
    free: *mut u32,
    total: *mut u32,
) -> u32 {
    HOOK_004066D0(root, per_cluster, per_sector, free, total)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004066D0, fn_004066d0};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(
        _r: *const u16,
        s: *mut u32,
        _b: *mut u32,
        _f: *mut u32,
        _t: *mut u32,
    ) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(s as usize, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_004066D0 = target };
        let mut a = 0u32;
        let mut b = 0u32;
        let mut c = 0u32;
        let mut d = 0u32;
        let r = unsafe {
            fn_004066d0(core::ptr::null(), &mut a, &mut b, &mut c, &mut d)
        };
        assert_eq!(r, 1);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), &a as *const u32 as usize);
    }
}
