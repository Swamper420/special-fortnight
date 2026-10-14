//! Original procedure `0x00406670` (6 bytes, `0x00406670–0x00406675`).
//! Evidence: `evidence/00406670_fn_00406670.md`.

unsafe extern "C" fn default_target(_proc: usize, _locale: u32, _cal: u32, _kind: u32) -> u32 {
    0
}

/// Import slot `dword ptr [0x004194c8]` (`KERNEL32.DLL::EnumCalendarInfoW`).
///
/// ponytail: hook standing in for OS import (keeps host tests linkable),
/// rewire to raw `extern "system"` once Windows-target linkage proven.
pub static mut HOOK_00406670: unsafe extern "C" fn(usize, u32, u32, u32) -> u32 = default_target;

/// `JMP dword ptr [0x004194c8]` — tail-forward with identical args.
pub unsafe fn fn_00406670(proc: usize, locale: u32, cal: u32, kind: u32) -> u32 {
    HOOK_00406670(proc, locale, cal, kind)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406670, fn_00406670};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(p: usize, _l: u32, _c: u32, _k: u32) -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(p, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_and_echoes() {
        unsafe { HOOK_00406670 = target };
        assert_eq!(unsafe { fn_00406670(0x70, 0x409, 1, 2) }, 1);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 0x70);
    }
}
