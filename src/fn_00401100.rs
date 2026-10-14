//! Original procedure `0x00401100` (6 bytes, `0x00401100–0x0040a5`).
//! Evidence: `evidence/00401100_fn_00401100.md`.
//!
//! Import thunk `KERNEL32.DLL::GetLocaleInfoW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: u32, a1: u32, a2: usize, a3: i32) -> i32 {
    0
}

/// Thunk `KERNEL32.DLL::GetLocaleInfoW` via IAT slot `0x00419388`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_00401100: unsafe extern "C" fn(u32, u32, usize, i32) -> i32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_00401100(locale: u32, lc_type: u32, lp_lc_data: usize, cch_data: i32) -> i32 {
    HOOK_00401100(locale, lc_type, lp_lc_data, cch_data)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00401100, fn_00401100};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);
    static A3: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: u32, a1: u32, a2: usize, a3: i32) -> i32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        A2.store(a2 as usize, Ordering::SeqCst);
        A3.store(a3 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_00401100 = hook };
        assert_eq!(unsafe { fn_00401100(11, 11, 0x1002, 12) }, 0);
        assert_eq!(A0.load(Ordering::SeqCst), 11);
        assert_eq!(A1.load(Ordering::SeqCst), 11);
        assert_eq!(A2.load(Ordering::SeqCst), 0x1002);
        assert_eq!(A3.load(Ordering::SeqCst), 12 as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
