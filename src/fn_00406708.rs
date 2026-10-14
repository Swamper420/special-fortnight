//! Original procedure `0x00406708` (6 bytes, `0x00406708–0x0040670d`).
//! Evidence: `evidence/00406708_fn_00406708.md`.
//!
//! Import thunk `KERNEL32.DLL::GetLocaleInfoW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: u32, a1: u32, a2: usize, a3: i32) -> i32 {
    0
}

/// Thunk `KERNEL32.DLL::GetLocaleInfoW` via IAT slot `0x00419488`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_00406708: unsafe extern "C" fn(u32, u32, usize, i32) -> i32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_00406708(Locale: u32, LCType: u32, lpLCData: usize, cchData: i32) -> i32 {
    HOOK_00406708(Locale, LCType, lpLCData, cchData)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406708, fn_00406708};
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
        0x6708
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_00406708 = hook };
        assert_eq!(unsafe { fn_00406708(11, 12, 13, 14) }, 0x6708);
        assert_eq!(A0.load(Ordering::SeqCst), 11);
        assert_eq!(A1.load(Ordering::SeqCst), 12);
        assert_eq!(A2.load(Ordering::SeqCst), 13);
        assert_eq!(A3.load(Ordering::SeqCst), 14);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
