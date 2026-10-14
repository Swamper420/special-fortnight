//! Original procedure `0x0040683c` (6 bytes, `0x0040683c–0x00406841`).
//! Evidence: `evidence/0040683c_fn_0040683c.md`.
//!
//! Import thunk `KERNEL32.DLL::SignalObjectAndWait`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(_h_signal: usize, _h_wait: usize, _ms: u32, _alertable: u32) -> u32 {
    0
}

/// Thunk `KERNEL32.DLL::SignalObjectAndWait` via IAT slot `0x00419428`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_0040683C: unsafe extern "C" fn(usize, usize, u32, u32) -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_0040683c(h_signal: usize, h_wait: usize, ms: u32, alertable: u32) -> u32 {
    HOOK_0040683C(h_signal, h_wait, ms, alertable)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040683C, fn_0040683c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);
    static A3: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: usize, a2: u32, a3: u32) -> u32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        A2.store(a2 as usize, Ordering::SeqCst);
        A3.store(a3 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        7
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_0040683C = hook };
        assert_eq!(unsafe { fn_0040683c(11, 0x2000, 100, 0) }, 7);
        assert_eq!(A0.load(Ordering::SeqCst), 11 as usize);
        assert_eq!(A1.load(Ordering::SeqCst), 0x2000 as usize);
        assert_eq!(A2.load(Ordering::SeqCst), 100 as usize);
        assert_eq!(A3.load(Ordering::SeqCst), 0 as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
