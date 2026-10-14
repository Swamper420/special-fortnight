//! Original procedure `0x00406710` (6 bytes, `0x00406710–0x00406715`).
//! Evidence: `evidence/00406710_fn_00406710.md`.
//!
//! Import thunk `KERNEL32.DLL::GetModuleFileNameW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize, a1: usize, a2: u32) -> u32 {
    0
}

/// Thunk `KERNEL32.DLL::GetModuleFileNameW` via IAT slot `0x00419484`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_00406710: unsafe extern "C" fn(usize, usize, u32) -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_00406710(hModule: usize, lpFilename: usize, nSize: u32) -> u32 {
    HOOK_00406710(hModule, lpFilename, nSize)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406710, fn_00406710};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: usize, a2: u32) -> u32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        A2.store(a2 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x6710
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_00406710 = hook };
        assert_eq!(unsafe { fn_00406710(11, 12, 13) }, 0x6710);
        assert_eq!(A0.load(Ordering::SeqCst), 11);
        assert_eq!(A1.load(Ordering::SeqCst), 12);
        assert_eq!(A2.load(Ordering::SeqCst), 13);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
